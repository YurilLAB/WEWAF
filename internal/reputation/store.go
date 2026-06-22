// Package reputation is WEWAF's durable, per-IP repeat-offender ledger — the
// substrate that lets the WAF "get better the longer it runs".
//
// Why it exists. WEWAF already escalates bans on repeat offenders
// (core.BanList's exponential backoff) and already has a configured-but-unwired
// "N blocks in a window auto-bans the IP" reputation feature. Both lived purely
// in memory: a daemon restart — or simply waiting out the in-memory backoff
// window — amnestied every offender and reset their escalation tier to zero. A
// returning attacker that survives a restart started from a clean slate. This
// package fixes that restart-amnesia the way fail2ban's persistent SQLite ban
// DB does: a single, NON-rotating reputation.sqlite records each offender's
// offense count, a decaying reputation score, which detection subsystems have
// independently flagged them (a bitmask, the seed for cross-subsystem
// "recidive" consensus), and any active ban expiry. On startup the active set
// is reloaded so escalation and bans survive across restarts.
//
// Design mirrors internal/history deliberately: the same CGo-free
// modernc.org/sqlite driver (keeps the single static binary), the same WAL
// pragmas, and the same buffered-channel + batched-transaction write-behind
// writer so persisting an offense NEVER blocks request handling. The in-memory
// cache (see reputation.go) is always authoritative; the DB is best-effort, so
// a stalled or corrupt DB can never UNban an attacker or stall the hot path —
// it can only fail to remember, degrading gracefully to the pre-existing
// in-memory behaviour.
package reputation

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const driverName = "sqlite"

// persisted is the flat, durable form of one offender entry. Times are stored
// as RFC3339Nano UTC strings (identical to internal/history) so the two stores
// are dump-compatible and human-greppable; a zero time persists as "".
type persisted struct {
	Key         string
	Offenses    int
	Score       float64
	FirstSeen   time.Time
	LastOffense time.Time
	LastBanned  time.Time
	LastDecay   time.Time
	Subsystems  uint16
	BanUntil    time.Time // zero => no active ban
}

// store owns the single reputation.sqlite file and its write-behind writer.
type store struct {
	path       string
	bufferSize int
	flushEvery time.Duration
	flushBatch int

	mu sync.RWMutex
	db *sql.DB

	writeCh  chan persisted
	stopCh   chan struct{}
	doneCh   chan struct{}
	started  atomic.Bool
	stopping atomic.Bool

	dropped atomic.Uint64
	written atomic.Uint64
}

// storeOptions configures the durable store.
type storeOptions struct {
	Path       string        // full path to reputation.sqlite
	BufferSize int           // default 4096
	FlushEvery time.Duration // default 2s
	FlushBatch int           // default 256
}

const repSchema = `
CREATE TABLE IF NOT EXISTS rep_entries (
	key          TEXT PRIMARY KEY,
	offenses     INTEGER NOT NULL DEFAULT 0,
	score        REAL    NOT NULL DEFAULT 0,
	first_seen   TEXT    NOT NULL,
	last_offense TEXT    NOT NULL,
	last_banned  TEXT,
	last_decay   TEXT    NOT NULL,
	subsystems   INTEGER NOT NULL DEFAULT 0,
	ban_until    TEXT
);
CREATE INDEX IF NOT EXISTS idx_rep_last_offense ON rep_entries(last_offense);
CREATE INDEX IF NOT EXISTS idx_rep_ban_until    ON rep_entries(ban_until);
`

// repMigrations adds columns introduced after the initial schema so a
// long-lived reputation.sqlite picks up the newer shape on reopen. Duplicate-
// column errors are expected and ignored, exactly as internal/history does.
var repMigrations = []string{}

// openStore opens (creating if needed) the reputation DB at opts.Path. The
// parent directory is created 0o700 — the ledger holds attacker IPs and
// timestamps adjacent unprivileged users shouldn't enumerate (same posture as
// the history store).
func openStore(opts storeOptions) (*store, error) {
	if opts.Path == "" {
		return nil, errors.New("reputation: empty store path")
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = 4096
	}
	if opts.FlushEvery <= 0 {
		opts.FlushEvery = 2 * time.Second
	}
	if opts.FlushBatch <= 0 {
		opts.FlushBatch = 256
	}
	if dir := filepath.Dir(opts.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("reputation: create dir: %w", err)
		}
	}
	db, err := openRepDB(opts.Path)
	if err != nil {
		return nil, err
	}
	if err := applyRepSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	s := &store{
		path:       opts.Path,
		bufferSize: opts.BufferSize,
		flushEvery: opts.FlushEvery,
		flushBatch: opts.FlushBatch,
		db:         db,
		writeCh:    make(chan persisted, opts.BufferSize),
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}
	return s, nil
}

// loadAll reads every offender row. Called once at startup to seed the
// in-memory cache; never on the hot path.
func (s *store) loadAll() ([]persisted, error) {
	s.mu.RLock()
	db := s.db
	s.mu.RUnlock()
	if db == nil {
		return nil, errors.New("reputation: db is closed")
	}
	rows, err := db.Query(`SELECT key, offenses, score, first_seen, last_offense, last_banned, last_decay, subsystems, ban_until FROM rep_entries`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []persisted
	for rows.Next() {
		var p persisted
		var firstSeen, lastOffense, lastDecay string
		var lastBanned, banUntil sql.NullString
		var subsystems int64
		if err := rows.Scan(&p.Key, &p.Offenses, &p.Score, &firstSeen, &lastOffense, &lastBanned, &lastDecay, &subsystems, &banUntil); err != nil {
			continue
		}
		p.Subsystems = uint16(subsystems)
		p.FirstSeen = parseTime(firstSeen)
		p.LastOffense = parseTime(lastOffense)
		p.LastDecay = parseTime(lastDecay)
		if lastBanned.Valid {
			p.LastBanned = parseTime(lastBanned.String)
		}
		if banUntil.Valid {
			p.BanUntil = parseTime(banUntil.String)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// start launches the write-behind writer. Safe to call once.
func (s *store) start() {
	if !s.started.CompareAndSwap(false, true) {
		return
	}
	go s.writerLoop()
}

// enqueue queues a durable upsert. Non-blocking: if the buffer is full the
// write is dropped and a counter incremented — the in-memory cache already
// reflects the change, so a dropped durable write only costs us memory of it
// across a restart, never correctness while running.
func (s *store) enqueue(p persisted) {
	if s == nil || s.stopping.Load() {
		return
	}
	select {
	case s.writeCh <- p:
	default:
		s.dropped.Add(1)
	}
}

// close stops the writer, drains pending writes, and closes the DB. Safe to
// call multiple times and before start().
func (s *store) close() error {
	if s == nil {
		return nil
	}
	var err error
	s.stopping.Store(true)
	closeOnce(s.stopCh)
	if s.started.Load() {
		<-s.doneCh
	}
	s.mu.Lock()
	if s.db != nil {
		err = s.db.Close()
		s.db = nil
	}
	s.mu.Unlock()
	return err
}

func (s *store) writerLoop() {
	defer close(s.doneCh)
	defer func() {
		if rec := recover(); rec != nil {
			fmt.Fprintf(os.Stderr, "reputation: writer goroutine panicked: %v\n", rec)
			s.dropped.Add(1)
		}
	}()

	ticker := time.NewTicker(s.flushEvery)
	defer ticker.Stop()

	buf := make([]persisted, 0, s.flushBatch)
	flush := func() {
		if len(buf) == 0 {
			return
		}
		if err := s.writeBatch(buf); err != nil {
			fmt.Fprintf(os.Stderr, "reputation: batch write failed: %v\n", err)
		}
		buf = buf[:0]
	}

	for {
		select {
		case <-s.stopCh:
			for {
				select {
				case p := <-s.writeCh:
					buf = append(buf, p)
					if len(buf) >= s.flushBatch {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case p := <-s.writeCh:
			buf = append(buf, p)
			if len(buf) >= s.flushBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

const upsertSQL = `INSERT INTO rep_entries
	(key, offenses, score, first_seen, last_offense, last_banned, last_decay, subsystems, ban_until)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(key) DO UPDATE SET
		offenses     = excluded.offenses,
		score        = excluded.score,
		last_offense = excluded.last_offense,
		last_banned  = excluded.last_banned,
		last_decay   = excluded.last_decay,
		subsystems   = excluded.subsystems,
		ban_until    = excluded.ban_until`

// writeBatch persists a batch of upserts in a single transaction. first_seen is
// deliberately NOT updated on conflict (it's the offender's true first sighting).
func (s *store) writeBatch(batch []persisted) error {
	s.mu.RLock()
	db := s.db
	s.mu.RUnlock()
	if db == nil {
		return errors.New("reputation: db is closed")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, p := range batch {
		if _, err := tx.Exec(upsertSQL,
			p.Key, p.Offenses, p.Score,
			fmtTime(p.FirstSeen), fmtTime(p.LastOffense), nullTime(p.LastBanned),
			fmtTime(p.LastDecay), int64(p.Subsystems), nullTime(p.BanUntil),
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("reputation: upsert failed: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.written.Add(uint64(len(batch)))
	return nil
}

// purgeOlderThan deletes quiet offenders with no active ban whose last offense
// predates cutoff. Best-effort housekeeping; returns rows removed.
func (s *store) purgeOlderThan(cutoff time.Time, nowBanFloor time.Time) (int64, error) {
	s.mu.RLock()
	db := s.db
	s.mu.RUnlock()
	if db == nil {
		return 0, errors.New("reputation: db is closed")
	}
	// Keep rows with an active ban (ban_until in the future) regardless of age,
	// so a long escalated ban is never purged out from under the restore path.
	res, err := db.Exec(
		`DELETE FROM rep_entries WHERE last_offense < ? AND (ban_until IS NULL OR ban_until = '' OR ban_until < ?)`,
		fmtTime(cutoff), fmtTime(nowBanFloor),
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (s *store) stats() (dropped, written uint64) {
	return s.dropped.Load(), s.written.Load()
}

// -------- low-level helpers (mirrors internal/history) --------

func openRepDB(path string) (*sql.DB, error) {
	db, err := sql.Open(driverName, "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite is single-writer
	db.SetMaxIdleConns(1)
	return db, nil
}

func applyRepSchema(db *sql.DB) error {
	if _, err := db.Exec(repSchema); err != nil {
		return err
	}
	for _, stmt := range repMigrations {
		_, _ = db.Exec(stmt)
	}
	return nil
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// nullTime returns a NULL for a zero time so the nullable columns stay NULL
// rather than holding an empty string the indexes would have to carry.
func nullTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	return time.Time{}
}

// closeOnce closes ch unless it is already closed. The store guards close with
// stopping+started so this is only ever reached once per store, but the guard
// keeps a double close() from panicking.
func closeOnce(ch chan struct{}) {
	defer func() { _ = recover() }()
	select {
	case <-ch:
	default:
		close(ch)
	}
}
