// Package history provides durable, time-rotated storage for WAF telemetry.
//
// A Store owns a directory of SQLite database files (one per rotation window,
// default 24 h). Incoming events are queued to a buffered channel and flushed
// to the current DB in batched transactions by a background worker. At the
// rotation boundary the current DB is finalised (its metadata row is updated
// with ended_at) and a new DB is opened.
//
// The store is designed so the hot path — proxy → telemetry → Enqueue — is
// non-blocking: if the buffer is full, events are dropped with a counter
// increment rather than stalling request handling.
package history

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const driverName = "sqlite"

// DefaultRotation is the default lifetime of a single history DB file.
const DefaultRotation = 24 * time.Hour

// BlockEvent is one persisted block record.
type BlockEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	IP           string    `json:"ip"`
	Method       string    `json:"method"`
	Path         string    `json:"path"`
	RuleID       string    `json:"rule_id"`
	RuleCategory string    `json:"rule_category"`
	Score        int       `json:"score"`
	Message      string    `json:"message"`
}

// IPActivity is an aggregated view of one IP's behaviour.
type IPActivity struct {
	IP           string    `json:"ip"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	RequestCount int64     `json:"request_count"`
	BlockCount   int64     `json:"block_count"`
}

// TrafficPoint is a single point on the traffic graph.
type TrafficPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Requests  int       `json:"requests"`
	Blocked   int       `json:"blocked"`
}

// DatabaseInfo describes one on-disk history DB.
type DatabaseInfo struct {
	Path       string    `json:"path"`
	StartedAt  time.Time `json:"started_at"`
	EndedAt    time.Time `json:"ended_at"`
	Active     bool      `json:"active"`
	SizeBytes  int64     `json:"size_bytes"`
	BlockCount int64     `json:"block_count"`
	IPCount    int64     `json:"ip_count"`
}

// Stats reports runtime counters about the store itself.
type Stats struct {
	CurrentPath   string `json:"current_path"`
	StartedAtUnix int64  `json:"started_at_unix"`
	BufferedQueue int    `json:"buffered_queue"`
	DroppedEvents uint64 `json:"dropped_events"`
	WrittenEvents uint64 `json:"written_events"`
	Rotations     uint64 `json:"rotations"`
}

// eventKind selects the table a queued event targets.
type eventKind int

const (
	kindBlock eventKind = iota
	kindRequest
	kindTrafficPoint
)

// event is a unit of work queued to the background writer.
type event struct {
	kind    eventKind
	block   BlockEvent
	ip      string
	blocked bool // only for kindRequest
	point   TrafficPoint
}

// RotationListener is invoked after a successful rotation with the new start time.
// It lets other subsystems (e.g. telemetry) reset their in-memory aggregates so
// the in-memory counters align with the fresh DB window.
type RotationListener func(newStart time.Time)

// Store is the history subsystem.
type Store struct {
	dir          string
	rotation     time.Duration
	wafVersion   string
	bufferSize   int
	flushEvery   time.Duration
	flushBatch   int
	listeners    []RotationListener

	mu          sync.RWMutex
	db          *sql.DB
	currentPath string
	startedAt   time.Time

	eventsCh chan event
	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}

	droppedEvents atomic.Uint64
	writtenEvents atomic.Uint64
	rotations     atomic.Uint64
}

// Options configures a Store.
type Options struct {
	Dir        string        // default "history"
	Rotation   time.Duration // default 24 h
	BufferSize int           // default 4096
	FlushEvery time.Duration // default 2 s
	FlushBatch int           // default 256
	WAFVersion string        // recorded in each DB's metadata row
}

// Open creates or reopens a history store rooted at opts.Dir.
func Open(opts Options) (*Store, error) {
	if opts.Dir == "" {
		opts.Dir = "history"
	}
	if opts.Rotation <= 0 {
		opts.Rotation = DefaultRotation
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

	if err := os.MkdirAll(opts.Dir, 0o755); err != nil {
		return nil, fmt.Errorf("history: create dir: %w", err)
	}

	s := &Store{
		dir:        opts.Dir,
		rotation:   opts.Rotation,
		wafVersion: opts.WAFVersion,
		bufferSize: opts.BufferSize,
		flushEvery: opts.FlushEvery,
		flushBatch: opts.FlushBatch,
		eventsCh:   make(chan event, opts.BufferSize),
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}

	if err := s.openOrCreateCurrent(); err != nil {
		return nil, err
	}
	return s, nil
}

// Start launches the background writer + rotation loops. Safe to call once.
func (s *Store) Start(ctx context.Context) {
	go s.writerLoop(ctx)
}

// OnRotate registers a callback fired after each successful rotation.
func (s *Store) OnRotate(fn RotationListener) {
	if fn == nil {
		return
	}
	s.mu.Lock()
	s.listeners = append(s.listeners, fn)
	s.mu.Unlock()
}

// SetRotation updates the rotation window dynamically.
func (s *Store) SetRotation(d time.Duration) {
	if d <= 0 {
		return
	}
	s.mu.Lock()
	s.rotation = d
	s.mu.Unlock()
}

// Close stops the writer and closes the active DB. Safe to call multiple times.
func (s *Store) Close() error {
	var err error
	s.stopOnce.Do(func() {
		close(s.stopCh)
		<-s.doneCh
		s.mu.Lock()
		if s.db != nil {
			s.finaliseMetadataLocked()
			err = s.db.Close()
			s.db = nil
		}
		s.mu.Unlock()
	})
	return err
}

// -------- hot-path enqueue --------

// EnqueueBlock queues a block event for durable storage. Non-blocking:
// if the buffer is full the event is dropped and a counter incremented.
func (s *Store) EnqueueBlock(e BlockEvent) {
	if s == nil {
		return
	}
	ev := event{kind: kindBlock, block: e}
	select {
	case s.eventsCh <- ev:
	default:
		s.droppedEvents.Add(1)
	}
}

// EnqueueRequest updates ip_activity for a single observed request.
// blocked=true increments the block counter as well.
func (s *Store) EnqueueRequest(ip string, blocked bool) {
	if s == nil || ip == "" {
		return
	}
	ev := event{kind: kindRequest, ip: ip, blocked: blocked}
	select {
	case s.eventsCh <- ev:
	default:
		s.droppedEvents.Add(1)
	}
}

// EnqueueTrafficPoint persists a traffic graph sample.
func (s *Store) EnqueueTrafficPoint(p TrafficPoint) {
	if s == nil {
		return
	}
	ev := event{kind: kindTrafficPoint, point: p}
	select {
	case s.eventsCh <- ev:
	default:
		s.droppedEvents.Add(1)
	}
}

// -------- background writer --------

func (s *Store) writerLoop(ctx context.Context) {
	defer close(s.doneCh)
	defer func() {
		if rec := recover(); rec != nil {
			// Best-effort: any panic in the writer must not take the process down.
			_ = rec
		}
	}()

	flushTicker := time.NewTicker(s.flushEvery)
	defer flushTicker.Stop()
	rotationTicker := time.NewTicker(time.Minute)
	defer rotationTicker.Stop()

	buf := make([]event, 0, s.flushBatch)
	flush := func() {
		if len(buf) == 0 {
			return
		}
		if err := s.writeBatch(buf); err != nil {
			// Log to stderr via fmt; avoid pulling in the logger dep.
			fmt.Fprintf(os.Stderr, "history: batch write failed: %v\n", err)
		}
		buf = buf[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case <-s.stopCh:
			// Drain remaining events before exiting.
			for {
				select {
				case ev := <-s.eventsCh:
					buf = append(buf, ev)
					if len(buf) >= s.flushBatch {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case ev := <-s.eventsCh:
			buf = append(buf, ev)
			if len(buf) >= s.flushBatch {
				flush()
			}
		case <-flushTicker.C:
			flush()
		case <-rotationTicker.C:
			s.maybeRotate()
		}
	}
}

// writeBatch runs all buffered events inside a single transaction on the current DB.
func (s *Store) writeBatch(batch []event) error {
	s.mu.RLock()
	db := s.db
	s.mu.RUnlock()
	if db == nil {
		return errors.New("history: db is closed")
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	// Commit/rollback is handled at the end.
	var blocks, reqs, points int
	for _, ev := range batch {
		switch ev.kind {
		case kindBlock:
			b := ev.block
			_, err = tx.Exec(
				`INSERT INTO blocks (ts, ip, method, path, rule_id, rule_category, score, message) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				b.Timestamp.UTC().Format(time.RFC3339Nano), b.IP, b.Method, b.Path, b.RuleID, b.RuleCategory, b.Score, b.Message,
			)
			if err == nil {
				// Also increment ip_activity.block_count.
				_, err = tx.Exec(
					`INSERT INTO ip_activity (ip, first_seen, last_seen, request_count, block_count) VALUES (?, ?, ?, 0, 1)
					 ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen, block_count = block_count + 1`,
					b.IP, b.Timestamp.UTC().Format(time.RFC3339Nano), b.Timestamp.UTC().Format(time.RFC3339Nano),
				)
			}
			blocks++
		case kindRequest:
			now := time.Now().UTC().Format(time.RFC3339Nano)
			blockInc := 0
			if ev.blocked {
				blockInc = 1
			}
			_, err = tx.Exec(
				`INSERT INTO ip_activity (ip, first_seen, last_seen, request_count, block_count) VALUES (?, ?, ?, 1, ?)
				 ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen, request_count = request_count + 1, block_count = block_count + ?`,
				ev.ip, now, now, blockInc, blockInc,
			)
			reqs++
		case kindTrafficPoint:
			p := ev.point
			_, err = tx.Exec(
				`INSERT INTO traffic_points (ts, requests, blocked) VALUES (?, ?, ?)`,
				p.Timestamp.UTC().Format(time.RFC3339Nano), p.Requests, p.Blocked,
			)
			points++
		}
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("history: insert failed: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.writtenEvents.Add(uint64(blocks + reqs + points))
	return nil
}

// -------- rotation --------

func (s *Store) maybeRotate() {
	s.mu.RLock()
	started := s.startedAt
	s.mu.RUnlock()
	if time.Since(started) < s.rotation {
		return
	}
	if err := s.rotate(); err != nil {
		fmt.Fprintf(os.Stderr, "history: rotate failed: %v\n", err)
	}
}

func (s *Store) rotate() error {
	s.mu.Lock()
	// Finalise current.
	if s.db != nil {
		s.finaliseMetadataLocked()
		_ = s.db.Close()
		s.db = nil
	}
	listeners := append([]RotationListener(nil), s.listeners...)
	s.mu.Unlock()

	if err := s.openOrCreateCurrent(); err != nil {
		return err
	}
	s.rotations.Add(1)

	s.mu.RLock()
	newStart := s.startedAt
	s.mu.RUnlock()
	for _, fn := range listeners {
		func() {
			defer func() { _ = recover() }()
			fn(newStart)
		}()
	}
	return nil
}

// openOrCreateCurrent picks the newest non-finalised DB within the rotation
// window, or creates a fresh one. On success s.db is set.
func (s *Store) openOrCreateCurrent() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, err := s.listDatabasesLocked()
	if err == nil && len(existing) > 0 {
		latest := existing[len(existing)-1]
		if latest.Active && time.Since(latest.StartedAt) < s.rotation {
			db, err := openDB(latest.Path)
			if err == nil {
				s.db = db
				s.currentPath = latest.Path
				s.startedAt = latest.StartedAt
				return nil
			}
		}
	}

	now := time.Now().UTC()
	name := fmt.Sprintf("waf-%s.sqlite", now.Format("2006-01-02T15-04-05Z"))
	path := filepath.Join(s.dir, name)
	db, err := openDB(path)
	if err != nil {
		return err
	}
	if err := applySchema(db); err != nil {
		_ = db.Close()
		return err
	}
	if _, err := db.Exec(
		`INSERT INTO metadata (started_at, waf_version, rotation_seconds) VALUES (?, ?, ?)`,
		now.Format(time.RFC3339Nano), s.wafVersion, int(s.rotation.Seconds()),
	); err != nil {
		_ = db.Close()
		return err
	}
	s.db = db
	s.currentPath = path
	s.startedAt = now
	return nil
}

func (s *Store) finaliseMetadataLocked() {
	if s.db == nil {
		return
	}
	_, _ = s.db.Exec(
		`UPDATE metadata SET ended_at = ? WHERE ended_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
}

// -------- queries --------

// ListDatabases returns metadata for every history DB in the directory,
// ordered by start time ascending.
func (s *Store) ListDatabases() ([]DatabaseInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listDatabasesLocked()
}

func (s *Store) listDatabasesLocked() ([]DatabaseInfo, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	out := make([]DatabaseInfo, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sqlite") {
			continue
		}
		p := filepath.Join(s.dir, e.Name())
		info, err := describeDB(p)
		if err != nil {
			continue
		}
		if s.currentPath == p {
			info.Active = true
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.Before(out[j].StartedAt) })
	return out, nil
}

// QueryBlocks returns BlockEvents across all DBs intersecting [from, to].
func (s *Store) QueryBlocks(from, to time.Time, limit int) ([]BlockEvent, error) {
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	dbs, err := s.ListDatabases()
	if err != nil {
		return nil, err
	}
	var out []BlockEvent
	for i := len(dbs) - 1; i >= 0 && len(out) < limit; i-- {
		d := dbs[i]
		if d.EndedAt.Before(from) && !d.EndedAt.IsZero() {
			continue
		}
		if d.StartedAt.After(to) {
			continue
		}
		rows, err := s.queryBlocksFromFile(d.Path, from, to, limit-len(out))
		if err != nil {
			continue
		}
		out = append(out, rows...)
	}
	return out, nil
}

func (s *Store) queryBlocksFromFile(path string, from, to time.Time, limit int) ([]BlockEvent, error) {
	db, err := openReadOnly(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(
		`SELECT ts, ip, method, path, rule_id, rule_category, score, message FROM blocks
		 WHERE ts >= ? AND ts <= ? ORDER BY ts DESC LIMIT ?`,
		from.UTC().Format(time.RFC3339Nano), to.UTC().Format(time.RFC3339Nano), limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BlockEvent
	for rows.Next() {
		var b BlockEvent
		var ts string
		if err := rows.Scan(&ts, &b.IP, &b.Method, &b.Path, &b.RuleID, &b.RuleCategory, &b.Score, &b.Message); err != nil {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			b.Timestamp = t
		}
		out = append(out, b)
	}
	return out, nil
}

// QueryIPs returns top IPs by request_count across DBs in range.
func (s *Store) QueryIPs(from, to time.Time, limit int) ([]IPActivity, error) {
	if limit <= 0 || limit > 10000 {
		limit = 100
	}
	dbs, err := s.ListDatabases()
	if err != nil {
		return nil, err
	}
	// Aggregate across DBs — same IP may appear in multiple files.
	agg := make(map[string]*IPActivity)
	for _, d := range dbs {
		if d.EndedAt.Before(from) && !d.EndedAt.IsZero() {
			continue
		}
		if d.StartedAt.After(to) {
			continue
		}
		rows, err := s.queryIPsFromFile(d.Path)
		if err != nil {
			continue
		}
		for _, r := range rows {
			existing, ok := agg[r.IP]
			if !ok {
				cp := r
				agg[r.IP] = &cp
				continue
			}
			if r.FirstSeen.Before(existing.FirstSeen) {
				existing.FirstSeen = r.FirstSeen
			}
			if r.LastSeen.After(existing.LastSeen) {
				existing.LastSeen = r.LastSeen
			}
			existing.RequestCount += r.RequestCount
			existing.BlockCount += r.BlockCount
		}
	}
	out := make([]IPActivity, 0, len(agg))
	for _, v := range agg {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RequestCount > out[j].RequestCount })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) queryIPsFromFile(path string) ([]IPActivity, error) {
	db, err := openReadOnly(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT ip, first_seen, last_seen, request_count, block_count FROM ip_activity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IPActivity
	for rows.Next() {
		var r IPActivity
		var first, last string
		if err := rows.Scan(&r.IP, &first, &last, &r.RequestCount, &r.BlockCount); err != nil {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, first); err == nil {
			r.FirstSeen = t
		}
		if t, err := time.Parse(time.RFC3339Nano, last); err == nil {
			r.LastSeen = t
		}
		out = append(out, r)
	}
	return out, nil
}

// QueryTraffic returns traffic points across DBs in range, newest first.
func (s *Store) QueryTraffic(from, to time.Time, limit int) ([]TrafficPoint, error) {
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	dbs, err := s.ListDatabases()
	if err != nil {
		return nil, err
	}
	var out []TrafficPoint
	for i := len(dbs) - 1; i >= 0 && len(out) < limit; i-- {
		d := dbs[i]
		if d.EndedAt.Before(from) && !d.EndedAt.IsZero() {
			continue
		}
		if d.StartedAt.After(to) {
			continue
		}
		points, err := queryTrafficFromFile(d.Path, from, to, limit-len(out))
		if err != nil {
			continue
		}
		out = append(out, points...)
	}
	return out, nil
}

func queryTrafficFromFile(path string, from, to time.Time, limit int) ([]TrafficPoint, error) {
	db, err := openReadOnly(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(
		`SELECT ts, requests, blocked FROM traffic_points WHERE ts >= ? AND ts <= ? ORDER BY ts DESC LIMIT ?`,
		from.UTC().Format(time.RFC3339Nano), to.UTC().Format(time.RFC3339Nano), limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrafficPoint
	for rows.Next() {
		var p TrafficPoint
		var ts string
		if err := rows.Scan(&ts, &p.Requests, &p.Blocked); err != nil {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			p.Timestamp = t
		}
		out = append(out, p)
	}
	return out, nil
}

// StatsSnapshot returns runtime stats about the store itself.
func (s *Store) StatsSnapshot() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Stats{
		CurrentPath:   s.currentPath,
		StartedAtUnix: s.startedAt.Unix(),
		BufferedQueue: len(s.eventsCh),
		DroppedEvents: s.droppedEvents.Load(),
		WrittenEvents: s.writtenEvents.Load(),
		Rotations:     s.rotations.Load(),
	}
}

// -------- low-level DB helpers --------

const schema = `
CREATE TABLE IF NOT EXISTS metadata (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	started_at TEXT NOT NULL,
	ended_at   TEXT,
	waf_version TEXT,
	rotation_seconds INTEGER
);
CREATE TABLE IF NOT EXISTS blocks (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts TEXT NOT NULL,
	ip TEXT NOT NULL,
	method TEXT,
	path TEXT,
	rule_id TEXT,
	rule_category TEXT,
	score INTEGER,
	message TEXT
);
CREATE INDEX IF NOT EXISTS idx_blocks_ts ON blocks(ts);
CREATE INDEX IF NOT EXISTS idx_blocks_ip ON blocks(ip);
CREATE TABLE IF NOT EXISTS ip_activity (
	ip TEXT PRIMARY KEY,
	first_seen TEXT NOT NULL,
	last_seen  TEXT NOT NULL,
	request_count INTEGER NOT NULL DEFAULT 0,
	block_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS traffic_points (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts TEXT NOT NULL,
	requests INTEGER NOT NULL,
	blocked INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic_points(ts);
`

func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open(driverName, "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite is single-writer; avoid contention
	db.SetMaxIdleConns(1)
	return db, nil
}

func openReadOnly(path string) (*sql.DB, error) {
	db, err := sql.Open(driverName, "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

func applySchema(db *sql.DB) error {
	_, err := db.Exec(schema)
	return err
}

// describeDB opens a DB read-only and extracts its metadata + counts.
func describeDB(path string) (DatabaseInfo, error) {
	info := DatabaseInfo{Path: path}
	if fi, err := os.Stat(path); err == nil {
		info.SizeBytes = fi.Size()
	}
	db, err := openReadOnly(path)
	if err != nil {
		return info, err
	}
	defer db.Close()

	var started, ended sql.NullString
	row := db.QueryRow(`SELECT started_at, ended_at FROM metadata ORDER BY id DESC LIMIT 1`)
	if err := row.Scan(&started, &ended); err == nil {
		if started.Valid {
			if t, err := time.Parse(time.RFC3339Nano, started.String); err == nil {
				info.StartedAt = t
			}
		}
		if ended.Valid {
			if t, err := time.Parse(time.RFC3339Nano, ended.String); err == nil {
				info.EndedAt = t
			} else {
				info.Active = true
			}
		} else {
			info.Active = true
		}
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM blocks`).Scan(&info.BlockCount)
	_ = db.QueryRow(`SELECT COUNT(*) FROM ip_activity`).Scan(&info.IPCount)
	return info, nil
}
