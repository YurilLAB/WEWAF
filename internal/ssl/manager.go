// Package ssl manages TLS certificates visible to the admin dashboard.
// It persists uploaded certificates to an on-disk directory so they survive
// restarts, and tracks TLS policy settings that the proxy layer consumes.
package ssl

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// certIDPattern is the SHA-256 hex fingerprint shape — 64 lowercase hex
// chars. Delete() callers route URL-derived IDs through this so a
// future code change that loosens fingerprint generation can't open a
// path-traversal hole on the cert directory.
var certIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// weakSigAlgorithms lists signature algorithms we refuse on upload.
// MD5 and SHA-1 are publicly broken for collision resistance; a CA
// that still signs with them is itself a red flag, and accepting such
// a cert silently weakens the operator's TLS posture.
var weakSigAlgorithms = map[x509.SignatureAlgorithm]string{
	x509.MD2WithRSA:      "MD2-with-RSA",
	x509.MD5WithRSA:      "MD5-with-RSA",
	x509.SHA1WithRSA:     "SHA1-with-RSA",
	x509.DSAWithSHA1:     "DSA-with-SHA1",
	x509.ECDSAWithSHA1:   "ECDSA-with-SHA1",
}

// validateCertStrength rejects certificates whose key or signature
// algorithm is below industry baseline. The thresholds match common
// browser-and-CA expectations: RSA ≥ 2048, ECDSA on P-256/P-384/P-521,
// Ed25519, and signature SHA-256 or stronger. Everything else is
// either a typo / mis-paste or a deliberate downgrade attempt and we
// fail closed at upload time so the operator hears about it loudly.
func validateCertStrength(c *x509.Certificate) error {
	if name, bad := weakSigAlgorithms[c.SignatureAlgorithm]; bad {
		return fmt.Errorf("ssl: certificate signed with weak algorithm %s", name)
	}
	switch pk := c.PublicKey.(type) {
	case *rsa.PublicKey:
		if pk.N.BitLen() < 2048 {
			return fmt.Errorf("ssl: RSA key too short (%d bits, need ≥2048)", pk.N.BitLen())
		}
	case *ecdsa.PublicKey:
		// P-256, P-384, P-521 only. P-224 is below baseline; non-NIST
		// curves are unusual enough to refuse outright.
		switch pk.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
		default:
			return fmt.Errorf("ssl: ECDSA curve %v not in {P-256, P-384, P-521}", pk.Curve.Params().Name)
		}
	case ed25519.PublicKey:
		// Ed25519 has a fixed strength ≥128-bit security; nothing to
		// check.
	default:
		return fmt.Errorf("ssl: unsupported public-key type %T", pk)
	}
	return nil
}

// Certificate is the public view returned by /api/ssl/certificates.
type Certificate struct {
	ID          string    `json:"id"`
	Domain      string    `json:"domain"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"`
	AutoRenew   bool      `json:"auto_renew"`
	Valid       bool      `json:"valid"`
}

// UploadRequest is the body accepted by POST /api/ssl/certificates.
type UploadRequest struct {
	Domain  string `json:"domain"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// Config models /api/ssl/config.
type Config struct {
	Enabled             bool   `json:"enabled"`
	CertSource          string `json:"cert_source"`   // "auto" | "upload"
	MinTLSVersion       string `json:"min_tls_version"` // "1.0".."1.3"
	PreferServerCiphers bool   `json:"prefer_server_ciphers"`
	HSTSEnabled         bool   `json:"hsts_enabled"`
	HSTSMaxAge          int    `json:"hsts_max_age"`
}

// Manager owns the in-memory cert cache, on-disk persistence, and TLS config.
type Manager struct {
	mu    sync.RWMutex
	dir   string
	certs map[string]Certificate // keyed by ID (SHA-256 hex fingerprint)
	cfg   Config

	// tlsCerts keys parsed *tls.Certificate values by lowercase
	// domain so SNI resolution can return the matching cert without
	// touching the disk on every handshake. Populated by loadIndex
	// at startup and by Upload at runtime; cleared on Delete. The
	// in-memory copy is the source of truth for the TLS listener.
	tlsCerts map[string]*tls.Certificate
}

// NewManager loads persisted state from dir. If dir doesn't exist it is created.
func NewManager(dir string) (*Manager, error) {
	if dir == "" {
		dir = "certs"
	}
	// 0o700 — this directory holds private keys (.key files), so any
	// world-readable bit on the parent directory is an obvious
	// regression. POSIX-only; on Windows ACLs are inherited.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ssl: create dir %q: %w", dir, err)
	}
	m := &Manager{
		dir:      dir,
		certs:    make(map[string]Certificate),
		tlsCerts: make(map[string]*tls.Certificate),
		cfg: Config{
			Enabled:             false,
			CertSource:          "upload",
			MinTLSVersion:       "1.2",
			PreferServerCiphers: true,
			HSTSEnabled:         false,
			HSTSMaxAge:          31536000,
		},
	}
	m.loadIndex()
	return m, nil
}

func (m *Manager) indexPath() string  { return filepath.Join(m.dir, "index.json") }
func (m *Manager) configPath() string { return filepath.Join(m.dir, "config.json") }

type indexFile struct {
	Certs  []Certificate `json:"certs"`
	Config Config        `json:"config"`
}

func (m *Manager) loadIndex() {
	data, err := os.ReadFile(m.indexPath())
	if err != nil {
		return
	}
	var idx indexFile
	if err := json.Unmarshal(data, &idx); err != nil {
		return
	}
	for _, c := range idx.Certs {
		m.certs[c.ID] = c
		// Hot load of each cert pair so the TLS listener can serve
		// straight away without a separate Upload(). A missing or
		// corrupt key file used to be silent — the cert metadata
		// would appear in /api/ssl/certificates but every TLS
		// handshake against the domain would fail. Surface the
		// inconsistency at startup so the operator catches it
		// before users do; we keep the partially-loaded state so
		// the rest of the certs still serve.
		pair, perr := tls.LoadX509KeyPair(
			filepath.Join(m.dir, c.ID+".crt"),
			filepath.Join(m.dir, c.ID+".key"),
		)
		if perr != nil {
			log.Printf("ssl: cert %s (domain=%s) failed to load from disk: %v",
				c.ID, c.Domain, perr)
			continue
		}
		m.tlsCerts[strings.ToLower(c.Domain)] = &pair
	}
	if idx.Config.MinTLSVersion != "" {
		m.cfg = idx.Config
	}
}

func (m *Manager) persistLocked() error {
	certs := make([]Certificate, 0, len(m.certs))
	for _, c := range m.certs {
		certs = append(certs, c)
	}
	sort.Slice(certs, func(i, j int) bool { return certs[i].Domain < certs[j].Domain })
	idx := indexFile{Certs: certs, Config: m.cfg}
	buf, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.indexPath(), buf, 0o600)
}

// List returns all known certificates, sorted by domain.
func (m *Manager) List() []Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Certificate, 0, len(m.certs))
	for _, c := range m.certs {
		c.Valid = time.Now().Before(c.NotAfter) && time.Now().After(c.NotBefore)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// Upload parses cert_pem + key_pem, stores them to disk, and returns the record.
func (m *Manager) Upload(req UploadRequest) (Certificate, error) {
	if req.Domain == "" || req.CertPEM == "" || req.KeyPEM == "" {
		return Certificate{}, errors.New("ssl: domain, cert_pem, and key_pem are required")
	}
	// Bound the inputs so a typo or malicious admin can't write a 1 GB
	// "key" file to disk and parse it. A real PEM cert/key chain is at
	// most a few KB; 256 KB is a generous ceiling.
	if len(req.CertPEM) > 256*1024 || len(req.KeyPEM) > 256*1024 {
		return Certificate{}, errors.New("ssl: cert_pem / key_pem too large")
	}
	if len(req.Domain) > 253 {
		return Certificate{}, errors.New("ssl: domain too long")
	}
	block, _ := pem.Decode([]byte(req.CertPEM))
	if block == nil {
		return Certificate{}, errors.New("ssl: cert_pem is not valid PEM")
	}
	x, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Certificate{}, fmt.Errorf("ssl: parse cert: %w", err)
	}
	// Reject certificates that are below today's cryptographic floor
	// before we touch the disk. A 1024-bit RSA cert or a SHA-1-signed
	// cert would otherwise load and quietly weaken the TLS posture
	// for every connection that picked it up.
	if err := validateCertStrength(x); err != nil {
		return Certificate{}, err
	}
	// Validate the key by parsing it AND confirm it matches the cert.
	// The previous code wrote the key bytes verbatim with no checks,
	// meaning an admin could store arbitrary content (or, more likely,
	// a mismatched key from a different cert) and the failure would
	// only surface much later when the TLS listener loaded the pair.
	keyBlock, _ := pem.Decode([]byte(req.KeyPEM))
	if keyBlock == nil {
		return Certificate{}, errors.New("ssl: key_pem is not valid PEM")
	}
	if _, err := tls.X509KeyPair([]byte(req.CertPEM), []byte(req.KeyPEM)); err != nil {
		return Certificate{}, fmt.Errorf("ssl: cert and key do not match: %w", err)
	}
	if err := x.VerifyHostname(req.Domain); err != nil {
		return Certificate{}, fmt.Errorf("ssl: cert does not cover domain %q: %w", req.Domain, err)
	}
	sum := sha256.Sum256(x.Raw)
	fp := hex.EncodeToString(sum[:])
	cert := Certificate{
		ID:          fp, // full fingerprint as ID — 64-bit truncation invited collisions
		Domain:      req.Domain,
		Issuer:      x.Issuer.CommonName,
		NotBefore:   x.NotBefore,
		NotAfter:    x.NotAfter,
		Fingerprint: fp,
		AutoRenew:   false,
		Valid:       time.Now().Before(x.NotAfter) && time.Now().After(x.NotBefore),
	}

	certFile := filepath.Join(m.dir, cert.ID+".crt")
	keyFile := filepath.Join(m.dir, cert.ID+".key")
	if err := os.WriteFile(certFile, []byte(req.CertPEM), 0o600); err != nil {
		return Certificate{}, err
	}
	if err := os.WriteFile(keyFile, []byte(req.KeyPEM), 0o600); err != nil {
		return Certificate{}, err
	}

	// Parse the pair once into a *tls.Certificate so the TLS listener
	// can serve it without re-reading from disk. We've already passed
	// tls.X509KeyPair above, so a re-parse is just CPU; the cost is
	// paid once per upload, not once per handshake.
	pair, perr := tls.X509KeyPair([]byte(req.CertPEM), []byte(req.KeyPEM))
	if perr != nil {
		return Certificate{}, fmt.Errorf("ssl: re-parse pair: %w", perr)
	}

	m.mu.Lock()
	m.certs[cert.ID] = cert
	m.tlsCerts[strings.ToLower(cert.Domain)] = &pair
	err = m.persistLocked()
	m.mu.Unlock()
	if err != nil {
		return Certificate{}, err
	}
	return cert, nil
}

// Delete removes a cert record and its files. The id format check is
// defence-in-depth: today every ID is a SHA-256 hex fingerprint
// generated by Upload(), but a future code change that loosened
// fingerprint generation could otherwise turn this into a path
// traversal sink (e.g. id="../../etc/passwd"). Refuse anything that
// isn't 64 lowercase hex chars even if the id is in the in-memory
// map — somebody who can populate that map can already hurt us in
// other ways, but this keeps us honest.
func (m *Manager) Delete(id string) error {
	if !certIDPattern.MatchString(id) {
		return errors.New("ssl: certificate id must be a 64-char SHA-256 hex fingerprint")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.certs[id]
	if !ok {
		return errors.New("ssl: certificate not found")
	}
	delete(m.certs, id)
	delete(m.tlsCerts, strings.ToLower(c.Domain))
	_ = os.Remove(filepath.Join(m.dir, id+".crt"))
	_ = os.Remove(filepath.Join(m.dir, id+".key"))
	return m.persistLocked()
}

// ConfigSnapshot returns the current TLS configuration.
func (m *Manager) ConfigSnapshot() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

// minVersionFor maps the operator-friendly "1.2"/"1.3" string to the
// crypto/tls constant. Returns the safe-default tls.VersionTLS12 for
// any unrecognised input — Validate / UpdateConfig refuse those at
// write time, so reaching the default here means the on-disk config
// pre-dates the validation upgrade.
func minVersionFor(s string) uint16 {
	switch s {
	case "1.3":
		return tls.VersionTLS13
	case "1.2":
		return tls.VersionTLS12
	default:
		return tls.VersionTLS12
	}
}

// modernCipherSuites is the Mozilla-"intermediate"-aligned subset of
// the Go cipher list: AEAD only (no CBC), forward-secret (ECDHE only,
// no plain RSA key exchange), no SHA-1 MAC. TLS 1.3 ignores this
// field entirely (Go fixes the cipher list), but configurations that
// still allow 1.2 must not negotiate the deprecated suites.
var modernCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// modernCurves is the corresponding curve list — X25519 first because
// it's the fastest on modern hardware, then the NIST curves for
// peers that don't speak it.
var modernCurves = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}

// HasUsableCerts reports whether at least one parsed cert is
// available for SNI. Callers use this to decide whether to bind a
// TLS listener at all — there's no point starting one with an empty
// certificate set; the handshake would fail every time.
func (m *Manager) HasUsableCerts() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tlsCerts) > 0
}

// BuildTLSConfig returns a *tls.Config ready to use with
// http.Server.TLSConfig + ListenAndServeTLS("", ""). Returns
// (nil, nil) when the manager has no certs loaded — the caller is
// expected to fall back to plaintext rather than try to bind a TLS
// listener with no usable cert (which would either panic or refuse
// every handshake).
//
// The returned config:
//   - sets MinVersion from m.cfg.MinTLSVersion (1.2 / 1.3 only,
//     enforced on write by UpdateConfig)
//   - restricts CipherSuites to modern AEAD+PFS suites for TLS 1.2
//     handshakes; TLS 1.3 ignores the field
//   - sets CurvePreferences to {X25519, P-256, P-384}
//   - resolves the certificate via SNI through GetCertificate so
//     multi-domain deployments work without per-listener wiring
//   - leaves NextProtos empty so the http.Server can negotiate h1/h2
//     based on its own choice, matching the existing plaintext path
//
// Defensive: snapshots the cert map under the lock, never holds the
// lock across a handshake. Hot-reload (Upload / Delete) replaces the
// underlying map entries so subsequent handshakes pick up the new
// cert without restarting the listener.
func (m *Manager) BuildTLSConfig() (*tls.Config, error) {
	if m == nil {
		return nil, errors.New("ssl: nil manager")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.tlsCerts) == 0 {
		return nil, nil
	}
	// Note: we deliberately do NOT populate cfg.Certificates. The
	// previous version snapshotted the alphabetically-first cert
	// into Certificates as a "default", but Go's crypto/tls only
	// consults that field when GetCertificate returns
	// (nil, nil) — and our getCertificateBySNI never does that
	// once the map is non-empty (it falls back to the first cert
	// inside the callback). Holding a stale snapshot here would
	// also drift behind a hot-reload Upload/Delete; keeping the
	// callback as the single source of truth avoids that class
	// of staleness entirely.
	cfg := &tls.Config{
		MinVersion:       minVersionFor(m.cfg.MinTLSVersion),
		CipherSuites:     modernCipherSuites,
		CurvePreferences: modernCurves,
		// SessionTicketsDisabled left at default (false) — Go's
		// session tickets are auto-rotated, and turning them off
		// hurts mobile-client resumption with no security gain.
		GetCertificate: m.getCertificateBySNI,
	}
	return cfg, nil
}

// getCertificateBySNI is the GetCertificate callback for
// BuildTLSConfig. Picks the cert whose registered domain (lowercased
// at upload time) equals the ClientHello SNI; falls back to any cert
// if SNI is missing. Bracketed in defer/recover so a malformed
// ClientHello can never crash the listener.
func (m *Manager) getCertificateBySNI(chi *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("ssl: GetCertificate panic: %v", rec)
		}
	}()
	if chi == nil {
		return nil, errors.New("ssl: nil ClientHelloInfo")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.tlsCerts) == 0 {
		return nil, errors.New("ssl: no certificates loaded")
	}
	name := strings.ToLower(strings.TrimSuffix(chi.ServerName, "."))
	if name != "" {
		if c, ok := m.tlsCerts[name]; ok {
			return c, nil
		}
		// Wildcard sweep: if we have *.example.com registered as a
		// literal domain, match a request for foo.example.com.
		// Operators upload wildcard certs with the wildcard domain
		// in the request body, so the map key contains the literal
		// "*.example.com" string.
		if i := strings.IndexByte(name, '.'); i > 0 {
			if c, ok := m.tlsCerts["*"+name[i:]]; ok {
				return c, nil
			}
		}
	}
	// Fall back to the alphabetically-first cert. This isn't a
	// security regression — every cert in the set has been validated
	// to today's strength baseline at Upload time. It's just less
	// useful than a true match.
	for _, d := range sortedKeys(m.tlsCerts) {
		return m.tlsCerts[d], nil
	}
	return nil, errors.New("ssl: no usable certificate")
}

// sortedKeys returns the map's keys in lexicographic order. Used by
// getCertificateBySNI so the fallback pick is deterministic across
// restarts (callers that audit the chosen cert via a packet capture
// won't see it churn for no reason).
func sortedKeys(m map[string]*tls.Certificate) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// validMinTLSVersions is the closed set of values UpdateConfig will
// accept. We refuse "1.0" / "1.1" outright — both have been deprecated
// by every major browser and standards body, and accepting the value
// here would persist it to disk without ever being consumed (the SSL
// manager is currently metadata-only; external TLS terminators read
// MinTLSVersion via /api/ssl/config to mirror the policy). Refusing
// at write time means the operator hears the error immediately rather
// than discovering it after a deploy.
var validMinTLSVersions = map[string]struct{}{
	"1.2": {},
	"1.3": {},
}

// validCertSources is similar — empty was previously a no-op patch
// while any other value was silently stored.
var validCertSources = map[string]struct{}{
	"upload": {},
	"auto":   {},
}

// UpdateConfig merges patch into the current TLS config and persists it.
func (m *Manager) UpdateConfig(patch Config) (Config, error) {
	if patch.MinTLSVersion != "" {
		if _, ok := validMinTLSVersions[patch.MinTLSVersion]; !ok {
			return Config{}, fmt.Errorf("ssl: min_tls_version %q not allowed (must be 1.2 or 1.3)", patch.MinTLSVersion)
		}
	}
	if patch.CertSource != "" {
		if _, ok := validCertSources[patch.CertSource]; !ok {
			return Config{}, fmt.Errorf("ssl: cert_source %q not allowed (must be 'upload' or 'auto')", patch.CertSource)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if patch.MinTLSVersion != "" {
		m.cfg.MinTLSVersion = patch.MinTLSVersion
	}
	if patch.CertSource != "" {
		m.cfg.CertSource = patch.CertSource
	}
	m.cfg.Enabled = patch.Enabled
	m.cfg.PreferServerCiphers = patch.PreferServerCiphers
	m.cfg.HSTSEnabled = patch.HSTSEnabled
	if patch.HSTSMaxAge > 0 {
		m.cfg.HSTSMaxAge = patch.HSTSMaxAge
	}
	if err := m.persistLocked(); err != nil {
		return Config{}, err
	}
	return m.cfg, nil
}
