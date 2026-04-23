// Package ssl manages TLS certificates visible to the admin dashboard.
// It persists uploaded certificates to an on-disk directory so they survive
// restarts, and tracks TLS policy settings that the proxy layer consumes.
package ssl

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

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
	certs map[string]Certificate // keyed by ID
	cfg   Config
}

// NewManager loads persisted state from dir. If dir doesn't exist it is created.
func NewManager(dir string) (*Manager, error) {
	if dir == "" {
		dir = "certs"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("ssl: create dir %q: %w", dir, err)
	}
	m := &Manager{
		dir:   dir,
		certs: make(map[string]Certificate),
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
	block, _ := pem.Decode([]byte(req.CertPEM))
	if block == nil {
		return Certificate{}, errors.New("ssl: cert_pem is not valid PEM")
	}
	x, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Certificate{}, fmt.Errorf("ssl: parse cert: %w", err)
	}
	sum := sha256.Sum256(x.Raw)
	fp := hex.EncodeToString(sum[:])
	cert := Certificate{
		ID:          fp[:16],
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

	m.mu.Lock()
	m.certs[cert.ID] = cert
	err = m.persistLocked()
	m.mu.Unlock()
	if err != nil {
		return Certificate{}, err
	}
	return cert, nil
}

// Delete removes a cert record and its files.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.certs[id]; !ok {
		return errors.New("ssl: certificate not found")
	}
	delete(m.certs, id)
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

// UpdateConfig merges patch into the current TLS config and persists it.
func (m *Manager) UpdateConfig(patch Config) (Config, error) {
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
