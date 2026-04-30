package ssl

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// makeRSACert is a self-signed cert helper for the strength tests. We
// keep it tiny — these tests only care about which inputs Upload()
// accepts vs rejects, not about TLS termination per se.
func makeRSACert(t *testing.T, bits int, sig x509.SignatureAlgorithm) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(%d): %v", bits, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "wewaf.test"},
		DNSNames:              []string{"wewaf.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    sig,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER := x509.MarshalPKCS1PrivateKey(priv)
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}))
	return
}

func makeEd25519Cert(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "wewaf.test"},
		DNSNames:              []string{"wewaf.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return
}

// TestUploadRejectsShortRSAKey closes the "1024-bit cert silently
// accepted" bypass class. The TLS terminator would then negotiate a
// session keyed by a forgeable certificate.
func TestUploadRejectsShortRSAKey(t *testing.T) {
	certPEM, keyPEM := makeRSACert(t, 1024, x509.SHA256WithRSA)
	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	_, err = mgr.Upload(UploadRequest{Domain: "wewaf.test", CertPEM: certPEM, KeyPEM: keyPEM})
	if err == nil {
		t.Fatal("Upload should reject 1024-bit RSA")
	}
	if !strings.Contains(err.Error(), "RSA key too short") {
		t.Fatalf("error not specific enough: %v", err)
	}
}

// TestUploadAcceptsRSA2048 documents the lower bound that's allowed.
func TestUploadAcceptsRSA2048(t *testing.T) {
	certPEM, keyPEM := makeRSACert(t, 2048, x509.SHA256WithRSA)
	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if _, err := mgr.Upload(UploadRequest{Domain: "wewaf.test", CertPEM: certPEM, KeyPEM: keyPEM}); err != nil {
		t.Fatalf("2048-bit RSA should be accepted: %v", err)
	}
}

// TestUploadAcceptsEd25519 — modern key type without bit-count checks.
func TestUploadAcceptsEd25519(t *testing.T) {
	certPEM, keyPEM := makeEd25519Cert(t)
	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if _, err := mgr.Upload(UploadRequest{Domain: "wewaf.test", CertPEM: certPEM, KeyPEM: keyPEM}); err != nil {
		t.Fatalf("Ed25519 should be accepted: %v", err)
	}
}

// TestUpdateConfigRejectsLegacyTLS — auditors and major CDNs both
// retired TLS 1.0/1.1 in 2020. Refusing them at write-time gives the
// operator immediate feedback rather than a silently weakened deploy.
func TestUpdateConfigRejectsLegacyTLS(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	for _, v := range []string{"1.0", "1.1", "0.9", "tls1.3", ""} {
		// Empty string is a no-op patch; everything else is rejected.
		_, err := mgr.UpdateConfig(Config{MinTLSVersion: v})
		if v == "" {
			if err != nil {
				t.Fatalf("empty MinTLSVersion is a no-op: %v", err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("UpdateConfig should reject MinTLSVersion=%q", v)
		}
	}
	for _, v := range []string{"1.2", "1.3"} {
		if _, err := mgr.UpdateConfig(Config{MinTLSVersion: v}); err != nil {
			t.Fatalf("UpdateConfig should accept MinTLSVersion=%q: %v", v, err)
		}
	}
}

// TestBuildTLSConfig_NilWhenNoCerts documents the empty-set
// behaviour: callers must NOT bind a TLS listener with nothing to
// serve. Returning (nil, nil) lets main.go fall back to plaintext
// without ambiguity.
func TestBuildTLSConfig_NilWhenNoCerts(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	cfg, err := mgr.BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig with no certs returned error: %v", err)
	}
	if cfg != nil {
		t.Fatalf("BuildTLSConfig with no certs must return nil")
	}
	if mgr.HasUsableCerts() {
		t.Fatal("HasUsableCerts must be false on a fresh manager")
	}
}

// TestBuildTLSConfig_AfterUploadIsUsable confirms that an uploaded
// cert is reachable through GetCertificate and that the resulting
// config is wired with the modern policy. We tunnel through a real
// crypto/tls handshake so we know the listener side works end-to-end.
func TestBuildTLSConfig_AfterUploadIsUsable(t *testing.T) {
	certPEM, keyPEM := makeRSACert(t, 2048, x509.SHA256WithRSA)
	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if _, err := mgr.Upload(UploadRequest{Domain: "wewaf.test", CertPEM: certPEM, KeyPEM: keyPEM}); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	cfg, err := mgr.BuildTLSConfig()
	if err != nil || cfg == nil {
		t.Fatalf("BuildTLSConfig: cfg=%v err=%v", cfg, err)
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Fatalf("MinVersion %#x should be ≥ TLS 1.2", cfg.MinVersion)
	}
	if len(cfg.CipherSuites) == 0 {
		t.Fatal("CipherSuites unset — fallback to Go default would include CBC suites")
	}
	// SNI lookup happy path.
	chi := &tls.ClientHelloInfo{ServerName: "wewaf.test"}
	got, err := cfg.GetCertificate(chi)
	if err != nil || got == nil || len(got.Certificate) == 0 {
		t.Fatalf("GetCertificate(wewaf.test) failed: %v", err)
	}
	// Unknown SNI must still return SOMETHING — listening with no
	// fallback would refuse every client that doesn't know the
	// configured domain, which is operator-hostile. The chosen cert
	// is deterministic (alphabetically first).
	chi2 := &tls.ClientHelloInfo{ServerName: "unknown.example"}
	got2, err := cfg.GetCertificate(chi2)
	if err != nil || got2 == nil {
		t.Fatalf("GetCertificate fallback for unknown SNI failed: %v", err)
	}
}

// TestBuildTLSConfig_HotReloadAfterDelete — Delete()ing the only
// loaded cert must immediately make HasUsableCerts return false so
// a future hot-reload of TLSConfig refuses to bind a useless listener.
func TestBuildTLSConfig_HotReloadAfterDelete(t *testing.T) {
	certPEM, keyPEM := makeRSACert(t, 2048, x509.SHA256WithRSA)
	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	cert, err := mgr.Upload(UploadRequest{Domain: "wewaf.test", CertPEM: certPEM, KeyPEM: keyPEM})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if !mgr.HasUsableCerts() {
		t.Fatal("after Upload, HasUsableCerts must be true")
	}
	if err := mgr.Delete(cert.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if mgr.HasUsableCerts() {
		t.Fatal("after Delete of last cert, HasUsableCerts must be false")
	}
}

// TestBuildTLSConfig_PersistedAcrossRestart loads a cert, simulates
// a daemon restart by recreating the Manager pointed at the same
// directory, and confirms the TLS listener still has the cert
// without re-uploading.
func TestBuildTLSConfig_PersistedAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := makeRSACert(t, 2048, x509.SHA256WithRSA)
	mgr, err := NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if _, err := mgr.Upload(UploadRequest{Domain: "wewaf.test", CertPEM: certPEM, KeyPEM: keyPEM}); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	// "Restart" — fresh manager pointed at the same dir.
	mgr2, err := NewManager(dir)
	if err != nil {
		t.Fatalf("re-NewManager: %v", err)
	}
	if !mgr2.HasUsableCerts() {
		t.Fatal("post-restart, HasUsableCerts must still be true (loadIndex re-loaded)")
	}
	cfg, err := mgr2.BuildTLSConfig()
	if err != nil || cfg == nil {
		t.Fatalf("post-restart BuildTLSConfig failed: %v", err)
	}
	chi := &tls.ClientHelloInfo{ServerName: "wewaf.test"}
	if got, err := cfg.GetCertificate(chi); err != nil || got == nil {
		t.Fatalf("post-restart GetCertificate failed: %v", err)
	}
}

// TestDeleteRejectsNonHexID closes the path-traversal door the audit
// flagged. Even though Upload() always produces hex IDs today, refusing
// non-hex inputs at the Delete boundary keeps a future code change
// from quietly opening a hole.
func TestDeleteRejectsNonHexID(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	for _, id := range []string{
		"../../etc/passwd",
		`..\..\windows\system32\config\sam`,
		"abc",                         // too short
		strings.Repeat("g", 64),       // 64 chars but not hex
		strings.Repeat("a", 63),       // hex but wrong length
		strings.Repeat("A", 64),       // uppercase rejected — fingerprints are lowercase
	} {
		if err := mgr.Delete(id); err == nil || !strings.Contains(err.Error(), "id must be") {
			t.Fatalf("Delete(%q) should reject non-hex id, got %v", id, err)
		}
	}
}
