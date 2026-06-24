package ddos

import "testing"

// TestSensitivePathMatrixParam guards the botnet/distributed-cardinality
// detector against the matrix-parameter evasion: a servlet backend routes
// "/login;jsessionid=x" to /login, so the path must count as sensitive or a
// distributed credential-stuffing flood escapes the distinct-IP check by
// appending a throwaway ";jsessionid=" suffix.
func TestSensitivePathMatrixParam(t *testing.T) {
	d := New(Config{}) // defaults populate BotnetSensitivePaths (/login, /auth, …)

	sensitive := []string{
		"/login",
		"/login;jsessionid=abc", // matrix param — was evading
		"/login/",
		"/admin",
		"/admin;foo=bar",
		"/api/login;jsessionid=x",
	}
	for _, p := range sensitive {
		if !d.isSensitivePath(p) {
			t.Errorf("isSensitivePath(%q) = false, want true", p)
		}
	}

	notSensitive := []string{
		"/loginhistory", // substring, different endpoint
		"/products",
		"/static/login.css",
	}
	for _, p := range notSensitive {
		if d.isSensitivePath(p) {
			t.Errorf("isSensitivePath(%q) = true, want false (false positive)", p)
		}
	}
}
