package graphql

import "testing"

// The GraphQL validator parses untrusted JSON request bodies and the embedded
// query string. A parser panic is a denial-of-service, so fuzz it with
// arbitrary bytes and assert it never panics regardless of how malformed the
// JSON / query is.
//
// Run:  go test ./internal/graphql -run x -fuzz FuzzGraphQLValidate -fuzztime 30s
func FuzzGraphQLValidate(f *testing.F) {
	seeds := []string{
		``, `{}`, `{"query":"{a}"}`,
		`{"query":"query{a{b{c{d{e{f{g}}}}}}}"}`,
		`{"query":"{a:x b:x c:x}"}`,
		`{"query":"mutation{deleteUser(id:1)}"}`,
		`{"query":"{__schema{types{name}}}"}`,
		`{"query":"subscription{onX}"}`,
		`{"query":` + "`" + `"unterminated` + "`" + `}`,
		`{"query":"{","variables":{}}`,
		`[{"query":"{a}"},{"query":"{b}"}]`,
		`{"query":"` + "fragment f on T{x} {...f}" + `"}`,
	}
	v, err := New(Config{Enabled: true, MaxDepth: 7, MaxAliases: 10, MaxFields: 200})
	if err != nil {
		f.Fatalf("New: %v", err)
	}
	for _, s := range seeds {
		f.Add([]byte(s), "user")
	}
	f.Fuzz(func(t *testing.T, body []byte, role string) {
		_ = v.Validate(body, role) // contract: never panic
	})
}
