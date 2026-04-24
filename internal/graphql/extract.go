package graphql

import (
	"encoding/json"
	"net/http"
	"strings"
)

// IsGraphQLRequest returns true if the request looks like a GraphQL
// operation. We match on path suffix + content-type rather than any
// single signal because deployments vary:
//   - POST /graphql with application/json body is the GA spec
//   - GET /graphql?query=... is valid too
//   - /graphql/v1 and /query are common alternates
func IsGraphQLRequest(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	path := strings.ToLower(r.URL.Path)
	if !(strings.HasSuffix(path, "/graphql") ||
		strings.HasSuffix(path, "/graphql/") ||
		strings.Contains(path, "/graphql/v") ||
		strings.HasSuffix(path, "/query")) {
		return false
	}
	if r.Method == http.MethodGet {
		return r.URL.Query().Get("query") != ""
	}
	if r.Method == http.MethodPost {
		ct := strings.ToLower(r.Header.Get("Content-Type"))
		return strings.Contains(ct, "application/json") ||
			strings.Contains(ct, "application/graphql")
	}
	return false
}

// extractQuery pulls the GraphQL query string + operation name from a
// POST body. Accepts both the standard JSON body ({"query":"…"}) and
// the raw application/graphql body (query string directly). Returns
// empty strings on parse failure — callers treat that as "not inspectable".
//
// Bounded: we refuse to parse bodies over 1 MiB. Anything bigger either
// isn't a real query or is a deliberate DoS; the existing max_body_bytes
// check in the proxy should already have caught it.
func extractQuery(body []byte) (query, opName string) {
	if len(body) == 0 || len(body) > 1<<20 {
		return "", ""
	}
	// Raw graphql body — starts with one of the operation keywords.
	trimmed := strings.TrimLeftFunc(string(body), func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\t' || r == '\r'
	})
	if len(trimmed) > 0 && trimmed[0] != '{' && trimmed[0] != '[' {
		return trimmed, ""
	}

	var payload struct {
		Query         string `json:"query"`
		OperationName string `json:"operationName"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		// Try array form (GraphQL batching).
		var batch []struct {
			Query         string `json:"query"`
			OperationName string `json:"operationName"`
		}
		if err2 := json.Unmarshal(body, &batch); err2 == nil && len(batch) > 0 {
			return batch[0].Query, batch[0].OperationName
		}
		return "", ""
	}
	return payload.Query, payload.OperationName
}
