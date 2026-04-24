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

// extractQuery returns the first query in the body. Kept for callers that
// only need one; most production paths should use extractQueries so batch
// requests are inspected in full rather than waved through after the first.
func extractQuery(body []byte) (query, opName string) {
	qs, ops := extractQueries(body)
	if len(qs) == 0 {
		return "", ""
	}
	return qs[0], ops[0]
}

// extractQueries pulls every query + operationName from a POST body.
// Supports:
//   - standard JSON body: {"query":"…", "operationName":"…"}
//   - raw application/graphql body: a query string directly
//   - batch form: [{"query":"…"}, {"query":"…"}, …]
//
// Returning a slice matters for security: when an attacker batches a
// malicious query behind a benign one, an "inspect the first entry only"
// shortcut leaves every other query uninspected. Callers should walk the
// returned slice and validate each query independently.
//
// Bounded: bodies over 1 MiB are refused, and the batch is capped at
// 32 operations so a malformed "[{…},{…},…]" can't explode validator
// work. max_body_bytes in the proxy should catch most of these upstream
// anyway; this is defence in depth.
func extractQueries(body []byte) (queries []string, opNames []string) {
	if len(body) == 0 || len(body) > 1<<20 {
		return nil, nil
	}
	// Raw graphql body — starts with one of the operation keywords.
	trimmed := strings.TrimLeftFunc(string(body), func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\t' || r == '\r'
	})
	if len(trimmed) > 0 && trimmed[0] != '{' && trimmed[0] != '[' {
		return []string{trimmed}, []string{""}
	}

	var payload struct {
		Query         string `json:"query"`
		OperationName string `json:"operationName"`
	}
	if err := json.Unmarshal(body, &payload); err == nil && payload.Query != "" {
		return []string{payload.Query}, []string{payload.OperationName}
	}

	// Try array form (GraphQL batching).
	var batch []struct {
		Query         string `json:"query"`
		OperationName string `json:"operationName"`
	}
	if err := json.Unmarshal(body, &batch); err == nil && len(batch) > 0 {
		const maxBatch = 32
		if len(batch) > maxBatch {
			batch = batch[:maxBatch]
		}
		queries = make([]string, 0, len(batch))
		opNames = make([]string, 0, len(batch))
		for _, b := range batch {
			if b.Query == "" {
				continue
			}
			queries = append(queries, b.Query)
			opNames = append(opNames, b.OperationName)
		}
		return queries, opNames
	}
	return nil, nil
}
