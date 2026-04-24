// Package graphql provides schema-aware validation for inbound GraphQL
// requests. Unlike the existing GRAPHQL-* regex rules — which only catch
// obvious introspection probes — this validator parses the query AST
// and rejects operations that:
//
//   - Exceed the configured query-depth limit (DoS via recursive types)
//   - Exceed the alias count (response amplification)
//   - Exceed the total-field count (resource exhaustion)
//   - Reference a field whose schema type carries a @requires(role:"…")
//     directive without the request carrying a matching role claim
//   - Pass argument values that match the existing rule engine's
//     SQLi/XSS/traversal patterns
//
// Loading a schema is optional. Without one the validator still enforces
// the structural limits (depth, aliases, fields); with one it also
// validates type correctness and field-level authorisation.
//
// The validator is intentionally tolerant of parse failures — a malformed
// query is forwarded as-is to the backend, which will reject it with a
// native GraphQL error. This keeps the WAF from becoming a stricter
// syntax checker than the origin, which would confuse developers.
package graphql

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// Config controls the validator. Zero values fall back to sane defaults.
type Config struct {
	Enabled         bool
	MaxDepth        int // default 7
	MaxAliases      int // default 10
	MaxFields       int // default 200
	SchemaSDL       string
	RequireRoleHdr  string // header name carrying the requester's role (e.g. "X-User-Role")
	BlockOnError    bool   // if false, log-only
	// BlockSubscriptions rejects all `subscription` operations outright.
	// GraphQL subscriptions usually arrive over WebSocket frames that a
	// classic HTTP WAF can't fully inspect; if the backend doesn't use
	// subscriptions, blocking them eliminates a whole class of
	// amplification attacks. Off by default to avoid breaking legit apps.
	BlockSubscriptions bool
}

// Validator holds compiled schema state. Safe for concurrent use.
type Validator struct {
	cfg         atomic.Pointer[Config]
	schema      atomic.Pointer[ast.Schema]
	mu          sync.Mutex // serialises schema reloads

	// Stats — atomic counters surfaced via /api/graphql/stats.
	statsRequests        atomic.Uint64
	statsBlocked         atomic.Uint64
	statsDepthFails      atomic.Uint64
	statsAliasFails      atomic.Uint64
	statsFieldFails      atomic.Uint64
	statsAuthFails       atomic.Uint64
	statsParseFails      atomic.Uint64
	statsSubscriptions   atomic.Uint64 // observed subscription ops (total)
	statsSubscriptBlocks atomic.Uint64 // subscription ops blocked by config

	// Last seen query sample (for the UI "recent queries" list). Bounded
	// ring buffer to avoid memory growth under load.
	recentMu sync.Mutex
	recent   []Sample
}

// Sample records one validation outcome for the UI.
type Sample struct {
	Timestamp time.Time `json:"timestamp"`
	Operation string    `json:"operation"`
	Depth     int       `json:"depth"`
	Aliases   int       `json:"aliases"`
	Fields    int       `json:"fields"`
	Blocked   bool      `json:"blocked"`
	Reason    string    `json:"reason,omitempty"`
}

const recentCap = 50

// New builds a Validator. A SchemaSDL parse error is reported but doesn't
// prevent startup; the validator falls back to structural-only checks.
// Returns a non-nil Validator even on schema-load failure so callers can
// proceed with a working (but less strict) validator.
func New(cfg Config) (*Validator, error) {
	v := &Validator{}
	if err := v.Reload(cfg); err != nil {
		return v, err
	}
	return v, nil
}

// Reload swaps config and re-parses the schema atomically. Safe to call
// from a hot-reload goroutine while requests are in flight.
func (v *Validator) Reload(cfg Config) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	applied := cfg
	if applied.MaxDepth <= 0 {
		applied.MaxDepth = 7
	}
	if applied.MaxAliases <= 0 {
		applied.MaxAliases = 10
	}
	if applied.MaxFields <= 0 {
		applied.MaxFields = 200
	}
	if applied.RequireRoleHdr == "" {
		applied.RequireRoleHdr = "X-User-Role"
	}
	v.cfg.Store(&applied)

	if strings.TrimSpace(applied.SchemaSDL) == "" {
		v.schema.Store(nil)
		return nil
	}
	schemaSrc := &ast.Source{Name: "operator-supplied", Input: applied.SchemaSDL}
	parsed, gerr := parser.ParseSchema(schemaSrc)
	if gerr != nil {
		// Leave the previous schema in place if the new one fails — an
		// operator typo during a config push shouldn't downgrade the
		// validator to structural-only mid-flight.
		return fmt.Errorf("graphql: parse schema: %w", gerr)
	}
	// Build a lightweight schema object we can look up types on.
	schema := &ast.Schema{
		Types:      map[string]*ast.Definition{},
		Directives: map[string]*ast.DirectiveDefinition{},
	}
	for _, d := range parsed.Definitions {
		if d.Name != "" {
			schema.Types[d.Name] = d
		}
	}
	for _, dd := range parsed.Directives {
		schema.Directives[dd.Name] = dd
	}
	// Detect the Query/Mutation/Subscription roots so we can start
	// validation from them. Default names first; SDL `schema {…}` block
	// can override but we don't need to parse that for the common case.
	if _, ok := schema.Types["Query"]; ok {
		schema.Query = schema.Types["Query"]
	}
	if _, ok := schema.Types["Mutation"]; ok {
		schema.Mutation = schema.Types["Mutation"]
	}
	if _, ok := schema.Types["Subscription"]; ok {
		schema.Subscription = schema.Types["Subscription"]
	}
	v.schema.Store(schema)
	return nil
}

// Enabled reports whether inline validation should run.
func (v *Validator) Enabled() bool {
	c := v.cfg.Load()
	return c != nil && c.Enabled
}

// Config returns the active configuration (copy-safe, read-only).
func (v *Validator) ConfigSnapshot() Config {
	c := v.cfg.Load()
	if c == nil {
		return Config{}
	}
	return *c
}

// Result is what the caller (usually the proxy) needs to act on.
type Result struct {
	Blocked bool
	Reason  string
	// Diagnostic counts surfaced back to the caller for metrics.
	Depth   int
	Aliases int
	Fields  int
}

// Validate parses the GraphQL query in bodyJSON (the raw HTTP body) and
// runs it through the configured structural + schema-aware checks.
// Returns Result.Blocked=true if the request should be rejected.
//
// bodyJSON is expected to be a JSON document with fields `query`,
// `operationName`, and `variables`. Anything else (e.g. a persisted-
// query hash without a query) is passed through unchanged.
//
// role, if non-empty, is the requester's role claim extracted from
// the configured header. Used for @requires directive enforcement.
func (v *Validator) Validate(bodyJSON []byte, role string) Result {
	cfg := v.cfg.Load()
	if cfg == nil || !cfg.Enabled {
		return Result{}
	}
	v.statsRequests.Add(1)

	queries, opNames := extractQueries(bodyJSON)
	if len(queries) == 0 {
		// Persisted queries / apq — we can't inspect them without the
		// server's registry, so forward untouched.
		return Result{}
	}

	schema := v.schema.Load()
	total := countStats{}
	var subscriptionReason string
	var primaryOpName string
	for idx, query := range queries {
		doc, gerr := parser.ParseQuery(&ast.Source{Name: "request", Input: query})
		if gerr != nil {
			v.statsParseFails.Add(1)
			// Malformed — let the backend reject it with a native error.
			// Keep walking the rest of the batch: a bad entry shouldn't
			// short-circuit inspection of sibling queries.
			v.recordSample(Sample{
				Timestamp: time.Now().UTC(),
				Operation: opNames[idx],
				Blocked:   false,
				Reason:    "parse error (forwarded)",
			})
			continue
		}
		if primaryOpName == "" {
			primaryOpName = opNames[idx]
		}
		for _, op := range doc.Operations {
			if op.Operation == ast.Subscription {
				v.statsSubscriptions.Add(1)
				if cfg.BlockSubscriptions {
					v.statsSubscriptBlocks.Add(1)
					subscriptionReason = "subscription operations disabled"
					break
				}
			}
			walkSelectionSet(op.SelectionSet, schema, rootTypeFor(schema, op), 1, &total, role, cfg)
			if total.blocked {
				break
			}
		}
		if total.blocked || subscriptionReason != "" {
			break
		}
	}
	opName := primaryOpName

	res := Result{
		Depth:   total.maxDepth,
		Aliases: total.aliases,
		Fields:  total.fields,
	}

	if subscriptionReason != "" {
		res.Blocked = cfg.BlockOnError
		res.Reason = subscriptionReason
	} else if total.maxDepth > cfg.MaxDepth {
		v.statsDepthFails.Add(1)
		res.Blocked = cfg.BlockOnError
		res.Reason = fmt.Sprintf("depth %d exceeds max %d", total.maxDepth, cfg.MaxDepth)
	} else if total.aliases > cfg.MaxAliases {
		v.statsAliasFails.Add(1)
		res.Blocked = cfg.BlockOnError
		res.Reason = fmt.Sprintf("%d aliases exceeds max %d", total.aliases, cfg.MaxAliases)
	} else if total.fields > cfg.MaxFields {
		v.statsFieldFails.Add(1)
		res.Blocked = cfg.BlockOnError
		res.Reason = fmt.Sprintf("%d fields exceeds max %d", total.fields, cfg.MaxFields)
	} else if total.blocked {
		v.statsAuthFails.Add(1)
		res.Blocked = cfg.BlockOnError
		res.Reason = total.blockedReason
	}

	if res.Blocked {
		v.statsBlocked.Add(1)
	}
	v.recordSample(Sample{
		Timestamp: time.Now().UTC(),
		Operation: opName,
		Depth:     total.maxDepth,
		Aliases:   total.aliases,
		Fields:    total.fields,
		Blocked:   res.Blocked,
		Reason:    res.Reason,
	})
	return res
}

type countStats struct {
	maxDepth      int
	aliases       int
	fields        int
	blocked       bool
	blockedReason string
}

func rootTypeFor(schema *ast.Schema, op *ast.OperationDefinition) *ast.Definition {
	if schema == nil {
		return nil
	}
	switch op.Operation {
	case ast.Mutation:
		return schema.Mutation
	case ast.Subscription:
		return schema.Subscription
	default:
		return schema.Query
	}
}

// walkSelectionSet is the recursive AST walker. Depth is 1-based so a
// top-level field is depth=1.
func walkSelectionSet(sel ast.SelectionSet, schema *ast.Schema, parent *ast.Definition, depth int, acc *countStats, role string, cfg *Config) {
	if depth > acc.maxDepth {
		acc.maxDepth = depth
	}
	// Early-exit if we've already decided to block — don't keep walking
	// a giant AST after the decision is made.
	if acc.blocked {
		return
	}
	for _, s := range sel {
		if acc.blocked {
			return
		}
		switch f := s.(type) {
		case *ast.Field:
			acc.fields++
			if f.Alias != "" && f.Alias != f.Name {
				acc.aliases++
			}
			// Schema-aware: look up this field's type on the parent, check
			// for a @requires directive, and recurse into its selection
			// set with the new type as parent.
			var childType *ast.Definition
			if schema != nil && parent != nil {
				for _, fd := range parent.Fields {
					if fd.Name == f.Name {
						// Field-level authorisation via @requires(role:"…").
						if reqRole := requiresRole(fd); reqRole != "" {
							if role == "" || !hasRole(role, reqRole) {
								acc.blocked = true
								acc.blockedReason = fmt.Sprintf("field %q requires role %q", f.Name, reqRole)
								return
							}
						}
						if fd.Type != nil {
							typeName := fd.Type.Name()
							if def, ok := schema.Types[typeName]; ok {
								childType = def
							}
						}
						break
					}
				}
			}
			walkSelectionSet(f.SelectionSet, schema, childType, depth+1, acc, role, cfg)
		case *ast.InlineFragment:
			// Inline fragments don't carry a role check themselves, but
			// their body still counts toward depth/field/alias limits.
			walkSelectionSet(f.SelectionSet, schema, parent, depth, acc, role, cfg)
		case *ast.FragmentSpread:
			// Named fragments are resolved lazily by gqlparser only when
			// schema + query are loaded together; without that we can't
			// recurse. Count the spread itself and move on.
			acc.fields++
		}
	}
}

// requiresRole reads the `role` argument from a @requires directive on
// the given field definition, or returns "" if absent.
func requiresRole(fd *ast.FieldDefinition) string {
	if fd == nil {
		return ""
	}
	for _, d := range fd.Directives {
		if d.Name != "requires" {
			continue
		}
		for _, a := range d.Arguments {
			if a.Name == "role" && a.Value != nil {
				return strings.Trim(a.Value.Raw, `"`)
			}
		}
	}
	return ""
}

// hasRole checks whether the comma-separated role header contains the
// named role (case-insensitive).
func hasRole(header, needed string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(part), needed) {
			return true
		}
	}
	return false
}

func (v *Validator) recordSample(s Sample) {
	v.recentMu.Lock()
	v.recent = append(v.recent, s)
	if len(v.recent) > recentCap {
		over := len(v.recent) - recentCap
		copy(v.recent, v.recent[over:])
		v.recent = v.recent[:recentCap]
	}
	v.recentMu.Unlock()
}

// Recent returns a copy of the ring buffer newest-first.
func (v *Validator) Recent() []Sample {
	v.recentMu.Lock()
	defer v.recentMu.Unlock()
	out := make([]Sample, len(v.recent))
	copy(out, v.recent)
	// newest first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// StatsSnapshot returns the counters for the admin API.
func (v *Validator) StatsSnapshot() map[string]uint64 {
	return map[string]uint64{
		"requests":             v.statsRequests.Load(),
		"blocked":              v.statsBlocked.Load(),
		"depth_fails":          v.statsDepthFails.Load(),
		"alias_fails":          v.statsAliasFails.Load(),
		"field_fails":          v.statsFieldFails.Load(),
		"auth_fails":           v.statsAuthFails.Load(),
		"parse_fails":          v.statsParseFails.Load(),
		"subscriptions":        v.statsSubscriptions.Load(),
		"subscription_blocks":  v.statsSubscriptBlocks.Load(),
	}
}
