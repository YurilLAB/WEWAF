// Command wafctl is a thin, scriptable CLI over the WEWAF daemon's admin API
// (the :8443 JSON API behind X-API-Key). It lets an operator automate WEWAF
// from a shell or another program without touching ypanel — status, config
// get/set, and ban management — reusing the exact same authenticated endpoints
// the agent and ypanel drive.
//
// It is a pure client: it adds NO new daemon attack surface. The admin key is
// read from the environment (WAF_API_KEY) or --key and sent only as the
// X-API-Key header, never logged.
//
//	wafctl [--addr URL] [--key KEY] [--json] [--timeout D] <command> [args]
//
// Commands:
//
//	status                          daemon health snapshot
//	bans                            list active bans
//	ban [--reason R] [--for D] <ip> add a ban (D is a Go duration, 0 = permanent)
//	unban <ip>                      remove a ban
//	config get [field]              print config (all, or one field)
//	config set <field> <value>      set one config field (value parsed as JSON, else string)
//	rules                           list active rules
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("wafctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", env("WAF_ADMIN_ADDR", "http://127.0.0.1:8443"), "admin API base URL")
	key := fs.String("key", os.Getenv("WAF_API_KEY"), "admin API key (X-API-Key); defaults to $WAF_API_KEY")
	jsonOut := fs.Bool("json", false, "emit raw JSON instead of pretty output")
	timeout := fs.Duration("timeout", 10*time.Second, "request timeout")
	fs.Usage = func() { usage(stderr) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		usage(stderr)
		return 2
	}

	c := &client{
		base: strings.TrimRight(*addr, "/"),
		key:  *key,
		hc:   &http.Client{Timeout: *timeout},
	}
	cmd, cmdArgs := rest[0], rest[1:]

	switch cmd {
	case "status":
		return c.get(stdout, stderr, "/api/health", *jsonOut)
	case "bans":
		return c.get(stdout, stderr, "/api/bans", *jsonOut)
	case "rules":
		return c.get(stdout, stderr, "/api/rules", *jsonOut)
	case "ban":
		return c.ban(cmdArgs, stdout, stderr)
	case "unban":
		return c.unban(cmdArgs, stdout, stderr)
	case "config":
		return c.config(cmdArgs, stdout, stderr, *jsonOut)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "wafctl: unknown command %q\n", cmd)
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `wafctl — control the WEWAF daemon over its admin API.

Usage:
  wafctl [--addr URL] [--key KEY] [--json] [--timeout D] <command> [args]

Global flags (must precede the command):
  --addr URL     admin API base URL (env WAF_ADMIN_ADDR, default http://127.0.0.1:8443)
  --key KEY      admin API key sent as X-API-Key (env WAF_API_KEY)
  --json         emit raw JSON
  --timeout D    request timeout (default 10s)

Commands:
  status                            daemon health snapshot
  bans                              list active bans
  ban [--reason R] [--for D] <ip>   add a ban (D is a Go duration like 1h; 0 = permanent)
  unban <ip>                        remove a ban
  config get [field]                print config (all, or a single field)
  config set <field> <value>        set one config field
  rules                             list active rules

Examples:
  wafctl status
  wafctl ban --reason "scanner" --for 24h 203.0.113.7
  wafctl config set mode active
  wafctl config set shaper_enabled true
`)
}

type client struct {
	base string
	key  string
	hc   *http.Client
}

// do performs an admin-API request. body, if non-nil, is JSON-encoded.
func (c *client) do(method, path string, body any) ([]byte, int, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	if c.key != "" {
		req.Header.Set("X-API-Key", c.key)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return data, resp.StatusCode, nil
}

// get fetches path and prints it (pretty by default, raw with --json). Returns
// the process exit code.
func (c *client) get(stdout, stderr io.Writer, path string, raw bool) int {
	data, status, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		fmt.Fprintf(stderr, "wafctl: %v\n", err)
		return 1
	}
	if status != http.StatusOK {
		fmt.Fprintf(stderr, "wafctl: %s -> HTTP %d: %s\n", path, status, strings.TrimSpace(string(data)))
		return 1
	}
	printBody(stdout, data, raw)
	return 0
}

func (c *client) ban(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ban", flag.ContinueOnError)
	fs.SetOutput(stderr)
	reason := fs.String("reason", "manual", "ban reason")
	dur := fs.Duration("for", 0, "ban duration (Go duration; 0 = permanent)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: wafctl ban <ip> [--reason R] [--for D]")
		return 2
	}
	ip := fs.Arg(0)
	payload := map[string]any{
		"ip":           ip,
		"reason":       *reason,
		"duration_sec": int((*dur).Seconds()),
	}
	data, status, err := c.do(http.MethodPost, "/api/bans", payload)
	if err != nil {
		fmt.Fprintf(stderr, "wafctl: %v\n", err)
		return 1
	}
	if status != http.StatusOK {
		fmt.Fprintf(stderr, "wafctl: ban %s -> HTTP %d: %s\n", ip, status, strings.TrimSpace(string(data)))
		return 1
	}
	fmt.Fprintf(stdout, "banned %s (%s)\n", ip, *reason)
	return 0
}

func (c *client) unban(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: wafctl unban <ip>")
		return 2
	}
	ip := args[0]
	data, status, err := c.do(http.MethodDelete, "/api/bans?ip="+ip, nil)
	if err != nil {
		fmt.Fprintf(stderr, "wafctl: %v\n", err)
		return 1
	}
	if status != http.StatusOK {
		fmt.Fprintf(stderr, "wafctl: unban %s -> HTTP %d: %s\n", ip, status, strings.TrimSpace(string(data)))
		return 1
	}
	fmt.Fprintf(stdout, "unbanned %s\n", ip)
	return 0
}

func (c *client) config(args []string, stdout, stderr io.Writer, raw bool) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: wafctl config get [field] | wafctl config set <field> <value>")
		return 2
	}
	switch args[0] {
	case "get":
		data, status, err := c.do(http.MethodGet, "/api/config", nil)
		if err != nil {
			fmt.Fprintf(stderr, "wafctl: %v\n", err)
			return 1
		}
		if status != http.StatusOK {
			fmt.Fprintf(stderr, "wafctl: config get -> HTTP %d: %s\n", status, strings.TrimSpace(string(data)))
			return 1
		}
		if len(args) >= 2 { // single field
			var m map[string]json.RawMessage
			if err := json.Unmarshal(data, &m); err != nil {
				fmt.Fprintf(stderr, "wafctl: %v\n", err)
				return 1
			}
			v, ok := m[args[1]]
			if !ok {
				fmt.Fprintf(stderr, "wafctl: no such config field %q\n", args[1])
				return 1
			}
			printBody(stdout, v, raw)
			return 0
		}
		printBody(stdout, data, raw)
		return 0
	case "set":
		if len(args) != 3 {
			fmt.Fprintln(stderr, "usage: wafctl config set <field> <value>")
			return 2
		}
		field, value := args[1], args[2]
		// POST /api/config is a MERGE: a single field is applied and the rest
		// of the running config is left untouched (nullable / zero-value-means-
		// unchanged semantics on the node).
		payload := map[string]any{field: parseConfigValue(value)}
		data, status, err := c.do(http.MethodPost, "/api/config", payload)
		if err != nil {
			fmt.Fprintf(stderr, "wafctl: %v\n", err)
			return 1
		}
		if status != http.StatusOK {
			fmt.Fprintf(stderr, "wafctl: config set -> HTTP %d: %s\n", status, strings.TrimSpace(string(data)))
			return 1
		}
		fmt.Fprintf(stdout, "set %s = %s\n", field, value)
		return 0
	default:
		fmt.Fprintf(stderr, "wafctl: unknown config subcommand %q (want get|set)\n", args[0])
		return 2
	}
}

// parseConfigValue turns a CLI string into the JSON-typed value the admin API
// expects: booleans and integers are typed (so *bool / int config fields apply
// correctly), explicit JSON (arrays, quoted strings) is honored, and anything
// else is sent as a bare string.
func parseConfigValue(s string) any {
	switch s {
	case "true":
		return true
	case "false":
		return false
	}
	if i, err := strconv.Atoi(s); err == nil {
		return i
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err == nil {
		return v
	}
	return s
}

// printBody pretty-prints JSON unless raw is requested or the body isn't JSON.
func printBody(w io.Writer, data []byte, raw bool) {
	if raw {
		fmt.Fprintln(w, strings.TrimSpace(string(data)))
		return
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		fmt.Fprintln(w, strings.TrimSpace(string(data)))
		return
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}
