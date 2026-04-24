package core

import (
	"log"
	"runtime/debug"
)

// SafeGo launches fn in a new goroutine with panic recovery. If fn panics,
// the panic value and stack trace are logged and the daemon keeps running
// instead of crashing the whole process.
//
// Use this for every fire-and-forget goroutine in the WAF — the whole
// daemon must survive a single subsystem's bug. The `label` argument is
// prefixed to the log line so operators can tell which goroutine died.
//
// SafeGo does not restart fn on panic. Loops that need to survive internal
// panics should wrap their inner body in a func() {defer recover(); ...}().
func SafeGo(label string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("safego: %s panicked: %v\n%s", label, r, debug.Stack())
			}
		}()
		fn()
	}()
}

// SafeRun is the synchronous counterpart. It executes fn in the current
// goroutine but catches panics so caller loops don't die. Used inside
// retry loops (watchdog, gossip, pollers) where losing the whole loop on
// one bad tick would be worse than losing one iteration.
func SafeRun(label string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("safego: %s iteration panicked: %v\n%s", label, r, debug.Stack())
		}
	}()
	fn()
}
