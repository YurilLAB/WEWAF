package proxy

// Priority load-shedding. When the node is under measured load, shed the MOST
// suspicious sessions first so capacity is preserved for low-risk (likely
// legitimate) users — rather than the static concurrency cap dropping requests
// arbitrarily once it's hit. Opt-in and fail-open: below the load floor nothing
// is shed, so a healthy node behaves exactly as before.

// loadShedFloor is the load below which nothing is ever shed (fail-open).
const loadShedFloor = 0.5

// loadShedThreshold returns the session-risk score at/above which a request is
// shed at the given load (0..1). Below loadShedFloor it returns 101 (> any real
// score) so nothing is shed; from the floor to full load it ramps the threshold
// DOWN from 100 to minScore, so heavier load sheds progressively less-suspicious
// sessions. Monotonic in load: higher load yields a lower-or-equal threshold.
func loadShedThreshold(load float64, minScore int) int {
	if load < loadShedFloor {
		return 101
	}
	if minScore < 1 {
		minScore = 1
	}
	if minScore > 100 {
		minScore = 100
	}
	if load > 1 {
		load = 1
	}
	frac := (load - loadShedFloor) / (1 - loadShedFloor) // 0..1 across the active range
	th := 100.0 - frac*float64(100-minScore)
	return int(th + 0.5)
}

// shouldShedForLoad reports whether a request with the given session risk score
// should be shed at the current load. Higher score and higher load both make
// shedding more likely; at/below the load floor nothing is shed.
func shouldShedForLoad(score int, load float64, minScore int) bool {
	if load < loadShedFloor {
		return false
	}
	return score >= loadShedThreshold(load, minScore)
}

// loadFraction returns a 0..1 estimate of this node's load for priority
// shedding: how far the adaptive limiter has constrained admission, floored to
// "high" whenever the DDoS detector has confirmed an attack (a confirmed attack
// is high load regardless of the limiter's current view).
func (wp *WAFProxy) loadFraction() float64 {
	if wp == nil {
		return 0
	}
	load := 0.0
	if wp.adaptive != nil {
		load = wp.adaptive.LoadFraction()
	}
	if wp.ddos != nil && wp.ddos.IsUnderAttack() && load < 0.85 {
		load = 0.85
	}
	return load
}
