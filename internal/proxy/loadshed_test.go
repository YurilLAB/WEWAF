package proxy

import "testing"

func TestLoadShedFailOpenBelowFloor(t *testing.T) {
	for _, load := range []float64{0, 0.1, 0.49} {
		for _, score := range []int{0, 50, 100} {
			if shouldShedForLoad(score, load, 50) {
				t.Fatalf("must not shed below the load floor: load=%.2f score=%d", load, score)
			}
		}
	}
}

func TestLoadShedAtFullLoad(t *testing.T) {
	// At full load the threshold equals minScore: shed >= minScore, keep below.
	if !shouldShedForLoad(50, 1.0, 50) {
		t.Fatal("at full load a score==minScore session should be shed")
	}
	if shouldShedForLoad(49, 1.0, 50) {
		t.Fatal("at full load a score below minScore must be kept")
	}
	// A low-risk user is preserved even at full load.
	if shouldShedForLoad(10, 1.0, 50) {
		t.Fatal("low-risk session must be preserved even at full load")
	}
}

func TestLoadShedThresholdRampsDown(t *testing.T) {
	// As load rises from the floor to 1.0, the threshold must be non-increasing
	// and bounded in [minScore,100].
	minScore := 40
	prev := 101
	for l := loadShedFloor; l <= 1.0001; l += 0.05 {
		th := loadShedThreshold(l, minScore)
		if th > prev {
			t.Fatalf("threshold must not rise as load rises: load=%.2f th=%d prev=%d", l, th, prev)
		}
		if l <= 1.0 && (th < minScore || th > 100) {
			t.Fatalf("threshold out of bounds: load=%.2f th=%d", l, th)
		}
		prev = th
	}
}

// FuzzShouldShedForLoad asserts the policy never panics and is monotonic:
// raising the score or the load can only make shedding more (or equally) likely,
// and nothing is ever shed below the load floor.
func FuzzShouldShedForLoad(f *testing.F) {
	f.Add(50, 0.7, 50)
	f.Add(0, 0.0, 1)
	f.Add(100, 1.0, 100)
	f.Add(-5, -1.0, 0)
	f.Add(999, 9.9, 250)
	f.Fuzz(func(t *testing.T, score int, load float64, minScore int) {
		shed := shouldShedForLoad(score, load, minScore)
		// Fail-open invariant.
		if load < loadShedFloor && shed {
			t.Fatalf("shed below floor: score=%d load=%.3f min=%d", score, load, minScore)
		}
		// Monotonic in score: if shed at score, also shed at score+1.
		if shed && !shouldShedForLoad(score+1, load, minScore) {
			t.Fatalf("not monotonic in score: shed@%d but not @%d (load=%.3f min=%d)", score, score+1, load, minScore)
		}
		// Monotonic in load: if shed at this load, also shed at a higher load.
		if shed && load < 1.0 {
			if !shouldShedForLoad(score, load+0.1, minScore) {
				t.Fatalf("not monotonic in load: shed@%.3f but not @%.3f (score=%d min=%d)", load, load+0.1, score, minScore)
			}
		}
	})
}
