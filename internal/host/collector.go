// Package host collects runtime and system telemetry for the admin dashboard.
// It uses gopsutil for cross-platform CPU/memory/disk/network metrics and
// falls back to Go runtime data when platform-specific calls fail.
package host

import (
	"context"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
)

// NetIOSnapshot is the point-in-time network counter snapshot the UI consumes.
type NetIOSnapshot struct {
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`
	PacketsSent uint64 `json:"packets_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
}

// Resources is what /api/host/resources returns.
type Resources struct {
	TotalCPUCores       int           `json:"total_cpu_cores"`
	TotalMemoryMB       uint64        `json:"total_memory_mb"`
	TotalDiskGB         uint64        `json:"total_disk_gb"`
	AllocatedCPUCores   int           `json:"allocated_cpu_cores"`
	AllocatedMemoryMB   uint64        `json:"allocated_memory_mb"`
	AllocatedDiskGB     uint64        `json:"allocated_disk_gb"`
	CPUUsagePercent     float64       `json:"cpu_usage_percent"`
	MemoryUsagePercent  float64       `json:"memory_usage_percent"`
	DiskUsagePercent    float64       `json:"disk_usage_percent"`
	LoadAverage         [3]float64    `json:"load_average"`
	NetworkIO           NetIOSnapshot `json:"network_io"`
	BandwidthInBps      uint64        `json:"bandwidth_in_bps"`
	BandwidthOutBps     uint64        `json:"bandwidth_out_bps"`
}

// Stats is what /api/host/stats returns.
type Stats struct {
	Online        bool   `json:"online"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	Hostname      string `json:"hostname"`
	Platform      string `json:"platform"`
	Architecture  string `json:"architecture"`
	GoVersion     string `json:"go_version"`
	WAFVersion    string `json:"waf_version"`
}

// Collector samples system metrics on a fixed interval.
type Collector struct {
	wafVersion string
	startTime  time.Time

	interval time.Duration
	stopOnce sync.Once
	stopCh   chan struct{}

	mu        sync.RWMutex
	resources Resources
	stats     Stats

	lastNetSampleAt atomic.Int64 // unix nano
	lastBytesSent   atomic.Uint64
	lastBytesRecv   atomic.Uint64
}

// NewCollector builds a collector. wafVersion is embedded in /api/host/stats.
func NewCollector(wafVersion string) *Collector {
	hostname, _ := os.Hostname()
	totalCPU := runtime.NumCPU()

	c := &Collector{
		wafVersion: wafVersion,
		startTime:  time.Now().UTC(),
		interval:   5 * time.Second,
		stopCh:     make(chan struct{}),
	}
	c.stats = Stats{
		Online:       true,
		Hostname:     hostname,
		Platform:     runtime.GOOS,
		Architecture: runtime.GOARCH,
		GoVersion:    runtime.Version(),
		WAFVersion:   wafVersion,
	}
	c.resources = Resources{
		TotalCPUCores:     totalCPU,
		AllocatedCPUCores: runtime.GOMAXPROCS(0),
	}
	return c
}

// Start launches the background sampling loop. Safe to call once.
func (c *Collector) Start(ctx context.Context) {
	// Prime with one synchronous sample so the first API call has data.
	c.sample(ctx)
	go c.loop(ctx)
}

// Stop halts the background loop.
func (c *Collector) Stop() {
	c.stopOnce.Do(func() { close(c.stopCh) })
}

func (c *Collector) loop(ctx context.Context) {
	defer func() {
		// Panics in gopsutil should not crash the daemon.
		_ = recover()
	}()
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.sample(ctx)
		}
	}
}

func (c *Collector) sample(ctx context.Context) {
	defer func() { _ = recover() }()

	cpuPct := 0.0
	if vals, err := cpu.PercentWithContext(ctx, 0, false); err == nil && len(vals) > 0 {
		cpuPct = vals[0]
	}

	var memPct float64
	var totalMemMB, allocMemMB uint64
	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		memPct = vm.UsedPercent
		totalMemMB = vm.Total / (1024 * 1024)
		allocMemMB = vm.Used / (1024 * 1024)
	}

	var diskPct float64
	var totalDiskGB, allocDiskGB uint64
	if u, err := disk.UsageWithContext(ctx, defaultDiskPath()); err == nil {
		diskPct = u.UsedPercent
		totalDiskGB = u.Total / (1024 * 1024 * 1024)
		allocDiskGB = u.Used / (1024 * 1024 * 1024)
	}

	var la [3]float64
	if avg, err := load.AvgWithContext(ctx); err == nil {
		la = [3]float64{avg.Load1, avg.Load5, avg.Load15}
	}

	var netSnap NetIOSnapshot
	var inBps, outBps uint64
	if nio, err := net.IOCountersWithContext(ctx, false); err == nil && len(nio) > 0 {
		n := nio[0]
		netSnap = NetIOSnapshot{
			BytesSent:   n.BytesSent,
			BytesRecv:   n.BytesRecv,
			PacketsSent: n.PacketsSent,
			PacketsRecv: n.PacketsRecv,
		}
		now := time.Now().UnixNano()
		prev := c.lastNetSampleAt.Load()
		prevSent := c.lastBytesSent.Load()
		prevRecv := c.lastBytesRecv.Load()
		if prev > 0 {
			elapsed := float64(now-prev) / float64(time.Second)
			if elapsed > 0 {
				if n.BytesSent > prevSent {
					outBps = uint64(float64(n.BytesSent-prevSent) / elapsed)
				}
				if n.BytesRecv > prevRecv {
					inBps = uint64(float64(n.BytesRecv-prevRecv) / elapsed)
				}
			}
		}
		c.lastNetSampleAt.Store(now)
		c.lastBytesSent.Store(n.BytesSent)
		c.lastBytesRecv.Store(n.BytesRecv)
	}

	c.mu.Lock()
	c.resources.CPUUsagePercent = cpuPct
	c.resources.MemoryUsagePercent = memPct
	c.resources.DiskUsagePercent = diskPct
	if totalMemMB > 0 {
		c.resources.TotalMemoryMB = totalMemMB
		c.resources.AllocatedMemoryMB = allocMemMB
	}
	if totalDiskGB > 0 {
		c.resources.TotalDiskGB = totalDiskGB
		c.resources.AllocatedDiskGB = allocDiskGB
	}
	c.resources.LoadAverage = la
	c.resources.NetworkIO = netSnap
	c.resources.BandwidthInBps = inBps
	c.resources.BandwidthOutBps = outBps
	c.resources.AllocatedCPUCores = runtime.GOMAXPROCS(0)
	c.stats.UptimeSeconds = int64(time.Since(c.startTime).Seconds())
	c.mu.Unlock()
}

// ResourcesSnapshot returns the latest resource sample.
func (c *Collector) ResourcesSnapshot() Resources {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.resources
}

// StatsSnapshot returns the latest host-identity/uptime info.
func (c *Collector) StatsSnapshot() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := c.stats
	s.UptimeSeconds = int64(time.Since(c.startTime).Seconds())
	return s
}

// defaultDiskPath returns the root path to measure for disk usage.
func defaultDiskPath() string {
	if runtime.GOOS == "windows" {
		return "C:\\"
	}
	return "/"
}
