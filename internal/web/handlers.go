package web

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"time"

	"wewaf/internal/config"
	"wewaf/internal/limits"
	"wewaf/internal/telemetry"
)

// Server holds the admin dashboard handlers.
type Server struct {
	cfg     *config.Config
	metrics *telemetry.Metrics
	tmpl    *template.Template
}

// NewServer creates the admin web server.
func NewServer(cfg *config.Config, metrics *telemetry.Metrics) *Server {
	s := &Server{
		cfg:     cfg,
		metrics: metrics,
	}
	// Parse embedded template (for the foundation we keep it simple).
	text := dashboardHTML()
	tmpl, err := template.New("dashboard").Parse(text)
	if err != nil {
		log.Fatalf("web: failed to parse dashboard template: %v", err)
	}
	s.tmpl = tmpl
	return s
}

// RegisterRoutes wires all admin endpoints.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", s.handleDashboard)
	mux.HandleFunc("/api/metrics", s.handleMetrics)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/blocks", s.handleBlocks)
	mux.HandleFunc("/api/traffic", s.handleTraffic)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := map[string]interface{}{
		"Version":   "0.1.0-foundation",
		"StartTime": time.Now().UTC().Format(time.RFC3339),
		"Mode":      s.cfg.ModeSnapshot(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.Execute(w, data); err != nil {
		log.Printf("web: template error: %v", err)
	}
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.metrics.Snapshot())
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	stats := limits.Stats()
	stats["mode"] = s.cfg.ModeSnapshot()
	stats["version"] = "0.1.0-foundation"
	stats["uptime_sec"] = int(time.Since(startTime).Seconds())
	writeJSON(w, stats)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.cfg.Snapshot())
	case http.MethodPost:
		var payload struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if payload.Mode != "" {
			s.cfg.SetMode(payload.Mode)
		}
		writeJSON(w, map[string]string{"status": "ok", "mode": s.cfg.ModeSnapshot()})
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleBlocks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]interface{}{
		"recent": s.metrics.RecentBlocksSnapshot(50),
	})
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.metrics.Snapshot()["traffic_history"])
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("web: json encode error: %v", err)
	}
}

var startTime = time.Now().UTC()

// dashboardHTML returns the raw dashboard template.
func dashboardHTML() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WEWaf Dashboard</title>
<style>
:root{--bg:#0b0c10;--panel:#1f2833;--accent:#45a29e;--text:#c5c6c7;--danger:#ff4c4c;--warn:#ffae42;--ok:#66fcf1;}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:Segoe UI,Roboto,sans-serif;display:flex;height:100vh;overflow:hidden}
.sidebar{width:260px;background:var(--panel);border-right:1px solid #2a2f3a;display:flex;flex-direction:column;padding:1rem;overflow-y:auto}
.sidebar h1{font-size:1.2rem;color:var(--ok);margin-bottom:1rem}
.search{width:100%;padding:.5rem;border-radius:6px;border:1px solid #2a2f3a;background:#0b0c10;color:var(--text);margin-bottom:1rem}
.nav-item{margin:.25rem 0;cursor:pointer;padding:.5rem;border-radius:6px;transition:background .2s}
.nav-item:hover{background:#2a2f3a}
.nav-item.active{background:#2a2f3a;border-left:3px solid var(--accent)}
.sub-nav{padding-left:1rem;font-size:.9rem;color:#8b8d90;display:none}
.sub-nav.open{display:block}
.main{flex:1;padding:1.5rem;overflow-y:auto}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem}
.card{background:var(--panel);border-radius:10px;padding:1rem;box-shadow:0 2px 8px rgba(0,0,0,.4)}
.card h3{color:var(--ok);margin-bottom:.5rem;font-size:.95rem;text-transform:uppercase;letter-spacing:1px}
.widgets{display:flex;gap:1rem;flex-wrap:wrap}
.widget{width:120px;height:120px;border-radius:50%;border:6px solid var(--accent);display:flex;align-items:center;justify-content:center;flex-direction:center;flex-direction:column;text-align:center;position:relative}
.widget.warn{border-color:var(--warn)}
.widget.danger{border-color:var(--danger)}
.widget span{font-size:1.4rem;font-weight:700;color:#fff}
.widget label{font-size:.7rem;color:#8b8d90;margin-top:.2rem}
.traffic-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-top:.5rem}
.stat{text-align:center}
.stat b{display:block;font-size:1.5rem;color:var(--ok)}
.stat span{font-size:.75rem;color:#8b8d90}
.map-placeholder{height:280px;background:#15161a;border-radius:10px;display:flex;align-items:center;justify-content:center;color:#555;font-size:.9rem}
.next-steps{background:linear-gradient(135deg,#1f2833 0%,#2a2f3a 100%);border-left:4px solid var(--warn)}
.next-steps ul{padding-left:1.2rem;margin-top:.5rem;font-size:.9rem}
.next-steps li{margin:.3rem 0}
canvas{max-width:100%}
.footer{margin-top:1rem;font-size:.75rem;color:#555;text-align:center}
@media(max-width:900px){.grid{grid-template-columns:1fr}.sidebar{width:200px}}
</style>
</head>
<body>
<aside class="sidebar">
<h1>WEWaf</h1>
<input class="search" type="text" placeholder="Search settings..." oninput="filterNav(this.value)">
<div class="nav-item active" onclick="toggleSub(this)">Dashboard</div>
<div class="nav-item" onclick="toggleSub(this)">Domains
  <div class="sub-nav">
    <div class="nav-item">Active Sites</div>
    <div class="nav-item">SSL Certificates</div>
  </div>
</div>
<div class="nav-item" onclick="toggleSub(this)">DNS
  <div class="sub-nav">
    <div class="nav-item">Records</div>
    <div class="nav-item">Resolver</div>
  </div>
</div>
<div class="nav-item" onclick="toggleSub(this)">Analytics &amp; Logs
  <div class="sub-nav">
    <div class="nav-item">Traffic Logs</div>
    <div class="nav-item">Blocked Requests</div>
    <div class="nav-item">Audit Trail</div>
  </div>
</div>
<div class="nav-item" onclick="toggleSub(this)">Zero Trust
  <div class="sub-nav">
    <div class="nav-item">Insights</div>
    <div class="nav-item">Networks</div>
    <div class="nav-item">Access Controls</div>
    <div class="nav-item">Device Posture</div>
  </div>
</div>
<div class="nav-item" onclick="toggleSub(this)">Security
  <div class="sub-nav">
    <div class="nav-item">Rules</div>
    <div class="nav-item">Rate Limits</div>
    <div class="nav-item">IP Reputation</div>
  </div>
</div>
<div class="footer">WEWaf v{{.Version}}<br>{{.Mode}} mode</div>
</aside>

<main class="main">
<div class="grid">
  <div class="card">
    <h3>WAF Host Resources</h3>
    <div class="widgets" id="resourceWidgets">
      <div class="widget"><span id="cpuVal">0%</span><label>CPU</label></div>
      <div class="widget"><span id="memVal">0</span><label>Memory MB</label></div>
      <div class="widget"><span id="goroVal">0</span><label>Goroutines</label></div>
    </div>
  </div>
  <div class="card">
    <h3>Incoming Traffic</h3>
    <div class="traffic-stats">
      <div class="stat"><b id="totalReq">0</b><span>Total Requests</span></div>
      <div class="stat"><b id="uniqIP">0</b><span>Unique IPs</span></div>
      <div class="stat"><b id="blockedReq">0</b><span>Blocked</span></div>
    </div>
  </div>
</div>

<div class="grid">
  <div class="card">
    <h3>World Map</h3>
    <div class="map-placeholder" id="attackMap">Attack map placeholder — integrate Leaflet or Mapbox here</div>
  </div>
  <div class="card">
    <h3>Network Traffic</h3>
    <canvas id="trafficChart" height="120"></canvas>
  </div>
</div>

<div class="card next-steps">
  <h3>Next Steps</h3>
  <p>Complete your WEWaf setup to secure your origin:</p>
  <ul>
    <li>Point your domain DNS A-record to this WAF host IP.</li>
    <li>Upload or generate an SSL certificate in <strong>Domains &rarr; SSL Certificates</strong>.</li>
    <li>Add your origin backend URL in <strong>Settings</strong> (default: <code>http://localhost:3000</code>).</li>
    <li>Review default rules in <strong>Security &rarr; Rules</strong> and tune thresholds.</li>
    <li>Enable <strong>Zero Trust &rarr; Access Controls</strong> to restrict admin panel access by IP.</li>
  </ul>
</div>
</main>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script>
function toggleSub(el){const sub=el.querySelector('.sub-nav');if(sub){sub.classList.toggle('open');}}
function filterNav(q){q=q.toLowerCase();document.querySelectorAll('.nav-item').forEach(n=>{n.style.display=n.textContent.toLowerCase().includes(q)?'':'none';});}

const ctx=document.getElementById('trafficChart').getContext('2d');
const trafficData={labels:[],datasets:[{label:'Requests',data:[],borderColor:'#45a29e',fill:false},{label:'Blocked',data:[],borderColor:'#ff4c4c',fill:false}]};
let chart=new Chart(ctx,{type:'line',data:trafficData,options:{responsive:true,plugins:{legend:{labels:{color:'#c5c6c7'}}},scales:{x:{ticks:{color:'#8b8d90'}},y:{ticks:{color:'#8b8d90'}}}}});

async function refresh(){
  try{
    const stats=await fetch('/api/stats').then(r=>r.json());
    document.getElementById('cpuVal').textContent=(stats.cpu_cores||0)+' cores';
    document.getElementById('memVal').textContent=stats.memory_used_mb||0;
    document.getElementById('goroVal').textContent=stats.goroutines||0;
    const m=await fetch('/api/metrics').then(r=>r.json());
    document.getElementById('totalReq').textContent=m.total_requests||0;
    document.getElementById('uniqIP').textContent=m.unique_ips||0;
    document.getElementById('blockedReq').textContent=m.blocked_requests||0;
    const t=await fetch('/api/traffic').then(r=>r.json());
    if(Array.isArray(t)&&t.length){
      trafficData.labels=t.map(p=>new Date(p.time).toLocaleTimeString());
      trafficData.datasets[0].data=t.map(p=>p.requests);
      trafficData.datasets[1].data=t.map(p=>p.blocked);
      chart.update();
    }
  }catch(e){console.error('refresh error',e);}
}
setInterval(refresh,5000);refresh();
</script>
</body>
</html>`
}
