import { useEffect, useRef, useState, useCallback } from 'react';
import * as d3 from 'd3';
import { feature } from 'topojson-client';
import { motion, AnimatePresence } from 'framer-motion';
import { Globe, X, MapPin, Users, ZoomIn, ZoomOut, Maximize2 } from 'lucide-react';
import { useWAF } from '../store/wafStore';

interface IPCountry {
  country: string;
  ip: string;
  count: number;
}

const countryCoords: Record<string, { lat: number; lon: number }> = {
  'China': { lat: 35.86, lon: 104.19 }, 'United States': { lat: 37.09, lon: -95.71 },
  'Russia': { lat: 61.52, lon: 105.31 }, 'Brazil': { lat: -14.23, lon: -51.92 },
  'India': { lat: 20.59, lon: 78.96 }, 'Germany': { lat: 51.16, lon: 10.45 },
  'United Kingdom': { lat: 55.37, lon: -3.43 }, 'France': { lat: 46.22, lon: 2.21 },
  'Japan': { lat: 36.20, lon: 138.25 }, 'Canada': { lat: 56.13, lon: -106.34 },
  'Australia': { lat: -25.27, lon: 133.77 }, 'South Korea': { lat: 35.90, lon: 127.76 },
  'Netherlands': { lat: 52.13, lon: 5.29 }, 'Singapore': { lat: 1.35, lon: 103.81 },
  'Ukraine': { lat: 48.37, lon: 31.16 }, 'North Korea': { lat: 40.33, lon: 127.51 },
  'Iran': { lat: 32.42, lon: 53.68 }, 'Vietnam': { lat: 14.05, lon: 108.27 },
  'Indonesia': { lat: -0.78, lon: 113.92 }, 'Turkey': { lat: 38.96, lon: 35.24 },
  'Pakistan': { lat: 30.37, lon: 69.34 }, 'Nigeria': { lat: 9.08, lon: 8.67 },
  'Bangladesh': { lat: 23.68, lon: 90.35 }, 'Philippines': { lat: 12.87, lon: 121.77 },
  'Egypt': { lat: 26.82, lon: 30.80 }, 'Poland': { lat: 51.91, lon: 19.14 },
  'Italy': { lat: 41.87, lon: 12.56 }, 'Spain': { lat: 40.46, lon: -3.74 },
  'Mexico': { lat: 23.63, lon: -102.55 }, 'South Africa': { lat: -30.56, lon: 22.94 },
  'Thailand': { lat: 15.87, lon: 100.99 }, 'Malaysia': { lat: 4.21, lon: 101.98 },
  'Argentina': { lat: -38.42, lon: -63.62 }, 'Colombia': { lat: 4.57, lon: -74.30 },
};

export default function WorldMap() {
  const svgRef = useRef<SVGSVGElement>(null);
  const gRef = useRef<SVGGElement | null>(null);
  const zoomRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const [worldData, setWorldData] = useState<any>(null);
  const [hoveredCountry, setHoveredCountry] = useState<string | null>(null);
  const [clickedCountry, setClickedCountry] = useState<string | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const [activeTab, setActiveTab] = useState<'map' | 'ips'>('map');
  const [countryIPs, setCountryIPs] = useState<IPCountry[]>([]);
  const { state } = useWAF();
  const { securityEvents } = state;

  useEffect(() => {
    if (securityEvents.length > 0) {
      const ipMap = new Map<string, { country: string; count: number }>();
      securityEvents.forEach((e) => {
        const existing = ipMap.get(e.sourceIP);
        if (existing) existing.count++;
        else ipMap.set(e.sourceIP, { country: e.country, count: 1 });
      });
      const ips: IPCountry[] = Array.from(ipMap.entries()).map(([ip, data]) => ({
        country: data.country, ip, count: data.count,
      }));
      setCountryIPs(ips);
    }
  }, [securityEvents]);

  useEffect(() => {
    fetch('/world-topology.json')
      .then((res) => res.json())
      .then((topology) => {
        const countries = feature(topology, topology.objects.countries);
        setWorldData(countries);
      })
      .catch((err) => console.error('Failed to load map data:', err));
  }, []);

  const hasIPs = useCallback((name: string) => countryIPs.some((c) => c.country === name), [countryIPs]);

  const getFill = useCallback((name: string) => {
    if (clickedCountry === name) return '#f97316';
    if (hasIPs(name)) return 'rgba(249, 115, 22, 0.4)';
    return '#1a1a1a';
  }, [clickedCountry, hasIPs]);

  const getStroke = useCallback((name: string) => {
    if (clickedCountry === name) return '#fb923c';
    if (hasIPs(name)) return 'rgba(251, 146, 60, 0.7)';
    return '#2a2a2a';
  }, [clickedCountry, hasIPs]);

  useEffect(() => {
    if (!worldData || !svgRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const rect = svgRef.current.getBoundingClientRect();
    const width = rect.width || 800;
    const height = rect.height || 350;
    if (width < 50) return;

    const projection = d3.geoNaturalEarth1()
      .scale(width / 5.5)
      .translate([width / 2, height / 2]);

    const path = d3.geoPath().projection(projection);

    const g = svg.append('g');
    gRef.current = g.node();

    g.selectAll('path.country')
      .data(worldData.features)
      .enter()
      .append('path')
      .attr('class', 'country')
      .attr('d', path as any)
      .attr('fill', (d: any) => getFill(d.properties.name))
      .attr('stroke', (d: any) => getStroke(d.properties.name))
      .attr('stroke-width', (d: any) => clickedCountry === d.properties.name ? 1.5 : 0.5)
      .style('cursor', 'pointer')
      .style('transition', 'fill 0.3s, stroke 0.3s')
      .on('mouseenter', function (_event: any, d: any) {
        if (clickedCountry !== d.properties.name) {
          d3.select(this).attr('fill', '#2a2a2e');
        }
        setHoveredCountry(d.properties.name);
      })
      .on('mousemove', function (event: any) {
        setTooltipPos({ x: event.clientX, y: event.clientY });
      })
      .on('mouseleave', function (_event: any, d: any) {
        d3.select(this).attr('fill', getFill(d.properties.name));
        setHoveredCountry(null);
      })
      .on('click', function (_event: any, d: any) {
        setClickedCountry((prev) => prev === d.properties.name ? null : d.properties.name);
      });

    countryIPs.forEach((ip) => {
      const coords = countryCoords[ip.country];
      if (!coords) return;
      const proj = projection([coords.lon, coords.lat]);
      if (!proj) return;
      const [x, y] = proj;
      g.append('circle').attr('cx', x).attr('cy', y).attr('r', 3).attr('fill', '#f97316').attr('opacity', 0.9);
      g.append('circle').attr('cx', x).attr('cy', y).attr('r', 3)
        .attr('fill', 'none').attr('stroke', '#f97316').attr('stroke-width', 1).attr('opacity', 0.5)
        .append('animate').attr('attributeName', 'r').attr('from', 3).attr('to', 20)
        .attr('dur', '2.5s').attr('repeatCount', 'indefinite');
    });

    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.8, 8])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });
    zoomRef.current = zoom;
    svg.call(zoom);

    // Cleanup function
    return () => {
      svg.on('.zoom', null); // Remove all zoom listeners
      svg.selectAll('*').remove();
    };
  }, [worldData, countryIPs, clickedCountry, getFill, getStroke]);

  const handleZoomIn = () => {
    if (!svgRef.current || !zoomRef.current) return;
    d3.select(svgRef.current).transition().duration(300).call(zoomRef.current.scaleBy, 1.5);
  };

  const handleZoomOut = () => {
    if (!svgRef.current || !zoomRef.current) return;
    d3.select(svgRef.current).transition().duration(300).call(zoomRef.current.scaleBy, 0.67);
  };

  const handleReset = () => {
    if (!svgRef.current || !zoomRef.current) return;
    d3.select(svgRef.current).transition().duration(300).call(zoomRef.current.transform, d3.zoomIdentity);
  };

  const uniqueCountries = [...new Set(countryIPs.map((c) => c.country))];

  // Tooltip position clamping for mobile
  const getTooltipStyle = () => {
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    let left = tooltipPos.x + 12;
    let top = tooltipPos.y - 12;
    if (left + 200 > vw) left = vw - 210;
    if (left < 8) left = 8;
    if (top + 60 > vh) top = vh - 70;
    if (top < 8) top = 8;
    return { left, top };
  };

  return (
    <div className="relative">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-waf-text font-semibold text-[10px] sm:text-xs lg:text-sm uppercase tracking-wider flex items-center gap-2">
          <Globe className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-waf-orange" />
          Global Threat Vector
        </h2>
        <div className="flex items-center gap-1.5 sm:gap-2">
          <button onClick={() => setActiveTab('map')} className={`px-2 py-0.5 sm:px-2.5 sm:py-1 rounded text-[10px] sm:text-xs font-medium transition-colors ${activeTab === 'map' ? 'bg-waf-orange text-white' : 'bg-waf-elevated text-waf-muted'}`}>Map</button>
          <button onClick={() => setActiveTab('ips')} className={`px-2 py-0.5 sm:px-2.5 sm:py-1 rounded text-[10px] sm:text-xs font-medium transition-colors flex items-center gap-1 ${activeTab === 'ips' ? 'bg-waf-orange text-white' : 'bg-waf-elevated text-waf-muted'}`}>
            <Users className="w-2.5 h-2.5 sm:w-3 sm:h-3" /> IPs
          </button>
        </div>
      </div>

      <div className="bg-waf-panel border border-waf-border rounded-xl overflow-hidden relative" style={{ minHeight: '200px' }}>
        <AnimatePresence mode="wait">
          {activeTab === 'map' ? (
            <motion.div key="map" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="relative" style={{ minHeight: '200px' }}>
              <div className="absolute top-2 right-2 z-10 flex flex-col gap-1">
                <button onClick={handleZoomIn} className="p-1 sm:p-1.5 bg-waf-elevated/90 border border-waf-border rounded hover:bg-waf-border text-waf-muted hover:text-waf-orange transition-colors">
                  <ZoomIn className="w-3 h-3 sm:w-4 sm:h-4" />
                </button>
                <button onClick={handleZoomOut} className="p-1 sm:p-1.5 bg-waf-elevated/90 border border-waf-border rounded hover:bg-waf-border text-waf-muted hover:text-waf-orange transition-colors">
                  <ZoomOut className="w-3 h-3 sm:w-4 sm:h-4" />
                </button>
                <button onClick={handleReset} className="p-1 sm:p-1.5 bg-waf-elevated/90 border border-waf-border rounded hover:bg-waf-border text-waf-muted hover:text-waf-orange transition-colors">
                  <Maximize2 className="w-3 h-3 sm:w-4 sm:h-4" />
                </button>
              </div>

              <svg
                ref={svgRef}
                className="w-full"
                style={{ height: 'clamp(180px, 35vw, 350px)', display: 'block' }}
                viewBox="0 0 800 350"
                preserveAspectRatio="xMidYMid meet"
              />

              {clickedCountry && (
                <motion.div initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} className="absolute bottom-2 left-2 right-2 sm:right-12 bg-waf-elevated/95 border border-waf-orange/30 rounded-lg p-2 sm:p-3 backdrop-blur-sm">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 sm:gap-2 min-w-0">
                      <MapPin className="w-3 h-3 sm:w-4 sm:h-4 text-waf-orange shrink-0" />
                      <span className="text-waf-text text-[11px] sm:text-sm font-medium truncate">{clickedCountry}</span>
                      <span className="text-waf-muted text-[10px] sm:text-xs shrink-0">{countryIPs.filter((c) => c.country === clickedCountry).length} IP(s)</span>
                    </div>
                    <button onClick={() => setClickedCountry(null)} className="p-0.5 sm:p-1 rounded hover:bg-waf-border text-waf-muted shrink-0 ml-2">
                      <X className="w-3 h-3 sm:w-3.5 sm:h-3.5" />
                    </button>
                  </div>
                </motion.div>
              )}

              {securityEvents.length === 0 && !clickedCountry && (
                <div className="absolute inset-0 flex items-center justify-center pointer-events-none" style={{ top: '30px', bottom: '30px' }}>
                  <div className="text-center">
                    <Globe className="w-6 h-6 sm:w-8 sm:h-8 text-waf-dim mx-auto mb-1 sm:mb-2 opacity-30" />
                    <p className="text-waf-dim text-[10px] sm:text-xs">No active threats detected</p>
                  </div>
                </div>
              )}
            </motion.div>
          ) : (
            <motion.div key="ips" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="p-3 sm:p-4">
              <div className="space-y-2 sm:space-y-3 max-h-[300px] sm:max-h-[350px] overflow-y-auto">
                {uniqueCountries.length === 0 ? (
                  <p className="text-waf-dim text-xs sm:text-sm text-center py-4 sm:py-6">No IP data yet</p>
                ) : (
                  uniqueCountries.map((country) => {
                    const ips = countryIPs.filter((c) => c.country === country);
                    return (
                      <div key={country} className="bg-waf-elevated rounded-lg p-2 sm:p-3 border border-waf-border">
                        <div className="flex items-center gap-1.5 sm:gap-2 mb-1.5 sm:mb-2">
                          <MapPin className="w-3 h-3 sm:w-4 sm:h-4 text-waf-orange" />
                          <span className="text-waf-text text-[11px] sm:text-sm font-medium">{country}</span>
                          <span className="text-waf-muted text-[10px] sm:text-xs">({ips.length})</span>
                        </div>
                        <div className="flex flex-wrap gap-1 sm:gap-1.5">
                          {ips.map((ip) => (
                            <span key={ip.ip} className="px-1.5 sm:px-2 py-0.5 bg-waf-bg text-waf-muted text-[10px] sm:text-xs font-mono rounded border border-waf-border">{ip.ip}</span>
                          ))}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {hoveredCountry && activeTab === 'map' && (
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            className="fixed z-50 bg-waf-elevated border border-waf-orange/30 rounded-lg px-2 sm:px-3 py-1.5 sm:py-2 shadow-xl pointer-events-none max-w-[180px] sm:max-w-[220px]"
            style={getTooltipStyle()}
          >
            <p className="text-waf-text text-[11px] sm:text-xs font-medium">{hoveredCountry}</p>
            <p className="text-waf-dim text-[9px] sm:text-[10px]">{countryIPs.filter((c) => c.country === hoveredCountry).length} IP(s) | Click to select</p>
          </motion.div>
        )}
      </div>

      <div className="flex items-center gap-2 sm:gap-4 mt-2 sm:mt-3 px-1 flex-wrap">
        <div className="flex items-center gap-1"><span className="w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-sm bg-waf-orange/40 border border-waf-orange/60" /><span className="text-[9px] sm:text-[10px] text-waf-muted">Known Source</span></div>
        <div className="flex items-center gap-1"><span className="w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-sm bg-waf-orange border border-waf-amber" /><span className="text-[9px] sm:text-[10px] text-waf-muted">Selected</span></div>
        <div className="flex items-center gap-1"><span className="w-1.5 h-1.5 sm:w-2 sm:h-2 rounded-full bg-waf-orange" /><span className="text-[9px] sm:text-[10px] text-waf-muted">Origin</span></div>
        <div className="flex items-center gap-1"><span className="text-[9px] sm:text-[10px] text-waf-dim">Scroll=Zoom Drag=Pan</span></div>
      </div>
    </div>
  );
}
