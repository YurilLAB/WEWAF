import { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { TrendingUp } from 'lucide-react';
import { api } from '../services/api';

interface DataPoint {
  time: Date;
  allowed: number;
  blocked: number;
}

// The backend samples traffic every 10s into a 288-point ring (~48 min at
// the default cadence). We render the most recent 48 buckets so the graph
// shows a live, moving window rather than cumulative totals.
const WINDOW_SIZE = 48;
const REFRESH_MS = 5000;

export default function NetworkGraph() {
  const svgRef = useRef<SVGSVGElement>(null);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const [data, setData] = useState<DataPoint[]>([]);

  // Poll traffic_history from the backend. Each point already represents a
  // per-interval delta (see startTrafficSampler), so we don't need to
  // difference anything client-side.
  useEffect(() => {
    let cancelled = false;
    const pull = async () => {
      const points = await api.getTraffic();
      if (cancelled || !points || !Array.isArray(points)) return;
      const slice = points.slice(-WINDOW_SIZE);
      setData(
        slice.map((p) => ({
          time: new Date(p.time),
          allowed: Math.max(0, (p.requests || 0) - (p.blocked || 0)),
          blocked: p.blocked || 0,
        })),
      );
    };
    pull();
    const id = setInterval(pull, REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  useEffect(() => {
    if (!svgRef.current || !wrapperRef.current) return;

    const draw = () => {
      const svg = d3.select(svgRef.current);
      svg.selectAll('*').remove();

      const wrapper = wrapperRef.current;
      if (!wrapper) return;
      const rect = wrapper.getBoundingClientRect();
      const width = rect.width;
      const height = rect.height;
      if (width < 50 || height < 50) return;

      svg.attr('width', width).attr('height', height);

      const margin = { top: 12, right: 12, bottom: 30, left: 40 };
      const innerWidth = Math.max(50, width - margin.left - margin.right);
      const innerHeight = Math.max(40, height - margin.top - margin.bottom);
      const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

      if (data.length === 0) {
        g.append('text')
          .attr('x', innerWidth / 2)
          .attr('y', innerHeight / 2)
          .attr('text-anchor', 'middle')
          .attr('fill', '#525252')
          .attr('font-size', '11px')
          .text('waiting for samples...');
        return;
      }

      const xScale = d3
        .scaleTime()
        .domain(d3.extent(data, (d: DataPoint) => d.time) as [Date, Date])
        .range([0, innerWidth]);

      const maxVal = Math.max(
        1,
        d3.max(data, (d: DataPoint) => Math.max(d.allowed, d.blocked)) || 1,
      );
      const yScale = d3.scaleLinear().domain([0, maxVal]).nice().range([innerHeight, 0]);

      const gridG = g.append('g');
      gridG.call(d3.axisLeft(yScale).tickSize(-innerWidth).tickFormat(() => ''));
      gridG.selectAll('line').attr('stroke', '#2a2a2a').attr('stroke-dasharray', '2,2');
      gridG.select('.domain')?.remove();

      const xAxisG = g.append('g').attr('transform', `translate(0,${innerHeight})`);
      const tickCount = width < 360 ? 2 : width < 500 ? 3 : 5;
      xAxisG.call(
        d3
          .axisBottom(xScale)
          .ticks(tickCount)
          .tickFormat((d: any) => d3.timeFormat('%H:%M')(d)),
      );
      xAxisG.selectAll('text').attr('fill', '#525252').attr('font-size', width < 400 ? '8px' : '9px');
      xAxisG.select('.domain').attr('stroke', '#2a2a2a');

      const yAxisG = g.append('g');
      yAxisG.call(d3.axisLeft(yScale).ticks(Math.min(4, height > 180 ? 4 : 3)));
      yAxisG.selectAll('text').attr('fill', '#525252').attr('font-size', width < 400 ? '8px' : '9px');
      yAxisG.select('.domain').attr('stroke', '#2a2a2a');

      const allowedArea = d3
        .area<DataPoint>()
        .x((d) => xScale(d.time))
        .y0(innerHeight)
        .y1((d) => yScale(d.allowed))
        .curve(d3.curveMonotoneX);

      const allowedLine = d3
        .line<DataPoint>()
        .x((d) => xScale(d.time))
        .y((d) => yScale(d.allowed))
        .curve(d3.curveMonotoneX);

      const blockedLine = d3
        .line<DataPoint>()
        .x((d) => xScale(d.time))
        .y((d) => yScale(d.blocked))
        .curve(d3.curveMonotoneX);

      g.append('path').datum(data).attr('fill', 'rgba(249, 115, 22, 0.08)').attr('d', allowedArea as any);
      g.append('path')
        .datum(data)
        .attr('fill', 'none')
        .attr('stroke', '#f97316')
        .attr('stroke-width', 1.5)
        .attr('d', allowedLine as any);
      g.append('path')
        .datum(data)
        .attr('fill', 'none')
        .attr('stroke', '#ef4444')
        .attr('stroke-width', 1.5)
        .attr('stroke-dasharray', '3,3')
        .attr('d', blockedLine as any);
    };

    draw();

    const ro = new ResizeObserver(() => draw());
    ro.observe(wrapperRef.current);
    return () => ro.disconnect();
  }, [data]);

  return (
    <div className="bg-waf-panel border border-waf-border rounded-xl p-3 sm:p-4 lg:p-5">
      <div className="flex items-center justify-between mb-3 sm:mb-4">
        <h2 className="text-waf-text font-semibold text-[10px] sm:text-xs lg:text-sm uppercase tracking-wider flex items-center gap-1.5 sm:gap-2">
          <TrendingUp className="w-3 h-3 sm:w-4 sm:h-4 text-waf-orange" />
          Network Traffic
        </h2>
        <div className="flex items-center gap-2 sm:gap-3 lg:gap-4">
          <div className="flex items-center gap-1 sm:gap-1.5 lg:gap-2">
            <span className="w-2.5 sm:w-3 h-[2px] bg-waf-orange" />
            <span className="text-[9px] sm:text-[10px] lg:text-xs text-waf-muted">Allowed</span>
          </div>
          <div className="flex items-center gap-1 sm:gap-1.5 lg:gap-2">
            <span className="w-2.5 sm:w-3 h-[2px] border-t-2 border-dashed border-red-500" />
            <span className="text-[9px] sm:text-[10px] lg:text-xs text-waf-muted">Blocked</span>
          </div>
        </div>
      </div>
      <div ref={wrapperRef} className="w-full" style={{ height: 'clamp(140px, 28vw, 250px)' }}>
        <svg ref={svgRef} className="w-full h-full block" />
      </div>
    </div>
  );
}
