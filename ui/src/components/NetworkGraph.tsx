import { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { TrendingUp } from 'lucide-react';
import { useWAF } from '../store/wafStore';

interface DataPoint {
  time: Date;
  allowed: number;
  blocked: number;
}

export default function NetworkGraph() {
  const svgRef = useRef<SVGSVGElement>(null);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const [data, setData] = useState<DataPoint[]>([]);
  const { state } = useWAF();
  const { trafficStats } = state;

  useEffect(() => {
    const now = new Date();
    const initialData: DataPoint[] = [];
    for (let i = 20; i >= 0; i--) {
      initialData.push({ time: new Date(now.getTime() - i * 3000), allowed: 0, blocked: 0 });
    }
    setData(initialData);
  }, []);

  useEffect(() => {
    if (data.length === 0) return;
    const lastPoint = data[data.length - 1];
    if (trafficStats.totalRequests > 0 && lastPoint.allowed === 0 && lastPoint.blocked === 0) {
      const now = new Date();
      const newData = [...data.slice(1)];
      newData.push({ time: now, allowed: trafficStats.allowedRequests, blocked: trafficStats.blockedRequests });
      setData(newData);
    }
  }, [trafficStats]);

  useEffect(() => {
    if (!svgRef.current || !wrapperRef.current || data.length === 0) return;

    const draw = () => {
      const svg = d3.select(svgRef.current);
      svg.selectAll('*').remove();

      const wrapper = wrapperRef.current;
      if (!wrapper) return;
      const rect = wrapper.getBoundingClientRect();
      const width = rect.width;
      const height = rect.height;
      if (width < 50 || height < 50) return;

      // Set SVG dimensions to match container exactly
      svg.attr('width', width).attr('height', height);

      const margin = { top: 12, right: 12, bottom: 30, left: 40 };
      const innerWidth = Math.max(50, width - margin.left - margin.right);
      const innerHeight = Math.max(40, height - margin.top - margin.bottom);
      const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

      const xScale = d3.scaleTime()
        .domain(d3.extent(data, (d: DataPoint) => d.time) as [Date, Date])
        .range([0, innerWidth]);

      const maxVal = Math.max(10, d3.max(data, (d: DataPoint) => Math.max(d.allowed, d.blocked)) || 10);
      const yScale = d3.scaleLinear().domain([0, maxVal]).nice().range([innerHeight, 0]);

      // Grid
      const gridG = g.append('g');
      gridG.call(d3.axisLeft(yScale).tickSize(-innerWidth).tickFormat(() => ''));
      gridG.selectAll('line').attr('stroke', '#2a2a2a').attr('stroke-dasharray', '2,2');
      gridG.select('.domain')?.remove();

      // X Axis
      const xAxisG = g.append('g').attr('transform', `translate(0,${innerHeight})`);
      const tickCount = width < 360 ? 2 : width < 500 ? 3 : 5;
      xAxisG.call(d3.axisBottom(xScale).ticks(tickCount).tickFormat((d: any) => d3.timeFormat('%H:%M')(d)));
      xAxisG.selectAll('text').attr('fill', '#525252').attr('font-size', width < 400 ? '8px' : '9px');
      xAxisG.select('.domain').attr('stroke', '#2a2a2a');

      // Y Axis
      const yAxisG = g.append('g');
      yAxisG.call(d3.axisLeft(yScale).ticks(Math.min(4, height > 180 ? 4 : 3)));
      yAxisG.selectAll('text').attr('fill', '#525252').attr('font-size', width < 400 ? '8px' : '9px');
      yAxisG.select('.domain').attr('stroke', '#2a2a2a');

      const allowedArea = d3.area<DataPoint>()
        .x((d) => xScale(d.time)).y0(innerHeight).y1((d) => yScale(d.allowed))
        .curve(d3.curveMonotoneX);

      const allowedLine = d3.line<DataPoint>()
        .x((d) => xScale(d.time)).y((d) => yScale(d.allowed))
        .curve(d3.curveMonotoneX);

      const blockedLine = d3.line<DataPoint>()
        .x((d) => xScale(d.time)).y((d) => yScale(d.blocked))
        .curve(d3.curveMonotoneX);

      g.append('path').datum(data).attr('fill', 'rgba(249, 115, 22, 0.08)').attr('d', allowedArea as any);
      g.append('path').datum(data).attr('fill', 'none').attr('stroke', '#f97316').attr('stroke-width', 1.5).attr('d', allowedLine as any);
      g.append('path').datum(data).attr('fill', 'none').attr('stroke', '#ef4444').attr('stroke-width', 1.5).attr('stroke-dasharray', '3,3').attr('d', blockedLine as any);
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
