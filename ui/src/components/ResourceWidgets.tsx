import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Cpu, HardDrive, Wifi, Activity } from 'lucide-react';
import { useWAF } from '../store/wafStore';
import ConnectionBadge from './ConnectionBadge';

interface ResourceConfig {
  label: string;
  unit: string;
  icon: React.ElementType;
  color: string;
  max: number; // denominator used to convert value → 0-100% for the ring
}

const resourceConfigs: ResourceConfig[] = [
  { label: 'CPU', unit: '%', icon: Cpu, color: '#f97316', max: 100 },
  { label: 'Memory', unit: '%', icon: Activity, color: '#fb923c', max: 100 },
  { label: 'Disk I/O', unit: '%', icon: HardDrive, color: '#f59e0b', max: 100 },
  // Latency ring scales to 500ms — anything above is "pegged red".
  { label: 'Latency', unit: 'ms', icon: Wifi, color: '#ef4444', max: 500 },
];

function CircularGauge({ config, index, value }: { config: ResourceConfig; index: number; value: number }) {
  const [animatedValue, setAnimatedValue] = useState(0);
  const radius = 32;
  const circumference = 2 * Math.PI * radius;
  const percentage = Math.min((value / config.max) * 100, 100);
  const offset = circumference - (percentage / 100) * circumference;

  useEffect(() => {
    const timer = setTimeout(() => setAnimatedValue(value), 200 + index * 150);
    return () => clearTimeout(timer);
  }, [value, index]);

  const Icon = config.icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.1, duration: 0.5 }}
      className="relative flex flex-col items-center"
    >
      <div className="relative w-[80px] h-[80px] sm:w-[100px] sm:h-[100px] lg:w-[110px] lg:h-[110px]">
        <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
          <circle cx="50" cy="50" r={radius} fill="none" stroke="#1a1a1a" strokeWidth="6" />
          <circle
            cx="50" cy="50" r={radius} fill="none" stroke={config.color}
            strokeWidth="6" strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={circumference}
            style={{ strokeDashoffset: offset, transition: 'stroke-dashoffset 1.2s cubic-bezier(0.22, 1, 0.36, 1)' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <Icon className="w-3.5 h-3.5 sm:w-4 sm:h-4 lg:w-5 lg:h-5 text-waf-dim mb-0.5" />
          <span className="text-sm sm:text-base lg:text-xl font-bold text-waf-text tabular-nums">
            {Math.round(animatedValue)}
            <span className="text-[9px] sm:text-xs lg:text-sm font-normal text-waf-muted">{config.unit}</span>
          </span>
        </div>
      </div>
      <p className="mt-1.5 sm:mt-2 text-[9px] sm:text-xs lg:text-sm font-medium text-waf-muted uppercase tracking-wider">{config.label}</p>
    </motion.div>
  );
}

export default function ResourceWidgets() {
  const { state } = useWAF();
  const { resourceUsage } = state;
  const values = [resourceUsage.cpu, resourceUsage.memory, resourceUsage.diskIO, resourceUsage.networkLatency];

  return (
    <div className="bg-waf-panel border border-waf-border rounded-xl p-3 sm:p-4 lg:p-6">
      <div className="flex items-center justify-between mb-3 sm:mb-4 lg:mb-6">
        <h2 className="text-waf-text font-semibold text-[10px] sm:text-xs lg:text-sm uppercase tracking-wider flex items-center gap-1.5 sm:gap-2">
          <Activity className="w-3 h-3 sm:w-4 sm:h-4 text-waf-orange" />
          WAF Host Resources
        </h2>
        <ConnectionBadge variant="dot" />
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 lg:gap-6">
        {resourceConfigs.map((config, i) => (
          <CircularGauge key={config.label} config={config} index={i} value={values[i]} />
        ))}
      </div>
    </div>
  );
}
