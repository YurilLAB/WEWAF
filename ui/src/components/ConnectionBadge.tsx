import { Wifi, WifiOff, Loader2, CheckCircle2 } from 'lucide-react';
import { useWAF } from '../store/wafStore';
import type { ConnectionState } from '../store/wafStore';

interface ConnectionBadgeProps {
  variant?: 'pill' | 'dot' | 'full';
}

const config: Record<ConnectionState, { label: string; color: string; bg: string; ring: string; icon: React.ElementType; animate: boolean }> = {
  connecting: {
    label: 'Connecting',
    color: 'text-waf-amber',
    bg: 'bg-waf-amber/10',
    ring: 'ring-waf-amber/30',
    icon: Loader2,
    animate: true,
  },
  online: {
    label: 'Online',
    color: 'text-green-400',
    bg: 'bg-green-400/10',
    ring: 'ring-green-400/30',
    icon: Wifi,
    animate: false,
  },
  offline: {
    label: 'Offline',
    color: 'text-red-400',
    bg: 'bg-red-400/10',
    ring: 'ring-red-400/30',
    icon: WifiOff,
    animate: false,
  },
  configured: {
    label: 'Configured',
    color: 'text-sky-400',
    bg: 'bg-sky-400/10',
    ring: 'ring-sky-400/30',
    icon: CheckCircle2,
    animate: false,
  },
};

export default function ConnectionBadge({ variant = 'pill' }: ConnectionBadgeProps) {
  const { state } = useWAF();
  const { connectionState } = state;
  const c = config[connectionState];
  const Icon = c.icon;

  if (variant === 'dot') {
    return (
      <div className="flex items-center gap-1.5" title={`WEWAF is ${c.label.toLowerCase()}`}>
        <span className="relative flex h-2.5 w-2.5">
          {c.animate && (
            <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${c.color.replace('text-', 'bg-')}`} />
          )}
          <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${c.color.replace('text-', 'bg-')}`} />
        </span>
      </div>
    );
  }

  if (variant === 'full') {
    return (
      <div className={`flex items-center gap-2 px-3 py-2 rounded-lg ${c.bg} border border-${c.color.split('-')[0]}-400/20`}>
        <span className="relative flex h-2.5 w-2.5">
          {c.animate && (
            <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${c.color.replace('text-', 'bg-')}`} />
          )}
          <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${c.color.replace('text-', 'bg-')}`} />
        </span>
        <Icon className={`w-3.5 h-3.5 ${c.color} ${c.animate ? 'animate-spin' : ''}`} />
        <span className={`text-xs font-medium ${c.color}`}>{c.label}</span>
        <span className={`text-[10px] ${c.color} opacity-60 hidden sm:inline`}>
          {connectionState === 'connecting' && '(polling backend...)'}
          {connectionState === 'online' && '(live metrics)'}
          {connectionState === 'offline' && '(backend unreachable)'}
          {connectionState === 'configured' && '(ready to connect)'}
        </span>
      </div>
    );
  }

  // pill (default)
  return (
    <div className={`flex items-center gap-1.5 px-2 sm:px-3 py-1.5 ${c.bg} rounded-md ring-1 ${c.ring}`}>
      <span className="relative flex h-2 w-2">
        {c.animate && (
          <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${c.color.replace('text-', 'bg-')}`} />
        )}
        <span className={`relative inline-flex rounded-full h-2 w-2 ${c.color.replace('text-', 'bg-')}`} />
      </span>
      <span className={`text-[9px] sm:text-xs font-medium ${c.color}`}>{c.label}</span>
    </div>
  );
}
