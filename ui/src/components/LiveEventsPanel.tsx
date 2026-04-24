import { useEffect, useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Radio, Shield, Globe, Bot } from 'lucide-react';
import { connectLiveEvents } from '../services/api';
import type { BlockRecord, EgressEvent, BotEvent } from '../services/api';

type LiveEvent =
  | { kind: 'block'; at: number; data: BlockRecord }
  | { kind: 'egress'; at: number; data: EgressEvent }
  | { kind: 'bot'; at: number; data: BotEvent };

const MAX_EVENTS = 30;

export default function LiveEventsPanel() {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const idCounter = useRef(0);

  useEffect(() => {
    const push = (ev: LiveEvent) => {
      setEvents((prev) => {
        const next = [ev, ...prev];
        return next.length > MAX_EVENTS ? next.slice(0, MAX_EVENTS) : next;
      });
    };
    const stop = connectLiveEvents({
      onOpen: () => setConnected(true),
      onError: () => setConnected(false),
      onBlock: (e) => push({ kind: 'block', at: ++idCounter.current, data: e }),
      onEgress: (e) => push({ kind: 'egress', at: ++idCounter.current, data: e }),
      onBot: (e) => push({ kind: 'bot', at: ++idCounter.current, data: e }),
    });
    return stop;
  }, []);

  const renderEvent = (ev: LiveEvent) => {
    if (ev.kind === 'block') {
      const b = ev.data;
      return (
        <>
          <Shield className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 text-[11px]">
              <span className="text-waf-text font-semibold">Block</span>
              <span className="text-waf-dim font-mono">{b.ip}</span>
              <span className="text-waf-muted font-mono truncate">{b.method} {b.path}</span>
            </div>
            <div className="text-[10px] text-waf-dim mt-0.5 truncate">{b.rule_id} · {b.message}</div>
          </div>
        </>
      );
    }
    if (ev.kind === 'egress') {
      const e = ev.data;
      return (
        <>
          <Globe className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${e.allowed ? 'text-emerald-400' : 'text-amber-400'}`} />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 text-[11px]">
              <span className="text-waf-text font-semibold">Egress {e.allowed ? 'allow' : 'block'}</span>
              <span className="text-waf-muted font-mono truncate">{e.target_url}</span>
            </div>
            {e.reason && <div className="text-[10px] text-waf-dim mt-0.5 truncate">{e.reason}</div>}
          </div>
        </>
      );
    }
    const b = ev.data;
    return (
      <>
        <Bot className="w-3.5 h-3.5 text-purple-400 shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 text-[11px]">
            <span className="text-waf-text font-semibold">Bot</span>
            <span className="text-waf-dim font-mono">{b.ip}</span>
            <span className="text-waf-muted truncate">{b.bot_name}</span>
          </div>
          <div className="text-[10px] text-waf-dim mt-0.5 truncate">{b.user_agent || 'no user-agent'}</div>
        </div>
      </>
    );
  };

  return (
    <div className="bg-waf-panel border border-waf-border rounded-xl p-3 sm:p-4 lg:p-5 h-full flex flex-col">
      <div className="flex items-center justify-between mb-3 sm:mb-4">
        <h2 className="text-waf-text font-semibold text-[10px] sm:text-xs lg:text-sm uppercase tracking-wider flex items-center gap-1.5 sm:gap-2">
          <Radio className="w-3 h-3 sm:w-4 sm:h-4 text-waf-orange" />
          Live Events
        </h2>
        <div className="flex items-center gap-1.5">
          <span className={`relative flex h-2 w-2`}>
            {connected && (
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            )}
            <span className={`relative inline-flex rounded-full h-2 w-2 ${connected ? 'bg-emerald-400' : 'bg-waf-dim'}`} />
          </span>
          <span className="text-[10px] text-waf-muted">{connected ? 'live' : 'disconnected'}</span>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto pr-1 space-y-1.5" style={{ maxHeight: 'clamp(180px, 30vh, 360px)' }}>
        {events.length === 0 ? (
          <div className="flex items-center justify-center h-24 text-waf-dim text-xs">
            Waiting for events...
          </div>
        ) : (
          <AnimatePresence initial={false}>
            {events.map((ev) => (
              <motion.div
                key={ev.at}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="flex gap-2 p-2 rounded-md bg-waf-elevated/50 border border-waf-border/40"
              >
                {renderEvent(ev)}
              </motion.div>
            ))}
          </AnimatePresence>
        )}
      </div>
    </div>
  );
}
