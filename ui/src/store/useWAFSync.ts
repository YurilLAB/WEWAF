import { useEffect, useRef, useCallback } from 'react';
import { api, startPolling } from '../services/api';
import { useWAF } from './wafStore';
import type { ConnectionState } from './wafStore';

// Stable connection state machine:
// - "connecting" ONLY during initial page load (first ~30s)
// - "online" when backend responds
// - "offline" after failed initial attempts — STAYS offline until success
// - "configured" when setup steps done but never connected
//
// Key rule: once we reach offline/configured, we NEVER go back to connecting.
// Background retries happen silently without changing the displayed state.
// This prevents the connect→offline→connect flicker loop.

const INITIAL_ATTEMPTS_MAX = 6;        // 6 attempts × 5s = 30s of "connecting"
const ONLINE_POLL_MS = 5000;           // Normal polling when online
const OFFLINE_BACKOFF_MS = 30000;      // Retry every 30s when offline (silent)

// Delays for connection test pacing (ms between each check)
const TEST_STEP_DELAY_MS = 800;

export function useWAFSync() {
  const { state, dispatch } = useWAF();
  const attemptCount = useRef(0);
  const hasEverConnected = useRef(false);
  const isRetrying = useRef(false);
  const lastOnlinePoll = useRef(0);
  const prevConnectionState = useRef(state.connectionState);

  // Mark that a background retry succeeded — promote offline→online
  const handleHealthSuccess = useCallback((health: { mode: string }) => {
    attemptCount.current = 0;
    hasEverConnected.current = true;
    isRetrying.current = false;
    dispatch({ type: 'SET_CONNECTION_STATE', payload: 'online' });
    dispatch({
      type: 'UPDATE_SETTINGS',
      payload: { mode: (health.mode as 'active' | 'detection' | 'learning') || 'detection' },
    });
    // Record event if state changed
    if (prevConnectionState.current !== 'online') {
      dispatch({ type: 'RECORD_CONNECTION_EVENT', payload: { state: 'online', ping_ms: 0 } });
    }
  }, [dispatch, prevConnectionState.current]);

  const handleHealthFailure = useCallback(() => {
    attemptCount.current++;

    // Only transition to offline during the initial connection window
    // Once we're offline/configured, STAY there — no flickering back to connecting
    if (state.connectionState === 'connecting' && attemptCount.current >= INITIAL_ATTEMPTS_MAX) {
      const allStepsDone = state.nextSteps.every((s) => s.completed);
      const newState: ConnectionState = allStepsDone && !hasEverConnected.current ? 'configured' : 'offline';
      dispatch({ type: 'SET_CONNECTION_STATE', payload: newState });
      dispatch({ type: 'RECORD_CONNECTION_EVENT', payload: { state: newState, ping_ms: -1 } });
    }
  }, [dispatch, state.connectionState, state.nextSteps]);

  // Track state changes for session history
  useEffect(() => {
    if (prevConnectionState.current !== state.connectionState) {
      dispatch({
        type: 'RECORD_CONNECTION_EVENT',
        payload: { state: state.connectionState, ping_ms: state.connectionInfo.last_ping_ms || -1 },
      });
      prevConnectionState.current = state.connectionState;
    }
  }, [state.connectionState, dispatch, state.connectionInfo.last_ping_ms]);

  // Fetch data when backend is reachable
  const fetchData = useCallback(async () => {
    // Metrics
    try {
      const metrics = await api.getMetrics();
      if (metrics) {
        dispatch({
          type: 'UPDATE_TRAFFIC_STATS',
          payload: {
            totalRequests: metrics.total_requests || 0,
            blockedRequests: metrics.blocked_requests || 0,
            allowedRequests: metrics.passed_requests || 0,
            uniqueIPs: metrics.unique_ips || 0,
            totalIPs: metrics.unique_ips || 0,
          },
        });

        if (metrics.recent_blocks && metrics.recent_blocks.length > 0) {
          const events = metrics.recent_blocks.map((b, i) => ({
            id: `block-${i}-${Date.now()}`,
            timestamp: b.timestamp,
            type: 'xss' as const,
            severity: 'high' as const,
            sourceIP: b.ip,
            country: 'Unknown',
            url: b.path,
            action: 'blocked' as const,
            details: b.message,
          }));
          dispatch({ type: 'SET_SECURITY_EVENTS', payload: events });
        }
      }
    } catch { /* silently fail */ }

    // Stats
    try {
      const stats = await api.getStats();
      if (stats) {
        dispatch({
          type: 'UPDATE_RESOURCE_USAGE',
          payload: {
            cpu: stats.cpu_percent || 0,
            memory: stats.memory_percent || 0,
            diskIO: stats.disk_io_percent || 0,
            networkLatency: stats.network_latency_ms || 0,
          },
        });
      }
    } catch { /* silently fail */ }

    // Rules
    try {
      const rules = await api.getRules();
      if (rules?.rules && rules.rules.length > 0) {
        const wafRules = rules.rules.map((r) => ({
          id: r.id,
          name: r.name,
          description: r.description,
          pattern: r.description,
          action: (r.action === 'BLOCK' ? 'block' : r.action === 'CHALLENGE' ? 'challenge' : 'log') as 'block' | 'challenge' | 'log',
          enabled: true,
          priority: r.score || 5,
          category: 'custom' as const,
          hits: 0,
        }));
        dispatch({ type: 'SET_WAF_RULES', payload: wafRules });
      }
    } catch { /* silently fail */ }

    // Host stats
    try {
      const host = await api.getHostStats();
      if (host) dispatch({ type: 'SET_HOST_STATS', payload: host });
    } catch { /* silently fail */ }

    // Host resources
    try {
      const resources = await api.getHostResources();
      if (resources) dispatch({ type: 'SET_HOST_RESOURCES', payload: resources });
    } catch { /* silently fail */ }

    // Connection status
    try {
      const conn = await api.getConnectionStatus();
      if (conn) {
        dispatch({
          type: 'UPDATE_CONNECTION_INFO',
          payload: {
            connected: conn.connected,
            last_ping_ms: conn.last_ping_ms,
            failover_active: conn.failover_active,
          },
        });
      }
    } catch { /* silently fail */ }

    // Request logs (blocks from history)
    try {
      const reqData = await api.getRequests();
      if (reqData?.requests && reqData.requests.length > 0) {
        const logs = reqData.requests.map((r, i) => ({
          id: `req-${i}-${Date.now()}`,
          timestamp: r.ts,
          method: r.method,
          url: r.path,
          sourceIP: r.ip,
          country: 'Unknown',
          userAgent: '',
          status: 'blocked' as const,
          responseTime: 0,
          ruleTriggered: r.rule_id,
        }));
        dispatch({ type: 'SET_REQUEST_LOGS', payload: logs });
      }
    } catch { /* silently fail */ }
  }, [dispatch]);

  // Main sync loop
  useEffect(() => {
    const tick = async () => {
      // 1. Try health check
      let healthOk = false;
      try {
        const health = await api.getHealth();
        if (health && health.status === 'ok') {
          healthOk = true;
          // Only update state if we're not already online (prevents redundant dispatches)
          if (state.connectionState !== 'online') {
            handleHealthSuccess(health);
          }
        } else {
          handleHealthFailure();
        }
      } catch {
        handleHealthFailure();
      }

      // 2. Fetch data only if health is good
      if (healthOk) {
        await fetchData();
        lastOnlinePoll.current = Date.now();
      }
    };

    tick();

    // Use different poll intervals based on state
    const intervalMs = state.connectionState === 'online' ? ONLINE_POLL_MS : OFFLINE_BACKOFF_MS;
    const stop = startPolling(tick, intervalMs);
    return () => stop();
  }, [dispatch, state.connectionState, handleHealthSuccess, handleHealthFailure, fetchData]);
}

// Paced connection test — runs each check with a visible delay
// so the user sees the progress happening
export async function runPacedConnectionTest(
  steps: { label: string; check: () => Promise<boolean> | boolean }[],
  onStepUpdate: (index: number, status: 'running' | 'pass' | 'fail', message: string) => void,
  stepDelayMs: number = TEST_STEP_DELAY_MS
): Promise<{ allPassed: boolean; results: { label: string; status: 'pass' | 'fail'; message: string }[] }> {
  const results: { label: string; status: 'pass' | 'fail'; message: string }[] = [];

  for (let i = 0; i < steps.length; i++) {
    onStepUpdate(i, 'running', 'Checking...');

    try {
      const passed = await Promise.resolve(steps[i].check());
      await sleep(stepDelayMs); // Minimum visible delay so it doesn't flash by

      if (passed) {
        onStepUpdate(i, 'pass', `${steps[i].label} OK`);
        results.push({ label: steps[i].label, status: 'pass', message: `${steps[i].label} OK` });
      } else {
        onStepUpdate(i, 'fail', `${steps[i].label} failed`);
        results.push({ label: steps[i].label, status: 'fail', message: `${steps[i].label} failed` });
      }
    } catch {
      await sleep(stepDelayMs);
      onStepUpdate(i, 'fail', `${steps[i].label} error`);
      results.push({ label: steps[i].label, status: 'fail', message: `${steps[i].label} error` });
    }
  }

  return { allPassed: results.every((r) => r.status === 'pass'), results };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
