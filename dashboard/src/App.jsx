import { useState, useEffect, useRef, useCallback } from 'react';
import Header from './components/Header';
import StatsCards from './components/StatsCards';
import ThroughputChart from './components/ThroughputChart';
import ProtocolChart from './components/ProtocolChart';
import AlertList from './components/AlertList';
import TopTalkers from './components/TopTalkers';
import {
  fetchHealth,
  fetchStats,
  fetchStatsHistory,
  fetchAlerts,
  fetchTopTalkers,
  createWebSocket,
} from './api';
import './App.css';

const POLL_INTERVAL = 2000;
const WS_RECONNECT_DELAY = 3000;

export default function App() {
  const [health, setHealth] = useState(null);
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState(null);
  const [alerts, setAlerts] = useState(null);
  const [topTalkers, setTopTalkers] = useState(null);
  const wsRef = useRef(null);
  const reconnectTimer = useRef(null);
  const connectRef = useRef(null);

  const connectWebSocket = useCallback(() => {
    if (wsRef.current) return;

    const ws = createWebSocket((msg) => {
      if (msg.type === 'stats_update') {
        setStats(msg.data);
      } else if (msg.type === 'new_alert' || msg.type === 'alert_resolved') {
        fetchAlerts('active').then(setAlerts).catch(() => {});
        fetchTopTalkers().then(setTopTalkers).catch(() => {});
      }
    });

    ws.onclose = () => {
      wsRef.current = null;
      reconnectTimer.current = setTimeout(() => connectRef.current?.(), WS_RECONNECT_DELAY);
    };

    wsRef.current = ws;
  }, []);

  useEffect(() => {
    connectRef.current = connectWebSocket;
  }, [connectWebSocket]);

  useEffect(() => {
    fetchHealth().then(setHealth).catch(() => {});
    fetchStats().then(setStats).catch(() => {});
    fetchStatsHistory().then(setHistory).catch(() => {});
    fetchAlerts('active').then(setAlerts).catch(() => {});
    fetchTopTalkers().then(setTopTalkers).catch(() => {});

    connectWebSocket();

    const interval = setInterval(() => {
      fetchHealth().then(setHealth).catch(() => {});
      fetchStatsHistory().then(setHistory).catch(() => {});
      fetchAlerts('active').then(setAlerts).catch(() => {});
      fetchTopTalkers().then(setTopTalkers).catch(() => {});
    }, POLL_INTERVAL);

    return () => {
      clearInterval(interval);
      clearTimeout(reconnectTimer.current);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connectWebSocket]);

  return (
    <div className="app">
      <Header health={health} />
      <main className="main">
        <StatsCards stats={stats} />
        <div className="charts-row">
          <ThroughputChart history={history} />
          <ProtocolChart stats={stats} />
        </div>
        <div className="tables-row">
          <AlertList alerts={alerts} />
          <TopTalkers topTalkers={topTalkers} />
        </div>
      </main>
      <footer className="footer">
        NetShield v{health?.version || '0.1.0'} — DPDK Network Traffic Analyzer POC
      </footer>
    </div>
  );
}
