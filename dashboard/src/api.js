const API_BASE = '/api/v1';

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

export async function fetchStats() {
  const res = await fetch(`${API_BASE}/stats`);
  return res.json();
}

export async function fetchStatsHistory(minutes = 5) {
  const res = await fetch(`${API_BASE}/stats/history?minutes=${minutes}`);
  return res.json();
}

export async function fetchAlerts(status) {
  const params = status ? `?status=${status}` : '';
  const res = await fetch(`${API_BASE}/alerts${params}`);
  return res.json();
}

export async function fetchTopTalkers(limit = 10) {
  const res = await fetch(`${API_BASE}/top-talkers?limit=${limit}`);
  return res.json();
}

export function createWebSocket(onMessage) {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    onMessage(data);
  };

  ws.onerror = () => {
    // Will reconnect via onclose
  };

  return ws;
}
