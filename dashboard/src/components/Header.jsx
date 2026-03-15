export default function Header({ health }) {
  return (
    <header className="header">
      <div className="header-left">
        <h1 className="header-title">NetShield</h1>
        <span className="header-subtitle">Network Traffic Analyzer</span>
      </div>
      <div className="header-right">
        <span className={`status-badge ${health?.status === 'healthy' ? 'status-healthy' : 'status-offline'}`}>
          {health?.status === 'healthy' ? 'Online' : 'Offline'}
        </span>
        <span className="header-meta">
          Mode: {health?.dpdk_mode || '—'} | Uptime: {formatUptime(health?.uptime_seconds)}
        </span>
      </div>
    </header>
  );
}

function formatUptime(seconds) {
  if (!seconds) return '—';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return `${h}h ${m}m ${s}s`;
}
