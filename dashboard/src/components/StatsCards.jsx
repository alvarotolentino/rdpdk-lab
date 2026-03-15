export default function StatsCards({ stats }) {
  const cards = [
    {
      label: 'Total Packets',
      value: formatNumber(stats?.total_packets),
      unit: '',
    },
    {
      label: 'Packets/sec',
      value: formatNumber(stats?.packets_per_second, 1),
      unit: 'pps',
    },
    {
      label: 'Throughput',
      value: formatBytes(stats?.bytes_per_second),
      unit: '/s',
    },
    {
      label: 'Total Bytes',
      value: formatBytes(stats?.total_bytes),
      unit: '',
    },
  ];

  return (
    <div className="stats-cards">
      {cards.map((card) => (
        <div key={card.label} className="stats-card">
          <span className="stats-card-label">{card.label}</span>
          <span className="stats-card-value">
            {card.value}
            {card.unit && <span className="stats-card-unit">{card.unit}</span>}
          </span>
        </div>
      ))}
    </div>
  );
}

function formatNumber(n, decimals = 0) {
  if (n == null) return '—';
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
  return n.toFixed(decimals);
}

function formatBytes(bytes) {
  if (bytes == null) return '—';
  if (bytes >= 1_073_741_824) return (bytes / 1_073_741_824).toFixed(2) + ' GB';
  if (bytes >= 1_048_576) return (bytes / 1_048_576).toFixed(2) + ' MB';
  if (bytes >= 1_024) return (bytes / 1_024).toFixed(1) + ' KB';
  return bytes.toFixed(0) + ' B';
}
