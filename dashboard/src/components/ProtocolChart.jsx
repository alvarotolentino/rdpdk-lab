import { Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';

ChartJS.register(ArcElement, Tooltip, Legend);

export default function ProtocolChart({ stats }) {
  const dist = stats?.protocol_distribution;
  if (!dist) return null;

  const data = {
    labels: ['TCP', 'UDP', 'ICMP', 'Other'],
    datasets: [
      {
        data: [dist.tcp, dist.udp, dist.icmp, dist.other].map((v) =>
          +(v * 100).toFixed(1)
        ),
        backgroundColor: ['#3b82f6', '#f59e0b', '#10b981', '#64748b'],
        borderColor: '#1e293b',
        borderWidth: 2,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: { color: '#cbd5e1', padding: 16 },
      },
      tooltip: {
        callbacks: {
          label: (ctx) => `${ctx.label}: ${ctx.parsed}%`,
        },
      },
    },
  };

  return (
    <div className="chart-container">
      <h2 className="chart-title">Protocol Distribution</h2>
      <div className="chart-wrapper chart-wrapper-doughnut">
        <Doughnut data={data} options={options} />
      </div>
    </div>
  );
}
