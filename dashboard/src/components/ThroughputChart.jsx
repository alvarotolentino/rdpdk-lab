import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler);

export default function ThroughputChart({ history }) {
  const dataPoints = history?.data_points || [];
  const labels = dataPoints.map((_, i) => `-${dataPoints.length - i}s`);

  const data = {
    labels,
    datasets: [
      {
        label: 'Total PPS',
        data: dataPoints.map((d) => d.packets_per_second),
        borderColor: '#3b82f6',
        backgroundColor: 'rgba(59, 130, 246, 0.1)',
        fill: true,
        tension: 0.3,
        pointRadius: 0,
      },
      {
        label: 'TCP PPS',
        data: dataPoints.map((d) => d.tcp_pps),
        borderColor: '#10b981',
        backgroundColor: 'transparent',
        tension: 0.3,
        pointRadius: 0,
        borderDash: [4, 2],
      },
      {
        label: 'UDP PPS',
        data: dataPoints.map((d) => d.udp_pps),
        borderColor: '#f59e0b',
        backgroundColor: 'transparent',
        tension: 0.3,
        pointRadius: 0,
        borderDash: [4, 2],
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 300 },
    scales: {
      x: {
        grid: { color: 'rgba(255,255,255,0.05)' },
        ticks: { color: '#94a3b8', maxTicksLimit: 10 },
      },
      y: {
        grid: { color: 'rgba(255,255,255,0.05)' },
        ticks: { color: '#94a3b8' },
        beginAtZero: true,
      },
    },
    plugins: {
      legend: { labels: { color: '#cbd5e1' } },
      tooltip: { mode: 'index', intersect: false },
    },
  };

  return (
    <div className="chart-container">
      <h2 className="chart-title">Throughput (packets/sec)</h2>
      <div className="chart-wrapper">
        <Line data={data} options={options} />
      </div>
    </div>
  );
}
