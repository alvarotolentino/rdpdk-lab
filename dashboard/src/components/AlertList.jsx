const SEVERITY_CLASSES = {
  critical: 'severity-critical',
  high: 'severity-high',
  medium: 'severity-medium',
  low: 'severity-low',
};

export default function AlertList({ alerts }) {
  const items = alerts?.alerts || [];

  return (
    <div className="alert-list">
      <h2 className="section-title">
        Active Alerts
        {items.length > 0 && <span className="badge badge-danger">{items.length}</span>}
      </h2>
      {items.length === 0 ? (
        <p className="empty-state">No active alerts — traffic is normal.</p>
      ) : (
        <div className="alert-table-wrapper">
          <table className="alert-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Source IP</th>
                <th>PPS</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {items.map((alert) => (
                <tr key={alert.id}>
                  <td className="mono">{alert.id}</td>
                  <td>{formatAttackType(alert.attack_type)}</td>
                  <td>
                    <span className={`severity-pill ${SEVERITY_CLASSES[alert.severity] || ''}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td className="mono">{alert.source_ip}</td>
                  <td>{alert.packets_per_second.toFixed(0)}</td>
                  <td>
                    <span className={`status-pill ${alert.status === 'active' ? 'status-active' : 'status-resolved'}`}>
                      {alert.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function formatAttackType(type) {
  const map = {
    syn_flood: 'SYN Flood',
    udp_flood: 'UDP Flood',
    icmp_flood: 'ICMP Flood',
    dns_amplification: 'DNS Amplification',
  };
  return map[type] || type;
}
