export default function TopTalkers({ topTalkers }) {
  const items = topTalkers?.top_talkers || [];

  return (
    <div className="top-talkers">
      <h2 className="section-title">Top Talkers</h2>
      {items.length === 0 ? (
        <p className="empty-state">No significant traffic sources detected.</p>
      ) : (
        <div className="alert-table-wrapper">
          <table className="alert-table">
            <thead>
              <tr>
                <th>Source IP</th>
                <th>PPS</th>
                <th>Flagged</th>
              </tr>
            </thead>
            <tbody>
              {items.map((talker) => (
                <tr key={talker.source_ip}>
                  <td className="mono">{talker.source_ip}</td>
                  <td>{talker.packets_per_second.toFixed(0)}</td>
                  <td>
                    {talker.is_flagged ? (
                      <span className="severity-pill severity-high">Yes</span>
                    ) : (
                      <span className="severity-pill severity-low">No</span>
                    )}
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
