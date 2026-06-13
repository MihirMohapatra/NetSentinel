async function renderAlerts() {
  const alerts = await invoke('get_alerts');
  const rows = alerts.length
    ? alerts.map(a => {
        const severityClass = a.severity === 'CRITICAL' || a.severity === 'HIGH' ? 'badge-high' : a.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low';
        return `<tr>
          <td><span class="badge ${severityClass}">${a.severity}</span></td>
          <td>${a.title}</td>
          <td>${a.description}</td>
          <td>${a.process_name || '-'}</td>
          <td>${a.source_ip || '-'}</td>
          <td>${a.destination_ip || '-'}</td>
          <td>${a.port || '-'}</td>
          <td>${new Date(a.timestamp).toLocaleString()}</td>
        </tr>`;
      }).join('')
    : '<tr><td colspan="8" class="empty">No alerts yet.</td></tr>';

  pageContainer.innerHTML = `
    <h1>Alerts</h1>
    <div class="card">
      <table>
        <thead><tr><th>Severity</th><th>Title</th><th>Description</th><th>Process</th><th>Source</th><th>Destination</th><th>Port</th><th>Time</th></tr></thead>
        <tbody id="alert-rows">${rows}</tbody>
      </table>
    </div>
    <button class="btn btn-primary" id="btn-refresh">Refresh</button>
  `;

  document.getElementById('btn-refresh')?.addEventListener('click', renderAlerts);
}