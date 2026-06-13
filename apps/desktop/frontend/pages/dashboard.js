async function renderDashboard() {
  const status = await invoke('get_status');
  pageContainer.innerHTML = `
    <h1>Dashboard</h1>
    <div class="card-grid">
      <div class="card"><div class="stat-value" id="stat-status">${status.is_capturing ? '🟢 Active' : '⏸ Stopped'}</div><div class="stat-label">Capture Status</div></div>
      <div class="card"><div class="stat-value" id="stat-connections">${status.connections_seen}</div><div class="stat-label">Connections Seen</div></div>
      <div class="card"><div class="stat-value" id="stat-alerts">${status.alert_count}</div><div class="stat-label">Total Alerts</div></div>
      <div class="card"><div class="stat-value" id="stat-uptime">${status.uptime_secs}s</div><div class="stat-label">Uptime</div></div>
    </div>
    <div class="card">
      <h2>Controls</h2>
      <button class="btn btn-success" id="btn-start" ${status.is_capturing ? 'disabled' : ''}>Start Capture</button>
      <button class="btn btn-danger" id="btn-stop" ${!status.is_capturing ? 'disabled' : ''}>Stop Capture</button>
    </div>
    <div class="card">
      <h2>Port Scan Candidates</h2>
      <div id="port-scan-list"><p class="empty">No port scans detected</p></div>
    </div>
  `;

  document.getElementById('btn-start')?.addEventListener('click', async () => {
    await invoke('start_capture');
    renderDashboard();
  });
  document.getElementById('btn-stop')?.addEventListener('click', async () => {
    await invoke('stop_capture');
    renderDashboard();
  });

  const scans = await invoke('get_port_scan_candidates');
  if (scans && scans.length > 0) {
    document.getElementById('port-scan-list').innerHTML = scans.map(s => `<p>⚠ ${s}</p>`).join('');
  }
}