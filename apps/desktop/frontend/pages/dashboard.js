async function renderDashboard() {
  const status = await invoke('get_status');
  const interfaceData = await invoke('list_interfaces');
  const interfaceOptions = interfaceData.interfaces.length
    ? interfaceData.interfaces.map(name => `<option value="${name}" ${status.selected_interface === name ? 'selected' : ''}>${name}</option>`).join('')
    : '<option value="">No interfaces found</option>';

  pageContainer.innerHTML = `
    <h1>Dashboard</h1>
    <div class="card-grid">
      <div class="card"><div class="stat-value" id="stat-status">${status.is_capturing ? 'Active' : 'Stopped'}</div><div class="stat-label">Capture Status</div></div>
      <div class="card"><div class="stat-value" id="stat-connections">${status.connections_seen}</div><div class="stat-label">Connections Seen</div></div>
      <div class="card"><div class="stat-value" id="stat-alerts">${status.alert_count}</div><div class="stat-label">Total Alerts</div></div>
      <div class="card"><div class="stat-value" id="stat-uptime">${status.uptime_secs}s</div><div class="stat-label">Uptime</div></div>
    </div>
    <div class="card">
      <h2>Controls</h2>
      <label class="field-label" for="interface-select">Network Interface</label>
      <select id="interface-select" class="select-input" ${status.is_capturing ? 'disabled' : ''}>
        ${interfaceOptions}
      </select>
      <div class="status-note">${status.last_message || 'Choose an interface, then start capture.'}</div>
      <button class="btn btn-success" id="btn-start" ${status.is_capturing ? 'disabled' : ''}>Start Capture</button>
      <button class="btn btn-danger" id="btn-stop" ${!status.is_capturing ? 'disabled' : ''}>Stop Capture</button>
    </div>
    <div class="card">
      <h2>Port Scan Candidates</h2>
      <div id="port-scan-list"><p class="empty">No port scans detected</p></div>
    </div>
  `;

  document.getElementById('interface-select')?.addEventListener('change', async event => {
    try {
      await invoke('select_interface', { interface: event.target.value });
      renderDashboard();
    } catch (error) {
      window.appState.showError(error);
    }
  });

  document.getElementById('btn-start')?.addEventListener('click', async () => {
    try {
      await invoke('start_capture');
      renderDashboard();
    } catch (error) {
      window.appState.showError(error);
    }
  });

  document.getElementById('btn-stop')?.addEventListener('click', async () => {
    try {
      await invoke('stop_capture');
      renderDashboard();
    } catch (error) {
      window.appState.showError(error);
    }
  });

  const scans = await invoke('get_port_scan_candidates');
  if (scans && scans.length > 0) {
    document.getElementById('port-scan-list').innerHTML = scans.map(scan => `<p>${scan}</p>`).join('');
  }

  window.appState.scheduleRefresh('dashboard', renderDashboard);
}
