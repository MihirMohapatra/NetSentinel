async function renderNetwork() {
  const connections = await invoke('get_connections');
  const rows = connections.length
    ? connections.map(c => `
      <tr>
        <td>${c.process_name || 'Unknown'}</td>
        <td>${c.source_ip}:${c.source_port}</td>
        <td>${c.destination_ip}:${c.destination_port}</td>
        <td>${c.protocol}</td>
        <td>${(c.packet_size || 0).toLocaleString()} B</td>
        <td>${new Date(c.timestamp).toLocaleTimeString()}</td>
      </tr>
    `).join('')
    : '<tr><td colspan="6" class="empty">No active connections. Start capture to begin monitoring.</td></tr>';

  pageContainer.innerHTML = `
    <h1>Network View</h1>
    <div class="card">
      <h2>Active Connections</h2>
      <table>
        <thead><tr><th>Process</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Size</th><th>Time</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;

  window.appState.scheduleRefresh('network', renderNetwork);
}
