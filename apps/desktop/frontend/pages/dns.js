async function renderDns() {
  const dnsHistory = await invoke('get_dns_history');
  const rows = dnsHistory.length
    ? dnsHistory.map(item => `
      <tr>
        <td>${item.domain}</td>
        <td>${item.resolver}</td>
        <td>${item.response_ips.length ? item.response_ips.join(', ') : '-'}</td>
        <td>${item.response_code ?? '-'}</td>
        <td>${item.risk_score}</td>
        <td>${item.risk_factors.length ? item.risk_factors.join('; ') : '-'}</td>
        <td>${new Date(item.timestamp).toLocaleString()}</td>
      </tr>
    `).join('')
    : '<tr><td colspan="7" class="empty">No DNS activity yet. Start capture and generate a DNS lookup.</td></tr>';

  pageContainer.innerHTML = `
    <h1>DNS Activity</h1>
    <div class="card">
      <h2>Observed DNS Queries</h2>
      <table>
        <thead><tr><th>Domain</th><th>Resolver</th><th>Response IPs</th><th>Code</th><th>Risk</th><th>Notes</th><th>Time</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;

  window.appState.scheduleRefresh('dns', renderDns);
}
