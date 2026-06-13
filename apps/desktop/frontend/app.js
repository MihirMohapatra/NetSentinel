const pageContainer = document.getElementById('page-container');

function navigate(page) {
  document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
  document.querySelector(`[data-page="${page}"]`).classList.add('active');
  switch (page) {
    case 'dashboard': renderDashboard(); break;
    case 'network': renderNetwork(); break;
    case 'alerts': renderAlerts(); break;
  }
}

document.querySelectorAll('.nav-links a').forEach(a => {
  a.addEventListener('click', e => { e.preventDefault(); navigate(a.dataset.page); });
});

async function invoke(cmd, args = {}) {
  if (window.__TAURI__) {
    return await window.__TAURI__.core.invoke(cmd, args);
  }
  return mockInvoke(cmd, args);
}

async function mockInvoke(cmd, args) {
  const mock = {
    get_status: { is_capturing: false, connections_seen: 0, alert_count: 0, uptime_secs: 0 },
    get_alerts: [],
    get_connections: [],
    get_dns_history: [],
    get_port_scan_candidates: [],
    start_capture: 'Capture started (mock)',
    stop_capture: 'Capture stopped (mock)',
  };
  return mock[cmd] ?? null;
}

navigate('dashboard');