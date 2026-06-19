const pageContainer = document.getElementById('page-container');
let currentPage = null;
let refreshTimer = null;

function navigate(page) {
  currentPage = page;
  if (refreshTimer) {
    clearTimeout(refreshTimer);
    refreshTimer = null;
  }

  document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
  document.querySelector(`[data-page="${page}"]`).classList.add('active');

  switch (page) {
    case 'dashboard':
      renderDashboard();
      break;
    case 'network':
      renderNetwork();
      break;
    case 'dns':
      renderDns();
      break;
    case 'alerts':
      renderAlerts();
      break;
  }
}

document.querySelectorAll('.nav-links a').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    navigate(a.dataset.page);
  });
});

async function invoke(cmd, args = {}) {
  if (window.__TAURI__) {
    return await window.__TAURI__.core.invoke(cmd, args);
  }
  return mockInvoke(cmd, args);
}

function scheduleRefresh(page, renderFn, delay = 2000) {
  if (refreshTimer) {
    clearTimeout(refreshTimer);
  }

  refreshTimer = setTimeout(() => {
    if (currentPage === page) {
      renderFn().catch(console.error);
    }
  }, delay);
}

function showError(error) {
  const message = typeof error === 'string'
    ? error
    : (error && error.message) ? error.message : String(error);
  window.alert(message);
}

async function mockInvoke(cmd, args) {
  const mock = {
    get_status: {
      is_capturing: false,
      connections_seen: 0,
      alert_count: 0,
      uptime_secs: 0,
      selected_interface: null,
      last_message: 'Mock mode'
    },
    get_alerts: [],
    get_connections: [],
    get_dns_history: [],
    get_port_scan_candidates: [],
    list_interfaces: { interfaces: ['Mock Adapter'], selected: 'Mock Adapter' },
    select_interface: 'Selected interface: Mock Adapter',
    start_capture: 'Capture started (mock)',
    stop_capture: 'Capture stopped (mock)',
  };
  return mock[cmd] ?? null;
}

window.appState = {
  invoke,
  scheduleRefresh,
  showError,
  getCurrentPage: () => currentPage,
};

navigate('dashboard');
