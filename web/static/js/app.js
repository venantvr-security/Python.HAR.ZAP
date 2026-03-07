// HAR-ZAP Web Interface

const API_BASE = '/api/v1';

// Status WebSocket
let statusWs = null;

function initStatusWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    statusWs = new WebSocket(`${protocol}//${window.location.host}/api/v1/ws/status`);

    statusWs.onmessage = (event) => {
        const data = JSON.parse(event.data);
        updateStatusBadges(data);
    };

    statusWs.onclose = () => {
        setTimeout(initStatusWebSocket, 5000);
    };
}

function updateStatusBadges(data) {
    const zapBadge = document.getElementById('zap-status');
    const torBadge = document.getElementById('tor-status');

    if (zapBadge) {
        zapBadge.className = `status-badge ${data.zap?.running ? 'online' : 'offline'}`;
    }

    if (torBadge) {
        torBadge.className = `status-badge ${data.tor?.connected ? 'online' : 'offline'}`;
    }
}

// API helpers
async function api(endpoint, options = {}) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
        headers: { 'Content-Type': 'application/json', ...options.headers },
        ...options
    });
    return response.json();
}

async function apiPost(endpoint, data = {}) {
    return api(endpoint, { method: 'POST', body: JSON.stringify(data) });
}

// ZAP controls
async function startZap() {
    const btn = event.target;
    btn.disabled = true;
    btn.textContent = 'Starting...';

    try {
        const result = await apiPost('/zap/start');
        if (result.status === 'started') {
            showAlert('success', 'ZAP started on ' + result.zap_url);
            location.reload();
        } else {
            showAlert('danger', result.message || 'Failed to start ZAP');
        }
    } catch (e) {
        showAlert('danger', e.message);
    } finally {
        btn.disabled = false;
        btn.textContent = 'Start ZAP';
    }
}

async function stopZap() {
    const btn = event.target;
    btn.disabled = true;

    try {
        await apiPost('/zap/stop');
        showAlert('success', 'ZAP stopped');
        location.reload();
    } catch (e) {
        showAlert('danger', e.message);
    }
}

// TOR controls
async function checkTorConnection() {
    const result = await api('/proxy/tor/status');
    return result;
}

async function newTorCircuit() {
    const btn = event.target;
    btn.disabled = true;
    btn.textContent = 'Changing...';

    try {
        const result = await apiPost('/proxy/tor/new-circuit');
        if (result.exit_ip) {
            showAlert('success', 'New IP: ' + result.exit_ip);
        } else {
            showAlert('warning', 'Circuit changed but IP unknown');
        }
    } catch (e) {
        showAlert('danger', e.message);
    } finally {
        btn.disabled = false;
        btn.textContent = 'New Circuit';
    }
}

async function enableTorInZap() {
    try {
        const result = await apiPost('/proxy/tor/enable');
        if (result.status === 'enabled') {
            showAlert('success', 'TOR enabled - Exit IP: ' + result.exit_ip);
        } else {
            showAlert('danger', 'Failed to enable TOR');
        }
    } catch (e) {
        showAlert('danger', e.message);
    }
}

async function disableTorInZap() {
    try {
        const result = await apiPost('/proxy/tor/disable');
        showAlert('success', 'TOR disabled in ZAP');
    } catch (e) {
        showAlert('danger', e.message);
    }
}

// Alerts
function showAlert(type, message) {
    const container = document.getElementById('alerts') || document.body;
    const alert = document.createElement('div');
    alert.className = 'alert alert-' + type;
    alert.textContent = message;
    container.prepend(alert);

    setTimeout(() => alert.remove(), 5000);
}

// Wizard - content is server-rendered, no innerHTML needed
let currentWizardStep = 0;

function wizardPrev() {
    if (currentWizardStep > 0) {
        window.location.href = '/wizard?step=' + (currentWizardStep - 1);
    }
}

function wizardNext() {
    window.location.href = '/wizard?step=' + (currentWizardStep + 1);
}

function setWizardStep(step) {
    currentWizardStep = step;
}

// Scan monitoring
function initScanWebSocket(scanId) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/api/v1/ws/scans/${scanId}`);

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        updateScanProgress(scanId, data);
    };

    return ws;
}

function updateScanProgress(scanId, data) {
    const progressBar = document.querySelector('#scan-' + scanId + ' .progress-bar');
    const statusText = document.querySelector('#scan-' + scanId + ' .scan-status');

    if (progressBar) {
        progressBar.style.width = data.progress + '%';
    }

    if (statusText) {
        statusText.textContent = data.state + ' - ' + data.progress + '%';
    }
}

// Init
document.addEventListener('DOMContentLoaded', () => {
    initStatusWebSocket();

    // Fetch initial status
    Promise.all([
        api('/zap/status').catch(() => ({ running: false })),
        api('/proxy/tor/status').catch(() => ({ connected: false }))
    ]).then(([zap, tor]) => {
        updateStatusBadges({ zap, tor });
    });
});
