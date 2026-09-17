/**
 * ARC Defender Dashboard — Main JavaScript
 * Comprehensive Traffic Intelligence, Threat Alerting, Filtering & GitHub Theme Support
 */

// ---- State ----
let currentTab = 'overview';
let timeRange = 24; // hours
const API = '/arc/api';
const charts = {}; // Store Chart instances for cleanup and theme refresh
let autoRefreshTimer = null;
let autoRefreshEnabled = true;

// Requests filter state
const requestFilters = {
    search: '',
    method: 'ALL',
    status_group: 'ALL',
    min_latency: 0,
    errors_only: false,
    login_only: false,
    slow_only: false,
    limit: 100,
    offset: 0
};

// Security filter state
const alertFilters = {
    severity: 'all',
    status: 'active'
};

// Cached data for client-side sub-filtering
let allTrafficEndpoints = [];
let allTrafficClients = [];
let currentMlFilter = 'anomalies';
let allMlResults = [];

// ---- Initialization ----
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    setupNavigation();
    setupControls();
    setupFiltering();
    setupAttackSimulator();
    startAutoRefresh();
    loadTab('overview');
});

// ---- Theme Management (GitHub Dark / Light Mode) ----
function initTheme() {
    const savedTheme = localStorage.getItem('arc-theme') || 
        (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    applyTheme(savedTheme);

    const themeToggleBtn = document.getElementById('btn-theme-toggle');
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
            const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
            applyTheme(nextTheme);
        });
    }
}

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('arc-theme', theme);
    const icon = document.getElementById('theme-icon');
    if (icon) {
        icon.textContent = theme === 'dark' ? '☀️' : '🌙';
    }
    updateChartTheme();
}

function isDarkMode() {
    return document.documentElement.getAttribute('data-theme') !== 'light';
}

function getThemeColors() {
    const dark = isDarkMode();
    return {
        grid: dark ? '#21262d' : '#e1e4e8',
        text: dark ? '#8b949e' : '#586069',
        primary: dark ? '#58a6ff' : '#0969da',
        primaryLight: dark ? 'rgba(88, 166, 255, 0.2)' : 'rgba(9, 105, 218, 0.15)',
        secondary: dark ? '#79c0ff' : '#0550ae',
        danger: dark ? '#f85149' : '#cf222e',
        dangerLight: dark ? 'rgba(248, 81, 73, 0.25)' : 'rgba(207, 34, 46, 0.15)',
        warning: dark ? '#d29922' : '#9a6700',
        success: dark ? '#3fb950' : '#1a7f37',
        info: dark ? '#388bfd' : '#218bff',
        surface: dark ? '#161b22' : '#ffffff',
        border: dark ? '#30363d' : '#d0d7de'
    };
}

function updateChartTheme() {
    if (typeof Chart === 'undefined') return;
    const colors = getThemeColors();
    Chart.defaults.color = colors.text;
    Chart.defaults.borderColor = colors.grid;
    Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';

    // Re-render charts on active tab if they exist
    Object.keys(charts).forEach(canvasId => {
        const chart = charts[canvasId];
        if (chart && chart.options && chart.options.scales) {
            Object.values(chart.options.scales).forEach(scale => {
                if (scale.grid) scale.grid.color = colors.grid;
                if (scale.ticks) scale.ticks.color = colors.text;
            });
            chart.update();
        }
    });
}

// ---- Auto Refresh ----
function startAutoRefresh() {
    if (autoRefreshTimer) clearInterval(autoRefreshTimer);
    autoRefreshTimer = setInterval(() => {
        if (autoRefreshEnabled) {
            loadTab(currentTab, true);
        }
    }, 10000);
}

function toggleAutoRefresh() {
    autoRefreshEnabled = !autoRefreshEnabled;
    const stateEl = document.getElementById('refresh-state');
    if (stateEl) {
        stateEl.textContent = autoRefreshEnabled ? 'Auto: ON' : 'Auto: PAUSED';
    }
    showToast(autoRefreshEnabled ? 'Auto-refresh enabled (10s)' : 'Auto-refresh paused', 'info');
}

// ---- Navigation ----
function setupNavigation() {
    document.querySelectorAll('.nav button').forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            loadTab(tab);
        });
    });

    const viewSecBtn = document.getElementById('banner-view-security-btn');
    if (viewSecBtn) {
        viewSecBtn.addEventListener('click', () => loadTab('security'));
    }

    const viewTrafficBtn = document.getElementById('overview-view-traffic-btn');
    if (viewTrafficBtn) {
        viewTrafficBtn.addEventListener('click', () => loadTab('traffic'));
    }
}

function loadTab(tab, isAutoRefresh = false) {
    currentTab = tab;
    if (!isAutoRefresh) {
        document.querySelectorAll('.nav button').forEach(b => b.classList.remove('active'));
        const activeNavBtn = document.getElementById(`nav-btn-${tab}`);
        if (activeNavBtn) activeNavBtn.classList.add('active');

        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        const tabEl = document.getElementById(`tab-${tab}`);
        if (tabEl) tabEl.classList.add('active');
    }

    // Always fetch latest threat status in parallel to keep header & badge fresh
    fetchThreatStatus();

    switch (tab) {
        case 'overview': loadOverview(); break;
        case 'traffic': loadTraffic(); break;
        case 'security': loadSecurity(); break;
        case 'requests': loadRequests(); break;
        case 'integration': loadIntegration(); break;
    }
}

// ---- Controls Setup ----
function setupControls() {
    const select = document.getElementById('time-range');
    if (select) {
        select.addEventListener('change', () => {
            timeRange = parseInt(select.value);
            loadTab(currentTab);
        });
    }

    const detectBtn = document.getElementById('btn-detect');
    if (detectBtn) detectBtn.addEventListener('click', runDetection);

    const secDetectBtn = document.getElementById('btn-security-detect');
    if (secDetectBtn) secDetectBtn.addEventListener('click', runDetection);

    const mlBtn = document.getElementById('btn-ml');
    if (mlBtn) mlBtn.addEventListener('click', runML);

    const trainMlBtn = document.getElementById('btn-train-ml');
    if (trainMlBtn) trainMlBtn.addEventListener('click', runML);

    const refreshBtn = document.getElementById('btn-refresh-toggle');
    if (refreshBtn) refreshBtn.addEventListener('click', toggleAutoRefresh);

    const ackAllOverviewBtn = document.getElementById('overview-ack-all-btn');
    if (ackAllOverviewBtn) ackAllOverviewBtn.addEventListener('click', acknowledgeAllAlerts);

    const ackAllSecBtn = document.getElementById('btn-security-ack-all');
    if (ackAllSecBtn) ackAllSecBtn.addEventListener('click', acknowledgeAllAlerts);

    const clearAlertsBtn = document.getElementById('btn-security-clear');
    if (clearAlertsBtn) clearAlertsBtn.addEventListener('click', clearAllAlerts);
}

// ---- Threat Alerting & Status ----
async function fetchThreatStatus() {
    try {
        const status = await api('/security/threat-status');
        if (status) updateThreatUI(status);
    } catch (e) {
        console.warn('Threat status telemetry updating:', e?.message || e);
    }
}

function updateThreatUI(status) {
    const indicator = document.getElementById('header-threat-indicator');
    const text = document.getElementById('header-threat-text');
    const badge = document.getElementById('nav-alert-badge');
    const secBadge = document.getElementById('security-threat-badge');

    const level = status.threat_level || 'NORMAL';
    if (indicator) {
        indicator.className = `threat-indicator-pill threat-${level.toLowerCase()}`;
    }
    if (text) {
        text.textContent = `Threat: ${level}`;
    }

    if (badge) {
        const count = status.active_alert_count || 0;
        badge.textContent = count;
        if (count > 0) {
            badge.classList.remove('hidden');
        } else {
            badge.classList.add('hidden');
        }
    }

    if (secBadge) {
        secBadge.textContent = `${level} (${status.active_alert_count} active)`;
        secBadge.className = `badge badge-${level === 'CRITICAL' ? 'critical' : level === 'ELEVATED' ? 'warning' : 'success'}`;
    }

    // Overview Banner
    const banner = document.getElementById('overview-threat-banner');
    const bannerTitle = document.getElementById('banner-threat-title');
    const bannerDesc = document.getElementById('banner-threat-desc');

    if (banner && bannerTitle && bannerDesc) {
        banner.className = `threat-alert-banner banner-${level.toLowerCase()}`;
        if (level === 'CRITICAL') {
            bannerTitle.textContent = `🚨 Critical Threat Level: ${status.critical_count} High-Risk Alert(s)`;
            bannerDesc.textContent = status.status_message;
        } else if (level === 'ELEVATED') {
            bannerTitle.textContent = `⚠️ Elevated Threat Activity: ${status.active_alert_count} Active Security Alert(s)`;
            bannerDesc.textContent = status.status_message;
        } else {
            bannerTitle.textContent = '🟢 Threat Status: NORMAL';
            bannerDesc.textContent = 'System traffic is normal. No active high-risk attacks detected.';
        }
    }

    const alertStat = document.getElementById('stat-alerts');
    if (alertStat) {
        alertStat.textContent = status.active_alert_count.toLocaleString();
        alertStat.className = `value ${status.active_alert_count > 0 ? 'danger' : 'success'}`;
    }

    const alertCountIndicator = document.getElementById('alert-count-indicator');
    if (alertCountIndicator) {
        alertCountIndicator.textContent = `Active alerts: ${status.active_alert_count} | Total: ${status.total_alert_count}`;
    }
}

// ---- Attack Simulation ----
function setupAttackSimulator() {
    const btnSimulate = document.getElementById('btn-simulate');
    const select = document.getElementById('simulate-attack-select');

    if (btnSimulate && select) {
        btnSimulate.addEventListener('click', async () => {
            const attackType = select.value;
            if (!attackType) {
                showToast('Select an attack type from the dropdown first', 'warning');
                return;
            }

            btnSimulate.disabled = true;
            btnSimulate.textContent = 'Injecting...';

            try {
                const resp = await fetch(`${API}/simulator/simulate`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ type: attackType })
                });
                const data = await resp.json();

                showToast(`⚡ ${data.message}`, data.type === 'normal' ? 'info' : 'error');

                // Instantly refresh threat status and active tab
                await fetchThreatStatus();
                loadTab(currentTab);
            } catch (err) {
                showToast(`Simulation failed: ${err.message}`, 'error');
            } finally {
                btnSimulate.disabled = false;
                btnSimulate.textContent = 'Simulate';
            }
        });
    }
}

// ---- Traffic Filtering Setup ----
function setupFiltering() {
    // Requests search input with debounce
    const searchInput = document.getElementById('filter-req-search');
    let debounceTimer = null;
    if (searchInput) {
        searchInput.addEventListener('input', () => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => {
                requestFilters.search = searchInput.value;
                requestFilters.offset = 0;
                loadRequests();
            }, 300);
        });
    }

    // Method filter
    const methodSelect = document.getElementById('filter-req-method');
    if (methodSelect) {
        methodSelect.addEventListener('change', () => {
            requestFilters.method = methodSelect.value;
            requestFilters.offset = 0;
            loadRequests();
        });
    }

    // Status group filter
    const statusSelect = document.getElementById('filter-req-status');
    if (statusSelect) {
        statusSelect.addEventListener('change', () => {
            requestFilters.status_group = statusSelect.value;
            requestFilters.offset = 0;
            loadRequests();
        });
    }

    // Min latency filter
    const latencySelect = document.getElementById('filter-req-latency');
    if (latencySelect) {
        latencySelect.addEventListener('change', () => {
            requestFilters.min_latency = parseFloat(latencySelect.value) || 0;
            requestFilters.offset = 0;
            loadRequests();
        });
    }

    // Quick filter chips
    const chipErrors = document.getElementById('chip-errors');
    if (chipErrors) {
        chipErrors.addEventListener('click', () => {
            requestFilters.errors_only = !requestFilters.errors_only;
            chipErrors.classList.toggle('active', requestFilters.errors_only);
            requestFilters.offset = 0;
            loadRequests();
        });
    }

    const chipLogin = document.getElementById('chip-login');
    if (chipLogin) {
        chipLogin.addEventListener('click', () => {
            requestFilters.login_only = !requestFilters.login_only;
            chipLogin.classList.toggle('active', requestFilters.login_only);
            if (requestFilters.login_only) {
                requestFilters.search = '/api/login';
                if (searchInput) searchInput.value = '/api/login';
            } else {
                requestFilters.search = '';
                if (searchInput) searchInput.value = '';
            }
            requestFilters.offset = 0;
            loadRequests();
        });
    }

    const chipSlow = document.getElementById('chip-slow');
    if (chipSlow) {
        chipSlow.addEventListener('click', () => {
            requestFilters.slow_only = !requestFilters.slow_only;
            chipSlow.classList.toggle('active', requestFilters.slow_only);
            requestFilters.min_latency = requestFilters.slow_only ? 100 : 0;
            if (latencySelect) latencySelect.value = requestFilters.slow_only ? '100' : '0';
            requestFilters.offset = 0;
            loadRequests();
        });
    }

    const chipPost = document.getElementById('chip-post');
    if (chipPost) {
        chipPost.addEventListener('click', () => {
            if (requestFilters.method === 'POST') {
                requestFilters.method = 'ALL';
                chipPost.classList.remove('active');
                if (methodSelect) methodSelect.value = 'ALL';
            } else {
                requestFilters.method = 'POST';
                chipPost.classList.add('active');
                if (methodSelect) methodSelect.value = 'POST';
            }
            requestFilters.offset = 0;
            loadRequests();
        });
    }

    // Clear filters button
    const clearBtn = document.getElementById('btn-clear-filters');
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            requestFilters.search = '';
            requestFilters.method = 'ALL';
            requestFilters.status_group = 'ALL';
            requestFilters.min_latency = 0;
            requestFilters.errors_only = false;
            requestFilters.login_only = false;
            requestFilters.slow_only = false;
            requestFilters.offset = 0;

            if (searchInput) searchInput.value = '';
            if (methodSelect) methodSelect.value = 'ALL';
            if (statusSelect) statusSelect.value = 'ALL';
            if (latencySelect) latencySelect.value = '0';

            document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
            loadRequests();
        });
    }

    // Security alert filters
    const alertSev = document.getElementById('filter-alert-severity');
    if (alertSev) {
        alertSev.addEventListener('change', () => {
            alertFilters.severity = alertSev.value;
            loadSecurity();
        });
    }

    const alertStatus = document.getElementById('filter-alert-status');
    if (alertStatus) {
        alertStatus.addEventListener('change', () => {
            alertFilters.status = alertStatus.value;
            loadSecurity();
        });
    }

    // Traffic Tab client-side filters
    const epFilter = document.getElementById('filter-endpoint-input');
    if (epFilter) {
        epFilter.addEventListener('input', () => {
            renderTrafficEndpoints(epFilter.value.trim().toLowerCase());
        });
    }

    const clFilter = document.getElementById('filter-client-input');
    if (clFilter) {
        clFilter.addEventListener('input', () => {
            renderTrafficClients(clFilter.value.trim().toLowerCase());
        });
    }

    // ML Tab filter chips
    const chipAnomalies = document.getElementById('ml-chip-anomalies');
    const chipAll = document.getElementById('ml-chip-all');
    if (chipAnomalies && chipAll) {
        chipAnomalies.addEventListener('click', () => {
            currentMlFilter = 'anomalies';
            chipAnomalies.classList.add('active');
            chipAll.classList.remove('active');
            renderMlResultsTable();
        });
        chipAll.addEventListener('click', () => {
            currentMlFilter = 'all';
            chipAll.classList.add('active');
            chipAnomalies.classList.remove('active');
            renderMlResultsTable();
        });
    }
}

// ---- API Helpers with Resilient Auto-Retry & Fallback ----
async function api(path, retries = 2, delayMs = 350) {
    const sep = path.includes('?') ? '&' : '?';
    const primaryUrl = `${API}${path}${sep}hours=${timeRange}`;
    const fallbackUrl = `/arc-api${path}${sep}hours=${timeRange}`;

    for (let attempt = 0; attempt <= retries; attempt++) {
        try {
            const urlToUse = attempt > 0 ? fallbackUrl : primaryUrl;
            const resp = await fetch(urlToUse);
            if (!resp.ok) {
                if (attempt < retries) {
                    await new Promise(r => setTimeout(r, delayMs * (attempt + 1)));
                    continue;
                }
                throw new Error(`HTTP ${resp.status}`);
            }
            return await resp.json();
        } catch (err) {
            if (attempt < retries) {
                await new Promise(r => setTimeout(r, delayMs * (attempt + 1)));
                continue;
            }
            throw err;
        }
    }
}

async function apiPost(path, body = {}, retries = 1, delayMs = 350) {
    const sep = path.includes('?') ? '&' : '?';
    const primaryUrl = `${API}${path}${sep}hours=${timeRange}`;
    const fallbackUrl = `/arc-api${path}${sep}hours=${timeRange}`;

    for (let attempt = 0; attempt <= retries; attempt++) {
        try {
            const urlToUse = attempt > 0 ? fallbackUrl : primaryUrl;
            const resp = await fetch(urlToUse, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            if (!resp.ok) {
                if (attempt < retries) {
                    await new Promise(r => setTimeout(r, delayMs * (attempt + 1)));
                    continue;
                }
                throw new Error(`HTTP ${resp.status}`);
            }
            return await resp.json();
        } catch (err) {
            if (attempt < retries) {
                await new Promise(r => setTimeout(r, delayMs * (attempt + 1)));
                continue;
            }
            throw err;
        }
    }
}

// ---- Chart Helpers ----
function destroyChart(id) {
    if (charts[id]) {
        charts[id].destroy();
        delete charts[id];
    }
}

function makeChart(canvasId, config) {
    destroyChart(canvasId);
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    if (typeof Chart === 'undefined') {
        console.warn(`Chart.js runtime unavailable for canvas #${canvasId}`);
        return null;
    }

    // Apply GitHub theme colors
    const colors = getThemeColors();
    if (!config.options) config.options = {};
    if (!config.options.plugins) config.options.plugins = {};

    charts[canvasId] = new Chart(ctx, config);
    return charts[canvasId];
}

const PALETTE = ['#58a6ff', '#3fb950', '#d29922', '#f85149', '#bc8cff', '#39c5bb', '#f0883e', '#8b949e'];

function statusClass(code) {
    if (code >= 500) return 'status-5xx';
    if (code >= 400) return 'status-4xx';
    if (code >= 300) return 'status-3xx';
    return 'status-2xx';
}

function methodBadge(method) {
    const m = (method || 'GET').toUpperCase();
    return `<span class="badge badge-${m.toLowerCase()}">${m}</span>`;
}

function severityBadge(sev) {
    const s = (sev || 'medium').toLowerCase();
    return `<span class="badge badge-${s}">${s.toUpperCase()}</span>`;
}

function formatTime(iso) {
    if (!iso) return '-';
    const d = new Date(iso + (iso.endsWith('Z') ? '' : 'Z'));
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + 
        ' ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

function formatMs(ms) {
    if (ms == null) return '-';
    return ms < 1 ? '<1ms' : Math.round(ms) + 'ms';
}

function riskColor(score) {
    if (score >= 60) return 'risk-high';
    if (score >= 30) return 'risk-medium';
    return 'risk-low';
}

// ---- Overview Tab ----
async function loadOverview() {
    try {
        const [stats, timeline, endpoints, statusCodes, alerts] = await Promise.all([
            api('/overview'),
            api('/overview/requests-over-time'),
            api('/traffic/endpoints?limit=5'),
            api('/traffic/status-codes'),
            api('/security/alerts?limit=6&status=active'),
        ]);

        const colors = getThemeColors();

        // Stat cards
        document.getElementById('stat-requests').textContent = stats.total_requests.toLocaleString();
        document.getElementById('stat-clients').textContent = stats.unique_clients.toLocaleString();
        const errorRate = stats.total_requests > 0 ? ((stats.total_errors / stats.total_requests) * 100).toFixed(1) : '0.0';
        document.getElementById('stat-errors').innerHTML = `${stats.total_errors.toLocaleString()} <span class="text-small text-muted" style="font-weight:normal;">(${errorRate}%)</span>`;
        document.getElementById('stat-avg-time').textContent = formatMs(stats.avg_response_time);

        // Timeline chart (Requests + Errors)
        makeChart('chart-timeline', {
            type: 'line',
            data: {
                labels: timeline.map(r => {
                    const d = new Date(r.bucket);
                    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                }),
                datasets: [
                    {
                        label: 'Requests',
                        data: timeline.map(r => r.count),
                        borderColor: colors.primary,
                        backgroundColor: colors.primaryLight,
                        fill: true,
                        tension: 0.25,
                        pointRadius: 2,
                        pointHoverRadius: 5,
                    },
                    {
                        label: 'Errors',
                        data: timeline.map(r => r.errors || 0),
                        borderColor: colors.danger,
                        backgroundColor: colors.dangerLight,
                        fill: true,
                        tension: 0.25,
                        pointRadius: 2,
                        pointHoverRadius: 5,
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: { display: true, position: 'top', labels: { boxWidth: 10, usePointStyle: true } }
                },
                scales: {
                    y: { beginAtZero: true, grid: { color: colors.grid }, ticks: { color: colors.text } },
                    x: { grid: { display: false }, ticks: { color: colors.text, maxTicksLimit: 10 } }
                }
            }
        });

        // Status code doughnut
        makeChart('chart-status-overview', {
            type: 'doughnut',
            data: {
                labels: statusCodes.map(r => `HTTP ${r.status_code}`),
                datasets: [{
                    data: statusCodes.map(r => r.count),
                    backgroundColor: statusCodes.map(r => {
                        if (r.status_code >= 500) return colors.danger;
                        if (r.status_code >= 400) return colors.warning;
                        if (r.status_code >= 300) return colors.info;
                        return colors.success;
                    }),
                    borderWidth: 1,
                    borderColor: colors.surface
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '68%',
                plugins: {
                    legend: { position: 'right', labels: { boxWidth: 12, usePointStyle: true, color: colors.text } }
                }
            }
        });

        // Top endpoints table
        const epBody = document.getElementById('table-top-endpoints');
        epBody.innerHTML = endpoints.length === 0
            ? '<tr><td colspan="4" class="text-muted">No endpoint activity</td></tr>'
            : endpoints.map(e => `<tr>
                <td class="mono"><strong>${e.path}</strong></td>
                <td>${e.count.toLocaleString()}</td>
                <td>${formatMs(e.avg_response_time)}</td>
                <td><span class="${e.error_rate > 0.05 ? 'status-5xx' : ''}">${(e.error_rate * 100).toFixed(1)}%</span></td>
            </tr>`).join('');

        // Recent alerts
        const alertBody = document.getElementById('table-recent-alerts');
        alertBody.innerHTML = alerts.length === 0
            ? '<tr><td colspan="5" class="text-muted">No active threats detected 🎉</td></tr>'
            : alerts.map(a => `<tr>
                <td class="text-small">${formatTime(a.timestamp)}</td>
                <td>${severityBadge(a.severity)}</td>
                <td><strong>${a.alert_type}</strong></td>
                <td class="mono clickable" onclick="showClientDetail('${a.ip}')">${a.ip || 'system'}</td>
                <td>
                    <button class="btn-sm btn-outline" onclick="acknowledgeAlert(${a.id}, event)">Dismiss</button>
                </td>
            </tr>`).join('');
    } catch (err) {
        console.warn('Overview telemetry syncing:', err?.message || err);
        // Automatically schedule recovery attempt after 1.5s
        setTimeout(() => {
            if (currentTab === 'overview') loadOverview();
        }, 1500);
    }
}

// ---- Traffic Tab & Visualizations ----
async function loadTraffic() {
    try {
        const [timeline, endpoints, methods, statusCodes, latency, clients, errors] = await Promise.all([
            api('/overview/requests-over-time'),
            api('/traffic/endpoints?limit=30'),
            api('/traffic/methods'),
            api('/traffic/status-codes'),
            api('/traffic/latency'),
            api('/traffic/clients?limit=30'),
            api('/traffic/errors'),
        ]);

        allTrafficEndpoints = endpoints;
        allTrafficClients = clients;
        const colors = getThemeColors();

        // 1. Traffic Volume & Latency Dual Timeline Chart
        makeChart('chart-traffic-timeline', {
            type: 'bar',
            data: {
                labels: timeline.map(r => {
                    const d = new Date(r.bucket);
                    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                }),
                datasets: [
                    {
                        type: 'bar',
                        label: 'Request Volume',
                        data: timeline.map(r => r.count),
                        backgroundColor: colors.primaryLight,
                        borderColor: colors.primary,
                        borderWidth: 1,
                        yAxisID: 'y'
                    },
                    {
                        type: 'line',
                        label: 'Avg Response Latency (ms)',
                        data: timeline.map(r => r.avg_latency || 0),
                        borderColor: colors.warning,
                        backgroundColor: 'transparent',
                        borderWidth: 2,
                        tension: 0.3,
                        pointRadius: 2,
                        yAxisID: 'y1'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: { display: true, position: 'top', labels: { boxWidth: 10, usePointStyle: true } }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: { display: true, text: 'Requests', color: colors.text },
                        grid: { color: colors.grid },
                        ticks: { color: colors.text }
                    },
                    y1: {
                        beginAtZero: true,
                        position: 'right',
                        title: { display: true, text: 'Latency (ms)', color: colors.text },
                        grid: { display: false },
                        ticks: { color: colors.text }
                    },
                    x: { grid: { display: false }, ticks: { color: colors.text, maxTicksLimit: 12 } }
                }
            }
        });

        // 2. Top Endpoints Horizontal Bar Chart
        const top10 = endpoints.slice(0, 10);
        makeChart('chart-endpoints-bar', {
            type: 'bar',
            data: {
                labels: top10.map(e => e.path.length > 25 ? e.path.slice(0, 23) + '..' : e.path),
                datasets: [{
                    label: 'Requests',
                    data: top10.map(e => e.count),
                    backgroundColor: colors.primaryLight,
                    borderColor: colors.primary,
                    borderWidth: 1,
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { beginAtZero: true, grid: { color: colors.grid }, ticks: { color: colors.text } },
                    y: { grid: { display: false }, ticks: { color: colors.text, font: { family: 'monospace' } } }
                }
            }
        });

        // 3. Latency Distribution Histogram Chart
        if (latency.distribution && latency.distribution.length > 0) {
            makeChart('chart-latency', {
                type: 'bar',
                data: {
                    labels: latency.distribution.map(d => d.bucket_label),
                    datasets: [{
                        label: 'Requests',
                        data: latency.distribution.map(d => d.count),
                        backgroundColor: colors.secondary,
                        borderRadius: 3
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { beginAtZero: true, grid: { color: colors.grid }, ticks: { color: colors.text } },
                        x: { grid: { display: false }, ticks: { color: colors.text } }
                    }
                }
            });
        }

        // 4. HTTP Methods Distribution Chart
        makeChart('chart-methods', {
            type: 'doughnut',
            data: {
                labels: methods.map(m => m.method),
                datasets: [{
                    data: methods.map(m => m.count),
                    backgroundColor: methods.map((_, i) => PALETTE[i % PALETTE.length]),
                    borderColor: colors.surface,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'right', labels: { boxWidth: 10, usePointStyle: true, color: colors.text } }
                }
            }
        });

        // 5. Status Codes Distribution Chart
        makeChart('chart-status-traffic', {
            type: 'bar',
            data: {
                labels: statusCodes.map(s => `HTTP ${s.status_code}`),
                datasets: [{
                    label: 'Count',
                    data: statusCodes.map(s => s.count),
                    backgroundColor: statusCodes.map(s => {
                        if (s.status_code >= 500) return colors.danger;
                        if (s.status_code >= 400) return colors.warning;
                        if (s.status_code >= 300) return colors.info;
                        return colors.success;
                    }),
                    borderRadius: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, grid: { color: colors.grid }, ticks: { color: colors.text } },
                    x: { grid: { display: false }, ticks: { color: colors.text } }
                }
            }
        });

        // Latency Percentile Cards
        document.getElementById('latency-avg').textContent = formatMs(latency.avg);
        document.getElementById('latency-p50').textContent = formatMs(latency.p50);
        document.getElementById('latency-p95').textContent = formatMs(latency.p95);
        document.getElementById('latency-p99').textContent = formatMs(latency.p99);

        // Render Tables
        renderTrafficEndpoints();
        renderTrafficClients();

        // Error Breakdown
        document.getElementById('error-4xx').textContent = errors.four_xx_count.toLocaleString();
        document.getElementById('error-5xx').textContent = errors.five_xx_count.toLocaleString();

        const errCommon = document.getElementById('table-common-errors');
        errCommon.innerHTML = errors.common_errors.length === 0
            ? '<tr><td colspan="2" class="text-muted">No errors logged</td></tr>'
            : errors.common_errors.map(e => `<tr>
                <td class="${statusClass(e.status_code)}">HTTP ${e.status_code}</td>
                <td><strong>${e.count.toLocaleString()}</strong></td>
            </tr>`).join('');
    } catch (err) {
        console.warn('Traffic telemetry syncing:', err?.message || err);
        setTimeout(() => {
            if (currentTab === 'traffic') loadTraffic();
        }, 1500);
    }
}

function renderTrafficEndpoints(filterQuery = '') {
    const epBody = document.getElementById('table-traffic-endpoints');
    if (!epBody) return;

    let list = allTrafficEndpoints;
    if (filterQuery) {
        list = list.filter(e => e.path.toLowerCase().includes(filterQuery));
    }

    epBody.innerHTML = list.length === 0
        ? '<tr><td colspan="4" class="text-muted">No matching endpoints</td></tr>'
        : list.map(e => `<tr>
            <td class="mono"><strong>${e.path}</strong></td>
            <td>${e.count.toLocaleString()}</td>
            <td>${formatMs(e.avg_response_time)}</td>
            <td><span class="${e.error_rate > 0.05 ? 'status-5xx' : ''}">${(e.error_rate * 100).toFixed(1)}%</span></td>
        </tr>`).join('');
}

function renderTrafficClients(filterQuery = '') {
    const clBody = document.getElementById('table-traffic-clients');
    if (!clBody) return;

    let list = allTrafficClients;
    if (filterQuery) {
        list = list.filter(c => c.ip.toLowerCase().includes(filterQuery) || (c.user_agent && c.user_agent.toLowerCase().includes(filterQuery)));
    }

    clBody.innerHTML = list.length === 0
        ? '<tr><td colspan="4" class="text-muted">No matching clients</td></tr>'
        : list.map(c => `<tr class="clickable" onclick="showClientDetail('${c.ip}')">
            <td class="mono">${c.ip}</td>
            <td>${c.count.toLocaleString()}</td>
            <td class="text-small">${formatTime(c.last_seen)}</td>
            <td class="text-small" style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${c.user_agent || '-'}</td>
        </tr>`).join('');
}

// ---- Security Tab & Threat Management ----
async function loadSecurity() {
    try {
        const queryParams = new URLSearchParams();
        if (alertFilters.severity && alertFilters.severity !== 'all') {
            queryParams.set('severity', alertFilters.severity);
        }
        if (alertFilters.status && alertFilters.status !== 'all') {
            queryParams.set('status', alertFilters.status);
        }

        const [alerts, suspicious, mlStatus, mlResults] = await Promise.all([
            api(`/security/alerts?${queryParams.toString()}`),
            api('/security/suspicious-clients'),
            api('/ml/status'),
            api('/ml/results'),
        ]);

        // Alerts Table
        const aBody = document.getElementById('table-security-alerts');
        aBody.innerHTML = alerts.length === 0
            ? '<tr><td colspan="7" class="text-muted">No alerts matching filter criteria</td></tr>'
            : alerts.map(a => `<tr class="${a.acknowledged ? 'alert-acknowledged' : ''}">
                <td class="text-small">${formatTime(a.timestamp)}</td>
                <td>${severityBadge(a.severity)}</td>
                <td><strong>${a.alert_type}</strong></td>
                <td class="mono clickable" onclick="showClientDetail('${a.ip}')">
                    <span style="color:var(--primary);text-decoration:underline;">${a.ip || 'system'}</span>
                </td>
                <td class="text-small">${a.description || '-'}</td>
                <td>
                    ${a.acknowledged 
                        ? '<span class="badge" style="background:var(--surface-secondary);color:var(--text-secondary);border:1px solid var(--border)">Resolved</span>' 
                        : '<span class="badge badge-danger">Active</span>'}
                </td>
                <td>
                    <div style="display:flex;gap:6px;">
                        ${!a.acknowledged 
                            ? `<button class="btn-sm btn-outline" onclick="acknowledgeAlert(${a.id}, event)">Acknowledge</button>` 
                            : `<button class="btn-sm btn-outline" disabled>Acknowledged</button>`}
                        ${a.ip ? `<button class="btn-sm" onclick="showClientDetail('${a.ip}')">Investigate</button>` : ''}
                    </div>
                </td>
            </tr>`).join('');

        // Suspicious Clients Table
        const sBody = document.getElementById('table-suspicious-clients');
        sBody.innerHTML = suspicious.length === 0
            ? '<tr><td colspan="7" class="text-muted">No suspicious clients currently detected</td></tr>'
            : suspicious.map(s => `<tr class="clickable" onclick="showClientDetail('${s.ip}')">
                <td class="mono"><strong>${s.ip}</strong></td>
                <td>${s.alert_count}</td>
                <td>${s.alert_types}</td>
                <td>${renderStageBadge(s.kill_chain)}</td>
                <td>
                    <div style="display:flex;align-items:center;gap:8px;">
                        <strong style="width:28px;">${Math.round(s.risk_score)}</strong>
                        <div class="risk-bar" style="flex:1">
                            <div class="risk-bar-fill ${riskColor(s.risk_score)}" style="width:${Math.min(s.risk_score, 100)}%"></div>
                        </div>
                    </div>
                </td>
                <td class="text-small">${(s.risk_reasons || []).join(', ') || '-'}</td>
                <td>
                    <button class="btn-sm btn-outline" onclick="showClientDetail('${s.ip}', event)">Inspect</button>
                </td>
            </tr>`).join('');

        // ML Status Box
        const mlContainer = document.getElementById('ml-status-info');
        if (mlStatus.has_model) {
            mlContainer.innerHTML = `
                <div class="ml-diagnostic-grid">
                    <div class="ml-diagnostic-box">
                        <span class="text-muted text-small">Algorithm:</span><br>
                        <strong>Isolation Forest (50 iTrees)</strong>
                    </div>
                    <div class="ml-diagnostic-box">
                        <span class="text-muted text-small">Vectors:</span><br>
                        <strong>10 Metrics (Z-Normalized)</strong>
                    </div>
                    <div class="ml-diagnostic-box">
                        <span class="text-muted text-small">Anomalies Detected:</span><br>
                        <strong class="${mlStatus.anomaly_count > 0 ? 'status-5xx' : ''}">${mlStatus.anomaly_count} / ${mlStatus.client_count} clients (${((mlStatus.anomaly_count / (mlStatus.client_count || 1)) * 100).toFixed(0)}%)</strong>
                    </div>
                    <div class="ml-diagnostic-box">
                        <span class="text-muted text-small">Evaluated At:</span><br>
                        <strong>${formatTime(mlStatus.last_run)}</strong>
                    </div>
                </div>
                <div style="margin-top:10px;padding:8px;border-radius:6px;background:var(--bg);font-size:11.5px;color:var(--text-secondary);border:1px solid var(--border);">
                    <strong>Statistical Model:</strong> Unsupervised path-isolation scoring <code>s(x,n)=2^(-E(h)/c)</code> with 3σ dynamic bounds and Shannon path entropy.
                </div>
            `;
        } else {
            mlContainer.innerHTML = '<p class="text-muted">Isolation Forest model not trained yet. Click "Run Isolation Forest" to train on current client traffic vectors.</p>';
        }

        // Cache and Render ML Table
        allMlResults = mlResults || [];
        renderMlResultsTable();
    } catch (err) {
        console.warn('Security telemetry syncing:', err?.message || err);
        setTimeout(() => {
            if (currentTab === 'security') loadSecurity();
        }, 1500);
    }
}

function renderStageBadge(stageInfo) {
    if (!stageInfo || !stageInfo.stage || stageInfo.stage === 'Benign') {
        return '<span class="stage-badge stage-benign">Benign</span>';
    }
    const stage = stageInfo.stage;
    const summary = stageInfo.chainSummary || '';
    if (stage.includes('Multi-Stage')) {
        return `<span class="stage-badge stage-multi" title="${escapeHtml(summary)}">⚡ Multi-Stage Intrusion</span>`;
    }
    if (stage.includes('Recon')) {
        return `<span class="stage-badge stage-recon" title="${escapeHtml(summary)}">🔍 Reconnaissance</span>`;
    }
    if (stage.includes('Credential')) {
        return `<span class="stage-badge stage-auth" title="${escapeHtml(summary)}">🔑 Auth Probing</span>`;
    }
    if (stage.includes('Exploit') || stage.includes('DoS')) {
        return `<span class="stage-badge stage-multi" title="${escapeHtml(summary)}">💥 Exploit / Flood</span>`;
    }
    return `<span class="stage-badge stage-multi" title="${escapeHtml(summary)}">${escapeHtml(stage)}</span>`;
}

function renderMlResultsTable() {
    const mlBody = document.getElementById('table-ml-results');
    if (!mlBody) return;

    const anomalyList = allMlResults.filter(r => r.is_anomaly || (r.anomaly_score && r.anomaly_score >= 70));
    const badgeCount = document.getElementById('ml-badge-count');
    if (badgeCount) {
        badgeCount.textContent = `${anomalyList.length} Anomaly${anomalyList.length === 1 ? '' : 's'}`;
        badgeCount.className = anomalyList.length > 0 ? 'badge badge-critical' : 'badge badge-low';
    }

    const listToRender = currentMlFilter === 'anomalies' ? anomalyList : allMlResults;

    if (listToRender.length === 0) {
        mlBody.innerHTML = currentMlFilter === 'anomalies'
            ? '<tr><td colspan="5" class="text-muted" style="text-align:center;padding:24px 16px;">No anomalous clients detected. All clients operate within normal statistical baseline bounds.</td></tr>'
            : '<tr><td colspan="5" class="text-muted" style="text-align:center;padding:24px 16px;">No ML results evaluated yet. Click "Run Isolation Forest" above.</td></tr>';
        return;
    }

    mlBody.innerHTML = listToRender.map(r => {
        const scoreVal = r.anomaly_score != null ? r.anomaly_score.toFixed(1) : '0.0';
        const scoreNum = parseFloat(scoreVal);
        const fillClass = scoreNum >= 75 ? 'score-critical' : (scoreNum >= 55 ? 'score-elevated' : 'score-normal');

        const drivers = r.top_drivers || [];
        let driversHtml = '<span class="text-muted text-small">Baseline normal profile</span>';
        if (drivers.length > 0) {
            driversHtml = `<div class="driver-tags">` + drivers.map(d => {
                const isCrit = d.z_score >= 2.5;
                return `<span class="driver-tag ${isCrit ? 'driver-critical' : 'driver-warning'}" title="${escapeHtml(d.feature)}: ${d.value} (+${d.z_score}σ)">${escapeHtml(d.label)} (+${d.z_score}σ)</span>`;
            }).join('') + `</div>`;
        }

        return `<tr>
            <td class="mono clickable" onclick="showClientDetail('${r.ip}')">
                <span style="color:var(--primary);">${r.ip}</span>
            </td>
            <td>
                <div class="mini-score-cell">
                    <strong style="width:28px;">${scoreVal}</strong>
                    <div class="mini-score-bar">
                        <div class="mini-score-fill ${fillClass}" style="width:${Math.min(scoreNum, 100)}%"></div>
                    </div>
                </div>
            </td>
            <td>${r.is_anomaly ? severityBadge('high') : '<span class="badge badge-low">Normal</span>'}</td>
            <td>${driversHtml}</td>
            <td>
                <button class="btn-sm btn-outline" onclick="showClientDetail('${r.ip}', event)">Inspect</button>
            </td>
        </tr>`;
    }).join('');
}

// Alert Actions
async function acknowledgeAlert(id, event) {
    if (event) event.stopPropagation();
    try {
        const data = await apiPost(`/security/alerts/${id}/acknowledge`);
        if (data.success) {
            showToast(`Alert #${id} acknowledged`, 'success');
            await fetchThreatStatus();
            if (currentTab === 'security') loadSecurity();
            if (currentTab === 'overview') loadOverview();
        }
    } catch (err) {
        showToast(`Failed to acknowledge alert: ${err.message}`, 'error');
    }
}

async function acknowledgeAllAlerts() {
    try {
        const res = await fetch(`${API}/security/alerts/acknowledge-all`, { method: 'POST' });
        const data = await res.json();
        showToast(`Acknowledged ${data.acknowledged || 0} active alerts`, 'success');
        await fetchThreatStatus();
        if (currentTab === 'security') loadSecurity();
        if (currentTab === 'overview') loadOverview();
    } catch (err) {
        showToast(`Failed to acknowledge alerts: ${err.message}`, 'error');
    }
}

async function clearAllAlerts() {
    if (!confirm('Are you sure you want to clear all security alerts?')) return;
    try {
        await fetch(`${API}/security/alerts/clear`, { method: 'POST' });
        showToast('All security alerts cleared', 'info');
        await fetchThreatStatus();
        loadSecurity();
    } catch (err) {
        showToast(`Failed to clear alerts: ${err.message}`, 'error');
    }
}

// ---- Requests Tab & Traffic Filtering ----
async function loadRequests() {
    try {
        const query = new URLSearchParams();
        query.set('limit', requestFilters.limit);
        query.set('offset', requestFilters.offset);

        if (requestFilters.search) query.set('search', requestFilters.search);
        if (requestFilters.method && requestFilters.method !== 'ALL') query.set('method', requestFilters.method);
        if (requestFilters.status_group && requestFilters.status_group !== 'ALL') query.set('status_group', requestFilters.status_group);
        if (requestFilters.min_latency > 0) query.set('min_latency', requestFilters.min_latency);
        if (requestFilters.errors_only) query.set('errors_only', 'true');

        const res = await api(`/requests?${query.toString()}`);
        const requests = Array.isArray(res) ? res : (res.requests || []);
        const totalCount = res.total !== undefined ? res.total : requests.length;
        const filteredCount = res.filtered !== undefined ? res.filtered : requests.length;

        // Update nav badge & count indicator
        const countBadge = document.getElementById('nav-request-badge');
        if (countBadge) countBadge.textContent = totalCount.toLocaleString();

        const indicator = document.getElementById('requests-count-indicator');
        if (indicator) {
            indicator.textContent = `Showing ${requests.length} of ${filteredCount.toLocaleString()} matching (${totalCount.toLocaleString()} total)`;
        }

        const tbody = document.getElementById('table-requests');
        tbody.innerHTML = requests.length === 0
            ? '<tr><td colspan="7" class="text-muted">No requests matched current filter criteria</td></tr>'
            : requests.map(r => `<tr class="clickable" onclick="showRequestDetail(${r.id})">
                <td class="text-small">${formatTime(r.timestamp)}</td>
                <td class="mono">${r.ip || '-'}</td>
                <td>${methodBadge(r.method)}</td>
                <td class="mono"><strong>${r.path}</strong></td>
                <td class="${statusClass(r.status_code)}">HTTP ${r.status_code}</td>
                <td>${formatMs(r.response_time_ms)}</td>
                <td class="text-small" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${r.user_agent || '-'}</td>
            </tr>`).join('');
    } catch (err) {
        console.warn('Request logs syncing:', err?.message || err);
        setTimeout(() => {
            if (currentTab === 'requests') loadRequests();
        }, 1500);
    }
}

// ---- Request Detail Modal ----
async function showRequestDetail(id) {
    try {
        const r = await api(`/requests/${id}`);
        if (r.error) {
            showToast('Request record not found', 'error');
            return;
        }

        const fields = [
            ['Request ID', `#${r.id}`],
            ['Timestamp', `${formatTime(r.timestamp)} (${r.timestamp})`],
            ['Client IP', `<span class="mono">${r.ip}</span> <button class="btn-sm btn-outline" style="margin-left:8px;" onclick="copyToClipboard('${r.ip}')">Copy</button>`],
            ['HTTP Method', methodBadge(r.method)],
            ['Endpoint Path', `<strong class="mono">${r.path}</strong>`],
            ['Status Code', `<span class="${statusClass(r.status_code)}">HTTP ${r.status_code}</span>`],
            ['Response Latency', `<strong>${formatMs(r.response_time_ms)}</strong>`],
            ['User-Agent', `<span class="mono text-small">${r.user_agent || '-'}</span>`],
            ['Referer', `<span class="text-small">${r.referer || 'None'}</span>`],
            ['Payload Size', `${r.request_size || 0} bytes (Req) / ${r.response_size || 0} bytes (Resp)`],
            ['Origin Country', r.country ? `${r.country} (${r.city || 'Unknown'})` : 'Local / Internal'],
            ['Auth Attempt', r.is_login_attempt ? (r.login_success ? '<span class="badge badge-success">Success</span>' : '<span class="badge badge-danger">Failed Login</span>') : 'No'],
        ];

        const content = fields.map(([label, val]) =>
            `<div class="detail-row"><div class="detail-label">${label}</div><div class="detail-value">${val}</div></div>`
        ).join('') + `
            <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px;">
                <button class="btn-sm" onclick="filterByThisIp('${r.ip}')">Filter Traffic by IP</button>
                <button class="btn-sm btn-primary" onclick="showClientDetail('${r.ip}')">View Client Profile</button>
            </div>
        `;

        showModal(`Request #${r.id} Inspection`, content);
    } catch (err) {
        showToast(`Failed to open request: ${err.message}`, 'error');
    }
}

function filterByThisIp(ip) {
    document.querySelectorAll('.modal-overlay').forEach(m => m.remove());
    loadTab('requests');
    const searchInput = document.getElementById('filter-req-search');
    if (searchInput) searchInput.value = ip;
    requestFilters.search = ip;
    loadRequests();
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast(`Copied ${text} to clipboard`, 'success');
    }).catch(() => {
        showToast(`Selected: ${text}`, 'info');
    });
}

// ---- Client Detail Modal ----
async function showClientDetail(ip, event) {
    if (event) event.stopPropagation();
    try {
        const [c, risk] = await Promise.all([
            api(`/clients/${encodeURIComponent(ip)}`),
            api(`/security/risk/${encodeURIComponent(ip)}`)
        ]);

        if (c.error) {
            showToast('Client telemetry not found', 'error');
            return;
        }

        const fields = [
            ['IP Address', `<strong class="mono">${c.ip}</strong> <button class="btn-sm btn-outline" style="margin-left:8px;" onclick="copyToClipboard('${c.ip}')">Copy</button>`],
            ['Total Requests', c.request_count.toLocaleString()],
            ['First Seen', formatTime(c.first_seen)],
            ['Last Seen', formatTime(c.last_seen)],
            ['Avg Response Time', formatMs(c.avg_response_time)],
            ['Location', c.country ? `${c.country} (${c.city || 'Unknown'})` : 'Internal / Private'],
        ];

        let html = fields.map(([label, val]) =>
            `<div class="detail-row"><div class="detail-label">${label}</div><div class="detail-value">${val}</div></div>`
        ).join('');

        // Risk score breakdown
        const score = Math.round(risk.score);
        html += `
            <div class="detail-row" style="margin-top:10px;">
                <div class="detail-label">Risk Assessment</div>
                <div class="detail-value">
                    <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
                        <span class="badge badge-${score >= 60 ? 'critical' : score >= 30 ? 'warning' : 'success'}">${score} / 100 Risk Score</span>
                    </div>
                    <div class="risk-bar"><div class="risk-bar-fill ${riskColor(score)}" style="width:${Math.min(score, 100)}%"></div></div>
                    ${risk.reasons.length > 0 ? '<ul style="margin-top:8px;padding-left:18px;">' + risk.reasons.map(r => `<li class="text-small status-5xx">${r}</li>`).join('') + '</ul>' : '<p class="text-small text-muted" style="margin-top:6px;">No elevated risk signals triggered.</p>'}
                </div>
            </div>
        `;

        // Top endpoints hit
        if (c.endpoints_hit && c.endpoints_hit.length > 0) {
            html += '<div style="margin-top:14px;"><strong>Targeted Endpoints:</strong><ul style="padding-left:18px;margin-top:4px;">';
            c.endpoints_hit.slice(0, 8).forEach(e => {
                html += `<li class="text-small mono">${e.path} (${e.count} reqs)</li>`;
            });
            html += '</ul></div>';
        }

        // Action footer
        html += `
            <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:18px;">
                <button class="btn-sm btn-outline" onclick="filterByThisIp('${c.ip}')">View All Requests by Client</button>
            </div>
        `;

        showModal(`Client Profile: ${ip}`, html);
    } catch (err) {
        showToast(`Failed to open client profile: ${err.message}`, 'error');
    }
}

// ---- Modal Display ----
function showModal(title, bodyHtml) {
    document.querySelectorAll('.modal-overlay').forEach(m => m.remove());
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
    overlay.innerHTML = `
        <div class="modal">
            <div class="modal-header">
                <span>${title}</span>
                <button onclick="this.closest('.modal-overlay').remove()" aria-label="Close modal">&times;</button>
            </div>
            <div class="modal-body">${bodyHtml}</div>
        </div>
    `;
    document.body.appendChild(overlay);
}

// ---- Toast Notifications ----
function showToast(message, type = 'info') {
    document.querySelectorAll('.toast-notification').forEach(t => t.remove());

    const toast = document.createElement('div');
    toast.className = `toast-notification ${type === 'error' ? 'toast-error' : type === 'success' ? 'toast-success' : type === 'warning' ? 'toast-warning' : ''}`;
    toast.innerHTML = `<span>${message}</span>`;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ---- Detect & ML Execution ----
async function runDetection() {
    showToast('Executing rule-based threat scans...', 'info');
    try {
        const res = await apiPost('/security/detect');
        const count = res.alerts_generated || 0;
        showToast(`Threat detection scan complete: ${count} alert(s) generated.`, count > 0 ? 'error' : 'success');
        await fetchThreatStatus();
        if (currentTab === 'security') loadSecurity();
        if (currentTab === 'overview') loadOverview();
    } catch (err) {
        showToast(`Detection scan failed: ${err.message}`, 'error');
    }
}

async function runML() {
    showToast('Training Isolation Forest ML model...', 'info');
    try {
        const res = await apiPost('/ml/run');
        if (res.trained === false) {
            showToast(`ML Training skipped: ${res.reason}`, 'warning');
        } else {
            const count = res.anomaly_count !== undefined ? res.anomaly_count : (res.anomalies_detected || 0);
            showToast(`ML Complete: Analyzed ${res.client_count} clients. Flagged ${count} anomalies.`, count > 0 ? 'warning' : 'success');
            await fetchThreatStatus();
            if (currentTab === 'security') loadSecurity();
        }
    } catch (err) {
        showToast(`ML Execution failed: ${err.message}`, 'error');
    }
}

// ============================================================================
// Developer Integration & Connect Your API Tab
// ============================================================================

const CODE_SNIPPETS = {
    express: `// 1. Install or import the ARC Defender client
import express from 'express';
import { ArcDefenderClient } from './src/sdk/arcClient.js';

const app = express();

// 2. Initialize ARC Defender telemetry client
const arc = new ArcDefenderClient({
  endpoint: 'http://localhost:3000', // URL of your ARC Defender server
  batchFlushIntervalMs: 1000        // Flushes non-blocking batches every 1s
});

// 3. Attach middleware before your business routes
app.use(arc.middleware());

// Your normal API routes
app.get('/api/v1/products', (req, res) => {
  res.json({ status: 'ok', items: ['Server', 'Firewall'] });
});

app.listen(8080, () => console.log('App running with ARC Defender protection'));`,

    fastapi: `# 1. Python FastAPI / Starlette Integration
from fastapi import FastAPI
from src.sdk.arc_middleware import ArcDefenderClient, get_fastapi_middleware

app = FastAPI(title="My Protected API")

# 2. Connect client to your ARC Defender instance
arc_client = ArcDefenderClient(endpoint="http://localhost:3000")

# 3. Mount asynchronous telemetry capture
ArcMiddleware = get_fastapi_middleware(arc_client)
app.add_middleware(ArcMiddleware)

@app.get("/api/v1/users")
def get_users():
    return [{"id": 1, "username": "admin"}]`,

    flask: `# 1. Python Flask Integration
from flask import Flask, request
from src.sdk.arc_middleware import ArcDefenderClient
import time

app = Flask(__name__)
arc = ArcDefenderClient(endpoint="http://localhost:3000")

@app.before_request
def start_timer():
    request._arc_start = time.perf_counter()

@app.after_request
def record_telemetry(response):
    elapsed_ms = (time.perf_counter() - getattr(request, '_arc_start', time.perf_counter())) * 1000
    arc.record_event(
        ip=request.headers.get("X-Forwarded-For", request.remote_addr),
        method=request.method,
        path=request.path,
        status_code=response.status_code,
        response_time_ms=elapsed_ms,
        user_agent=request.headers.get("User-Agent", "")
    )
    return response`,

    go: `// Go / Gin Web Framework Integration
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
	"github.com/gin-gonic/gin"
)

func ArcDefenderMiddleware(arcEndpoint string) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		latency := time.Since(start).Milliseconds()

		// Non-blocking telemetry dispatch
		go func() {
			payload, _ := json.Marshal(map[string]interface{}{
				"ip":               c.ClientIP(),
				"method":           c.Request.Method,
				"path":             c.FullPath(),
				"status_code":      c.Writer.Status(),
				"response_time_ms": latency,
				"user_agent":       c.Request.UserAgent(),
			})
			http.Post(arcEndpoint+"/arc/api/v1/ingest", "application/json", bytes.NewBuffer(payload))
		}()
	}
}

func main() {
	r := gin.Default()
	r.Use(ArcDefenderMiddleware("http://localhost:3000"))
	r.GET("/api/ping", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })
	r.Run(":8080")
}`,

    curl: `# 1. Single Ingestion Event (POST /arc/api/v1/ingest)
curl -X POST http://localhost:3000/arc/api/v1/ingest \\
  -H "Content-Type: application/json" \\
  -d '{
    "ip": "203.0.113.195",
    "method": "POST",
    "path": "/api/v1/auth/login",
    "status_code": 401,
    "response_time_ms": 19.4,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "request_size": 256,
    "response_size": 128,
    "is_login_attempt": true,
    "login_success": false
  }'

# 2. Batch Ingestion (POST /arc/api/v1/batch-ingest)
curl -X POST http://localhost:3000/arc/api/v1/batch-ingest \\
  -H "Content-Type: application/json" \\
  -d '[
    {"ip": "198.51.100.22", "method": "GET", "path": "/api/feed", "status_code": 200, "response_time_ms": 12.1},
    {"ip": "198.51.100.22", "method": "GET", "path": "/api/feed", "status_code": 200, "response_time_ms": 11.8}
  ]'`
};

let currentSnippetLang = 'express';

function loadIntegration() {
    setupSnippetTabs();
    setupSandboxButtons();
    renderCurrentSnippet();
}

function setupSnippetTabs() {
    const tabs = document.querySelectorAll('#snippet-lang-tabs .snippet-btn');
    tabs.forEach(btn => {
        btn.onclick = () => {
            tabs.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentSnippetLang = btn.dataset.lang || 'express';
            renderCurrentSnippet();
        };
    });

    const copyBtn = document.getElementById('btn-copy-snippet');
    if (copyBtn) {
        copyBtn.onclick = () => {
            const code = CODE_SNIPPETS[currentSnippetLang] || '';
            navigator.clipboard.writeText(code).then(() => {
                showToast(`Copied ${currentSnippetLang.toUpperCase()} integration snippet!`, 'success');
            }).catch(() => {
                showToast('Snippet ready to copy', 'info');
            });
        };
    }
}

function renderCurrentSnippet() {
    const pre = document.getElementById('code-snippet-display');
    if (pre) {
        pre.textContent = CODE_SNIPPETS[currentSnippetLang] || CODE_SNIPPETS.express;
    }
}

function setupSandboxButtons() {
    const btnNormal = document.getElementById('btn-prefill-normal');
    if (btnNormal) {
        btnNormal.onclick = () => {
            document.getElementById('sandbox-ip').value = '192.168.1.105';
            document.getElementById('sandbox-method').value = 'GET';
            document.getElementById('sandbox-path').value = '/api/v1/users/profile';
            document.getElementById('sandbox-status').value = '200';
            document.getElementById('sandbox-latency').value = '12.4';
            document.getElementById('sandbox-ua').value = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)';
            document.getElementById('sandbox-is-login').checked = false;
            document.getElementById('sandbox-login-success').checked = false;
            showToast('Form pre-filled with normal user telemetry', 'info');
        };
    }

    const btnAttack = document.getElementById('btn-prefill-attack');
    if (btnAttack) {
        btnAttack.onclick = () => {
            document.getElementById('sandbox-ip').value = '203.0.113.88';
            document.getElementById('sandbox-method').value = 'POST';
            document.getElementById('sandbox-path').value = '/wp-admin/login.php';
            document.getElementById('sandbox-status').value = '401';
            document.getElementById('sandbox-latency').value = '85.2';
            document.getElementById('sandbox-ua').value = 'Hydra/9.5 (BruteForce Scanner)';
            document.getElementById('sandbox-is-login').checked = true;
            document.getElementById('sandbox-login-success').checked = false;
            showToast('Form pre-filled with suspicious attack event', 'warning');
        };
    }
}

async function sendCustomIngestEvent() {
    const ip = document.getElementById('sandbox-ip').value.trim();
    const method = document.getElementById('sandbox-method').value;
    const path = document.getElementById('sandbox-path').value.trim();
    const status_code = parseInt(document.getElementById('sandbox-status').value, 10) || 200;
    const response_time_ms = parseFloat(document.getElementById('sandbox-latency').value) || 15;
    const user_agent = document.getElementById('sandbox-ua').value.trim();
    const is_login_attempt = document.getElementById('sandbox-is-login').checked;
    const login_success = document.getElementById('sandbox-login-success').checked;

    const pill = document.getElementById('sandbox-status-pill');
    const jsonPre = document.getElementById('sandbox-response-json');
    if (pill) {
        pill.className = 'badge badge-warning';
        pill.textContent = 'Transmitting...';
    }

    const payload = {
        ip,
        method,
        path,
        status_code,
        response_time_ms,
        user_agent,
        is_login_attempt,
        login_success
    };

    try {
        const resp = await apiPost('/v1/ingest', payload);
        if (pill) {
            pill.className = 'badge badge-success';
            pill.textContent = '201 Created';
        }
        if (jsonPre) {
            jsonPre.textContent = JSON.stringify(resp, null, 2);
        }
        showToast(`Ingested request #${resp.event_id} from ${ip}`, 'success');
        // Update threat status
        fetchThreatStatus();
    } catch (err) {
        if (pill) {
            pill.className = 'badge badge-critical';
            pill.textContent = 'Failed';
        }
        if (jsonPre) {
            jsonPre.textContent = JSON.stringify({ error: err.message }, null, 2);
        }
        showToast(`Ingestion failed: ${err.message}`, 'error');
    }
}

// ---- Explicit Window Global Exports (Cross-frame and Inline Event Resilience) ----
window.loadTab = loadTab;
window.filterMlTable = filterMlTable;
window.showRequestDetail = showRequestDetail;
window.showClientDetail = showClientDetail;
window.acknowledgeAlert = acknowledgeAlert;
window.filterByThisIp = filterByThisIp;
window.copyToClipboard = copyToClipboard;
window.sendCustomIngestEvent = sendCustomIngestEvent;
window.runDetection = runDetection;
window.runML = runML;

