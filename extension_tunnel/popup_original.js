const ENDPOINT_CONFIG_KEY = 'firewall_endpoint_config';
const DEFAULT_API_BASE = '';
const DEFAULT_LOCAL_ENGINE = '';
const DEFAULT_ENDPOINT_CONFIG = Object.freeze({
    backendApiBase: DEFAULT_API_BASE,
    localEngineApiBase: DEFAULT_LOCAL_ENGINE
});
const TUNNEL_CONFIG_REQUIRED_MESSAGE = 'Tunnel endpoints are not configured. Run start_dev_tunnels.sh to generate Dev Tunnel URLs.';
const LOCAL_RUNNER_OPTIONS_KEY = 'local_runner_options';
let API_BASE = DEFAULT_API_BASE;
let LOCAL_ENGINE = DEFAULT_LOCAL_ENGINE;
const AUTOMATION_OPTIONS_KEY = 'automated_browser_options';
const AUTOMATION_OPTION_FIELDS = [
    'incognitoMode',
    'blockAdsMode',
    'disableCssMode',
    'interceptClicksMode',
    'interceptFormsMode'
];
const LOCAL_RUNNER_OPTION_FIELDS = [
    'localRunnerHeadless',
    'localRunnerLightweight',
    'localRunnerTextOnly',
    'localRunnerAllowImages'
];
const RULE_STORAGE_KEYS = [
    'firewall_rules',
    'rules_version',
    'console_firewall_policy',
    'local_engine_rules',
    'local_engine_status',
    'rule_change_history'
];
const RUNTIME_TUNNEL_CONFIG_PATH = 'runtime_tunnel_config.local.json';
const LOCAL_RUNNER_API_BASE = 'http://localhost:6000/api/local-browser';
const LOCAL_RUNNER_FALLBACK_API_BASE = 'http://127.0.0.1:6000/api/local-browser';
const SEARCH_APP_BASE = 'http://localhost:4000';
const SEARCH_APP_FALLBACK_BASE = 'http://127.0.0.1:4000';
const EXTENSION_PAGES_CSP = chrome.runtime.getManifest()?.content_security_policy?.extension_pages || '';
const LOCALHOST_CSP_REQUIRED_MESSAGE = 'Runner endpoints are blocked by this loaded extension CSP. Reload the updated unpacked extension.';
let LOCAL_RUNNER_API_BASE_OVERRIDE = '';
let SEARCH_APP_BASE_OVERRIDE = '';
let latestLocalRunnerResult = null;

document.addEventListener('DOMContentLoaded', () => {
    void initializePopup();
});

chrome.runtime.onMessage.addListener((message) => {
    if (message.action === 'sessionEnded') {
        showNotification('Session Ended', `Session ended: ${message.reason}`);
        checkSessionId();
        return;
    }

    if (message.action === 'ruleHistoryUpdated') {
        loadStoredFirewallRuleState();
    }
});

chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace !== 'local') {
        return;
    }

    if (changes.firewall_guard_sessions) {
        checkSessionId();
    }

    if (changes[ENDPOINT_CONFIG_KEY]) {
        void syncEndpointConfig().then(() => {
            return syncLocalRunnerApiBaseOverride();
        }).then(() => {
            return syncSearchAppBaseOverride();
        }).then(() => {
            refreshEndpointMode();
            refreshServerStatus();
            refreshSearchEngineStatus(false);
        });
    }

    if (
        changes.firewall_rules ||
        changes.rules_version ||
        changes.console_firewall_policy ||
        changes.local_engine_rules ||
        changes.local_engine_status ||
        changes.rule_change_history
    ) {
        loadStoredFirewallRuleState();
    }
});

async function initializePopup() {
    console.log('[Popup] Initializing...');
    setupEventListeners();
    loadAutomatedBrowserSettings();
    await syncEndpointConfig();
    await syncLocalRunnerApiBaseOverride();
    await syncSearchAppBaseOverride();
    refreshEndpointMode();
    checkPageStatus();
    refreshServerStatus();
    checkSessionId();
    refreshFirewallRuleState();
    refreshAutomationSessions(false);
    refreshSearchEngineStatus(false);
    refreshAutomationModeUI();

    setInterval(checkPageStatus, 5000);
    setInterval(checkSessionId, 10000);
    setInterval(refreshServerStatus, 15000);
    setInterval(() => {
        refreshAutomationSessions(false);
    }, 15000);
    setInterval(() => {
        refreshFirewallRuleState(false);
    }, 15000);
    setInterval(() => {
        refreshSearchEngineStatus(false);
    }, 20000);
}

function setupEventListeners() {
    bindClick('testConnectionBtn', testConnection);
    bindClick('launchBrowserBtn', launchAutomatedBrowser);
    bindClick('getSessionsBtn', () => refreshAutomationSessions(true));
    bindClick('dashboardBtn', openDashboard);
    bindClick('updateBtn', checkUpdate);
    bindClick('consoleCommandsBtn', showConsoleCommands);
    bindClick('aiTestingPanelBtn', openAITestingPanel);
    bindClick('refreshSessionBtn', checkSessionId);
    bindClick('refreshRulesBtn', () => refreshFirewallRuleState(true));
    bindClick('forceSessionBtn', forceSessionForCurrentTab);
    bindClick('clearSessionBtn', clearCurrentSession);
    bindClick('launchSearchEngineBtn', launchSearchEngine);
    bindClick('refreshSearchEngineBtn', () => refreshSearchEngineStatus(true));

    const sessionIdElement = document.getElementById('sessionId');
    if (sessionIdElement) {
        sessionIdElement.addEventListener('click', openDashboard);
    }

    bindAutomationOptionChangeHandlers();
}

function bindClick(id, handler) {
    const element = document.getElementById(id);
    if (element) {
        element.addEventListener('click', handler);
    }
}

function normalizeBaseUrl(value, fallback) {
    const candidate = typeof value === 'string' && value.trim()
        ? value.trim()
        : fallback;

    if (!candidate) {
        return '';
    }

    return candidate.replace(/\/+$/, '');
}

function normalizeApiBase(value, fallback) {
    const normalized = normalizeBaseUrl(value, fallback);

    if (!normalized) {
        return normalizeBaseUrl(fallback, '');
    }

    return /\/api$/i.test(normalized)
        ? normalized
        : `${normalized}/api`;
}

function toLocalRunnerApiBase(serverBase) {
    const normalized = normalizeBaseUrl(serverBase, '');
    if (!normalized) {
        return '';
    }

    return /\/api$/i.test(normalized)
        ? `${normalized}/local-browser`
        : `${normalized}/api/local-browser`;
}

function deriveExtensionServerBaseFromBackendApi(backendApiBase) {
    try {
        const parsed = new URL(normalizeBaseUrl(backendApiBase, ''));
        if (!parsed.hostname.toLowerCase().includes('devtunnels.ms')) {
            return '';
        }

        const hostWithPort6000 = parsed.hostname.replace(/-\d+(\.)/i, '-6000$1');
        if (hostWithPort6000 === parsed.hostname) {
            return '';
        }

        return `${parsed.protocol}//${hostWithPort6000}`;
    } catch (error) {
        return '';
    }
}

async function syncLocalRunnerApiBaseOverride() {
    const setIfValid = (candidate) => {
        const nextBase = toLocalRunnerApiBase(candidate);
        if (isSupportedUrl(nextBase)) {
            LOCAL_RUNNER_API_BASE_OVERRIDE = nextBase;
            return true;
        }
        return false;
    };

    LOCAL_RUNNER_API_BASE_OVERRIDE = '';

    try {
        const response = await fetch(chrome.runtime.getURL(RUNTIME_TUNNEL_CONFIG_PATH), { cache: 'no-store' });
        if (response.ok) {
            const config = await response.json();
            if (setIfValid(config?.extensionServerBase)) {
                return;
            }
        }
    } catch (error) {
        // Runtime tunnel config is optional; fallback below.
    }

    const derivedServerBase = deriveExtensionServerBaseFromBackendApi(API_BASE);
    if (setIfValid(derivedServerBase)) {
        return;
    }

    const fallbackServerBase = LOCAL_ENGINE.replace(/:\d+(?=\/|$)/, ':6000').replace(/\/api$/i, '');
    setIfValid(fallbackServerBase);
}

function deriveSearchAppBaseFromBackendApi(backendApiBase) {
    try {
        const parsed = new URL(normalizeBaseUrl(backendApiBase, ''));
        if (!parsed.hostname.toLowerCase().includes('devtunnels.ms')) {
            return '';
        }

        const hostWithPort4000 = parsed.hostname.replace(/-\d+(\.)/i, '-4000$1');
        if (hostWithPort4000 === parsed.hostname) {
            return '';
        }

        return `${parsed.protocol}//${hostWithPort4000}`;
    } catch (error) {
        return '';
    }
}

async function syncSearchAppBaseOverride() {
    const setIfValid = (candidate) => {
        const normalized = normalizeBaseUrl(candidate, '');
        if (isSupportedUrl(normalized)) {
            SEARCH_APP_BASE_OVERRIDE = normalized;
            return true;
        }
        return false;
    };

    SEARCH_APP_BASE_OVERRIDE = '';

    try {
        const response = await fetch(chrome.runtime.getURL(RUNTIME_TUNNEL_CONFIG_PATH), { cache: 'no-store' });
        if (response.ok) {
            const config = await response.json();
            if (setIfValid(config?.searchAppBase)) {
                return;
            }
        }
    } catch (error) {
        // Runtime tunnel config is optional; fallback below.
    }

    const derivedSearchBase = deriveSearchAppBaseFromBackendApi(API_BASE);
    setIfValid(derivedSearchBase);
}

function getCurrentEndpointConfig() {
    return {
        backendApiBase: API_BASE,
        localEngineApiBase: LOCAL_ENGINE
    };
}

function isEndpointConfigEmpty(config) {
    const candidate = config && typeof config === 'object' ? config : {};
    const backendApiBase = normalizeApiBase(candidate.backendApiBase, DEFAULT_API_BASE);
    const localEngineApiBase = normalizeApiBase(candidate.localEngineApiBase, DEFAULT_LOCAL_ENGINE);
    return !backendApiBase && !localEngineApiBase;
}

function isDevTunnelUrl(url) {
    try {
        const normalized = normalizeBaseUrl(url, '');
        if (!normalized) {
            return false;
        }

        const parsed = new URL(normalized);
        return parsed.protocol === 'https:' && parsed.hostname.toLowerCase().includes('devtunnels.ms');
    } catch (error) {
        return false;
    }
}

function isLocalhostUrl(url) {
    try {
        const normalized = normalizeBaseUrl(url, '');
        if (!normalized) {
            return false;
        }

        const parsed = new URL(normalized);
        const hostname = parsed.hostname.toLowerCase();
        return (parsed.protocol === 'http:' || parsed.protocol === 'https:')
            && (hostname === 'localhost' || hostname === '127.0.0.1');
    } catch (error) {
        return false;
    }
}

function popupCspAllowsLocalhostConnections() {
    return /localhost|127\.0\.0\.1|devtunnels\.ms/i.test(EXTENSION_PAGES_CSP);
}

function hasConfiguredEndpointConfig(config) {
    const candidate = config && typeof config === 'object' ? config : {};
    const backendApiBase = normalizeApiBase(candidate.backendApiBase, DEFAULT_API_BASE);
    const localEngineApiBase = normalizeApiBase(candidate.localEngineApiBase, DEFAULT_LOCAL_ENGINE);
    return isSupportedUrl(backendApiBase) && isSupportedUrl(localEngineApiBase);
}

function isSupportedUrl(url) {
    return isDevTunnelUrl(url) || isLocalhostUrl(url);
}

function getEndpointMode(config) {
    const candidate = config && typeof config === 'object' ? config : {};
    const backendApiBase = normalizeApiBase(candidate.backendApiBase, DEFAULT_API_BASE);
    const localEngineApiBase = normalizeApiBase(candidate.localEngineApiBase, DEFAULT_LOCAL_ENGINE);

    if (!isSupportedUrl(backendApiBase) || !isSupportedUrl(localEngineApiBase)) {
        return 'unconfigured';
    }

    if (isDevTunnelUrl(backendApiBase) && isLocalhostUrl(localEngineApiBase)) {
        return 'hybrid';
    }

    if (isDevTunnelUrl(backendApiBase) || isDevTunnelUrl(localEngineApiBase)) {
        return 'dev_tunnel';
    }

    return 'localhost';
}

function assertSupportedUrl(url, label) {
    let parsed;

    try {
        parsed = new URL(normalizeBaseUrl(url, ''));
    } catch (error) {
        throw new Error(`${label} must be a valid http:// or https:// URL`);
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error(`${label} must use http:// or https://`);
    }

    if (!isSupportedUrl(parsed.toString())) {
        throw new Error(`${label} must use a Dev Tunnel or localhost URL`);
    }
}

function applyEndpointConfig(config) {
    const nextApiBase = normalizeApiBase(config?.backendApiBase, DEFAULT_API_BASE);
    const nextLocalEngine = normalizeApiBase(config?.localEngineApiBase, DEFAULT_LOCAL_ENGINE);

    if (!nextApiBase && !nextLocalEngine) {
        API_BASE = '';
        LOCAL_ENGINE = '';
        return;
    }

    assertSupportedUrl(nextApiBase, 'Backend API endpoint');
    assertSupportedUrl(nextLocalEngine, 'Local engine endpoint');

    API_BASE = nextApiBase;
    LOCAL_ENGINE = nextLocalEngine;
}

function syncEndpointConfig() {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: 'getEndpointConfig' }, (response) => {
            if (chrome.runtime.lastError || !response || !response.success || !response.config) {
                applyEndpointConfig(DEFAULT_ENDPOINT_CONFIG);
                resolve({
                    backendApiBase: API_BASE,
                    localEngineApiBase: LOCAL_ENGINE
                });
                return;
            }

            applyEndpointConfig(response.config);
            resolve(response.config);
        });
    });
}

function createTunnelAwareRequestOptions(url, options = {}) {
    const nextOptions = { ...options };
    const headers = new Headers(options.headers || {});

    if (isDevTunnelUrl(url)) {
        nextOptions.credentials = 'include';
        headers.set('X-Tunnel-Skip-AntiPhishing-Page', 'true');
        if (!headers.has('Accept')) {
            headers.set('Accept', 'application/json, text/plain, */*');
        }
    }

    nextOptions.headers = headers;
    return nextOptions;
}

function fetchTunnelAware(url, options = {}) {
    if (typeof url !== 'string' || !/^[a-z][a-z0-9+.-]*:\/\//i.test(url.trim())) {
        throw new Error(TUNNEL_CONFIG_REQUIRED_MESSAGE);
    }

    assertSupportedUrl(url, 'Requested service URL');
    return fetch(url, createTunnelAwareRequestOptions(url, options));
}

function refreshEndpointMode() {
    const endpointModeElement = document.getElementById('endpointMode');
    if (!endpointModeElement) {
        return;
    }

    const mode = getEndpointMode(getCurrentEndpointConfig());

    if (mode === 'hybrid') {
        endpointModeElement.textContent = 'Tunnel + Local Engine';
        endpointModeElement.className = 'status-value ok';
        return;
    }

    if (mode === 'dev_tunnel') {
        endpointModeElement.textContent = 'All Tunnel';
        endpointModeElement.className = 'status-value ok';
        return;
    }

    if (mode === 'localhost') {
        endpointModeElement.textContent = 'All Local';
        endpointModeElement.className = 'status-value ok';
        return;
    }

    endpointModeElement.textContent = 'Config Required';
    endpointModeElement.className = 'status-value warning';
}

function checkPageStatus() {
    chrome.runtime.sendMessage({ action: 'getSiteInfo' }, (response) => {
        const pageStatus = document.getElementById('pageStatus');
        if (!pageStatus) {
            return;
        }

        if (chrome.runtime.lastError) {
            pageStatus.textContent = 'Unavailable';
            pageStatus.className = 'page-status';
            return;
        }

        if (response && response.success && response.siteInfo) {
            const siteInfo = response.siteInfo;

            if (siteInfo.url.startsWith('chrome://') || siteInfo.url.startsWith('chrome-extension://')) {
                pageStatus.textContent = 'Secure Page';
            } else if (isDevTunnelUrl(siteInfo.url)) {
                pageStatus.textContent = 'Tunnel Page';
            } else {
                pageStatus.textContent = 'External Page';
            }

            pageStatus.className = 'page-status';
            return;
        }

        pageStatus.textContent = 'No Site Info';
        pageStatus.className = 'page-status';
    });
}

function refreshServerStatus() {
    const statusElement = document.getElementById('serverStatus');
    if (!statusElement) {
        return;
    }

    if (!hasConfiguredEndpointConfig(getCurrentEndpointConfig())) {
        statusElement.textContent = 'Config Required';
        statusElement.className = 'status-value warning';
        return;
    }

    fetchTunnelAware(`${API_BASE}/status`)
        .then((response) => {
            if (response.status === 401) {
                const error = new Error('Tunnel login required');
                error.code = 'TUNNEL_AUTH_REQUIRED';
                throw error;
            }

            if (!response.ok) {
                throw new Error(`Backend status failed: ${response.status}`);
            }

            return response.json();
        })
        .then((data) => {
            const isHealthy = Boolean(
                data &&
                (
                    data.success === true ||
                    data.status === 'running' ||
                    data.status === 'online' ||
                    data.server === 'running' ||
                    data.version
                )
            );

            if (isHealthy) {
                statusElement.textContent = 'Connected';
                statusElement.className = 'status-value ok';
            } else {
                statusElement.textContent = 'Unavailable';
                statusElement.className = 'status-value warning';
            }
        })
        .catch(() => {
            chrome.runtime.sendMessage({ action: 'getBackendStatus' }, (status) => {
                if (status && (status.configRequired || status.mode === 'unconfigured')) {
                    statusElement.textContent = 'Config Required';
                    statusElement.className = 'status-value warning';
                } else if (status && status.connected) {
                    statusElement.textContent = 'Connected';
                    statusElement.className = 'status-value ok';
                } else if (status && status.authRequired) {
                    statusElement.textContent = 'Tunnel Login';
                    statusElement.className = 'status-value warning';
                } else {
                    statusElement.textContent = 'Offline';
                    statusElement.className = 'status-value error';
                }
            });
        });
}

function checkSessionId() {
    chrome.storage.local.get('firewall_guard_sessions', (result) => {
        const sessionIdElement = document.getElementById('sessionId');
        if (!sessionIdElement) {
            return;
        }

        const storage = result.firewall_guard_sessions;
        if (storage && storage.currentSession && storage.currentSession.sessionId) {
            sessionIdElement.textContent = storage.currentSession.sessionId;
            sessionIdElement.className = 'status-value ok clickable';
            sessionIdElement.title = 'Click to open Dashboard';
            updateAutomationSessionDisplay(storage.currentSession);
            return;
        }

        sessionIdElement.textContent = 'None';
        sessionIdElement.className = 'status-value';
        sessionIdElement.title = '';
        updateAutomationSessionDisplay(null);
    });
}

function refreshFirewallRuleState(showNotificationAfterRefresh = false) {
    chrome.runtime.sendMessage({
        action: 'refreshRuleSnapshots',
        refreshRemote: showNotificationAfterRefresh
    }, (response) => {
        if (response && response.success) {
            updateFirewallRuleUI({
                firewall_rules: response.globalRules,
                rules_version: response.globalVersion,
                console_firewall_policy: response.localPolicy,
                local_engine_rules: response.localEngineRules,
                local_engine_status: response.localEngineStatus,
                rule_change_history: response.history
            });

            if (showNotificationAfterRefresh) {
                showNotification('Rules Refreshed', 'Global and local firewall rule snapshots updated');
            }
            return;
        }

        loadStoredFirewallRuleState();

        if (showNotificationAfterRefresh) {
            showNotification('Rules Refreshed', 'Loaded latest stored firewall rule history');
        }
    });
}

function loadStoredFirewallRuleState() {
    chrome.storage.local.get(RULE_STORAGE_KEYS, (result) => {
        updateFirewallRuleUI(result);
    });
}

function updateFirewallRuleUI(data) {
    const globalRules = data.firewall_rules || {};
    const globalVersion = data.rules_version || globalRules.version || 0;
    const localPolicy = data.console_firewall_policy || {};
    const localEngineRules = data.local_engine_rules || {};
    const localEngineStatus = data.local_engine_status || {};
    const history = buildDisplayRuleHistory(data);
    const globalChange = history.find((entry) => entry.scope === 'global');
    const localChange = history.find((entry) => entry.scope === 'local' && entry.target === 'console-policy')
        || history.find((entry) => entry.scope === 'local');
    const globalBlockedCount = Array.isArray(globalRules.blocked_domains)
        ? globalRules.blocked_domains.length
        : (Array.isArray(globalRules.rule_sets) ? globalRules.rule_sets.length : 0);

    setText('rulesVersion', formatVersion(globalVersion));
    setText('globalRulesVersion', formatVersion(globalRules.version || globalVersion));
    setText('globalBlockedCount', String(globalBlockedCount));
    setText('globalRulesChange', buildLatestChangeText(globalChange));
    setText('localPolicyRuleCount', String(Array.isArray(localPolicy.rules) ? localPolicy.rules.length : 0));
    setText('localRulesChange', buildLatestChangeText(localChange));

    const localEngineLabel = document.getElementById('localEngineRulesStatus');
    if (localEngineLabel) {
        if (localEngineStatus.available) {
            const engineVersion = localEngineStatus.rules_version || localEngineRules.version || 0;
            localEngineLabel.textContent = isLocalhostUrl(LOCAL_ENGINE)
                ? `Local ${formatVersion(engineVersion)}`
                : `Online ${formatVersion(engineVersion)}`;
        } else if (localEngineStatus.configRequired) {
            localEngineLabel.textContent = 'Config required';
        } else if (localEngineStatus.authRequired) {
            localEngineLabel.textContent = 'Tunnel login required';
        } else if (Array.isArray(localPolicy.rules) && localPolicy.rules.length) {
            localEngineLabel.textContent = 'Offline - policy active';
        } else if (localEngineStatus.error) {
            localEngineLabel.textContent = 'Offline';
        } else {
            localEngineLabel.textContent = 'Checking...';
        }
    }

    const localEngineIndicator = document.getElementById('localEngine');
    if (localEngineIndicator) {
        if (localEngineStatus.available) {
            localEngineIndicator.textContent = isLocalhostUrl(LOCAL_ENGINE) ? 'Running (Local)' : 'Running';
            localEngineIndicator.className = 'status-value ok';
        } else if (localEngineStatus.configRequired) {
            localEngineIndicator.textContent = 'Config Required';
            localEngineIndicator.className = 'status-value warning';
        } else if (localEngineStatus.authRequired) {
            localEngineIndicator.textContent = 'Tunnel Login';
            localEngineIndicator.className = 'status-value warning';
        } else if (Array.isArray(localPolicy.rules) && localPolicy.rules.length) {
            localEngineIndicator.textContent = 'Policy Active';
            localEngineIndicator.className = 'status-value warning';
        } else if (localEngineStatus.error) {
            localEngineIndicator.textContent = 'Offline';
            localEngineIndicator.className = 'status-value error';
        } else {
            localEngineIndicator.textContent = 'Checking...';
            localEngineIndicator.className = 'status-value warning';
        }
    }

    renderRuleChangeHistory(history);
}

function renderRuleChangeHistory(history) {
    const container = document.getElementById('ruleChangeHistory');
    if (!container) {
        return;
    }

    if (!Array.isArray(history) || history.length === 0) {
        container.innerHTML = '<div class="empty-history">No rule changes recorded yet.</div>';
        return;
    }

    const items = history.slice(0, 5).map((entry) => {
        const detailBits = [];

        (entry.listChanges || []).slice(0, 2).forEach((change) => {
            const counts = [];
            if (change.addedCount) {
                counts.push(`+${change.addedCount}`);
            }
            if (change.removedCount) {
                counts.push(`-${change.removedCount}`);
            }
            if (change.changedCount) {
                counts.push(`~${change.changedCount}`);
            }
            detailBits.push(`${humanizeKey(change.key)} ${counts.join(' / ')}`);
        });

        if (entry.scalarChanges && entry.scalarChanges.length) {
            detailBits.push(`${entry.scalarChanges.length} property changes`);
        }

        if (entry.note) {
            detailBits.unshift(entry.note);
        }

        return `
            <div class="rule-change-item">
                <div class="rule-change-top">
                    <span class="rule-change-badge ${escapeHtml(entry.scope || 'local')}">${escapeHtml(entry.scope || 'local')}</span>
                    <span class="rule-change-target">${escapeHtml(formatRuleTarget(entry.target))}</span>
                    <span class="rule-change-time">${escapeHtml(getTimeAgo(entry.timestamp))}</span>
                </div>
                <div class="rule-change-summary">${escapeHtml(entry.summary || 'Rules changed')}</div>
                ${detailBits.length ? `<div class="rule-change-detail">${escapeHtml(detailBits.join(' | '))}</div>` : ''}
            </div>
        `;
    }).join('');

    container.innerHTML = items;
}

function formatRuleTarget(target) {
    if (!target) {
        return 'rules';
    }

    return String(target).replace(/[-_]+/g, ' ');
}

function buildConsolePolicyVersionLabel(policy) {
    const rules = Array.isArray(policy && policy.rules) ? policy.rules : [];
    const activeRules = rules.filter((rule) => rule && rule.enabled !== false);
    const blockingRules = activeRules.filter((rule) => rule.block);

    return activeRules.length
        ? `1:${activeRules.length}:b${blockingRules.length}`
        : `0:0:b${blockingRules.length}`;
}

function isLegacyConsolePolicyHistorySummary(summary) {
    const text = String(summary || '').trim();
    if (!text) {
        return true;
    }

    if (/^Rule versions:/i.test(text)) {
        return false;
    }

    return /^version\s+(?:none|\d+)(?:\s*->\s*(?:none|\d+))?(?:\s*,.*)?$/i.test(text);
}

function buildConsolePolicyHistorySummary(entry, localPolicy) {
    const previousVersion = typeof entry?.previousVersion === 'string' && entry.previousVersion
        ? entry.previousVersion
        : '';
    const nextVersion = typeof entry?.nextVersion === 'string' && entry.nextVersion
        ? entry.nextVersion
        : buildConsolePolicyVersionLabel(localPolicy);

    if (previousVersion && nextVersion && previousVersion !== nextVersion) {
        return `Rule versions: ${previousVersion} -> ${nextVersion}`;
    }

    return `Rule versions: ${nextVersion}`;
}

function normalizeRuleHistoryEntry(entry, context = {}) {
    if (!entry || typeof entry !== 'object') {
        return entry;
    }

    if (entry.target !== 'console-policy') {
        return entry;
    }

    const localPolicy = context.localPolicy || {};
    const versionLabel = typeof entry.nextVersion === 'string' && entry.nextVersion
        ? entry.nextVersion
        : buildConsolePolicyVersionLabel(localPolicy);
    const normalizedSummary = isLegacyConsolePolicyHistorySummary(entry.summary)
        ? buildConsolePolicyHistorySummary(entry, localPolicy)
        : entry.summary;

    return {
        ...entry,
        nextVersion: versionLabel,
        summary: normalizedSummary
    };
}

function humanizeKey(key) {
    return String(key || 'rules').replace(/[_-]+/g, ' ');
}

function buildLatestChangeText(entry) {
    if (!entry) {
        return 'No changes yet';
    }

    return `${entry.summary || 'Rules changed'} • ${getTimeAgo(entry.timestamp)}`;
}

function buildDisplayRuleHistory(data) {
    const globalRules = data.firewall_rules || {};
    const localPolicy = data.console_firewall_policy || {};
    const localEngineRules = data.local_engine_rules || {};
    const history = (Array.isArray(data.rule_change_history) ? data.rule_change_history : [])
        .map((entry) => normalizeRuleHistoryEntry(entry, { localPolicy }));
    const hasGlobalHistory = history.some((entry) => entry && entry.scope === 'global');
    const hasLocalHistory = history.some((entry) => entry && entry.scope === 'local');
    const timestamp = new Date().toISOString();

    if (!hasGlobalHistory && (Array.isArray(globalRules.blocked_domains) || Array.isArray(globalRules.rule_sets))) {
        history.push({
            id: 'derived-global-history',
            scope: 'global',
            target: 'server-rules',
            timestamp: timestamp,
            summary: `version ${globalRules.version || data.rules_version || 0} loaded`,
            note: 'Current global firewall rules loaded',
            listChanges: [],
            scalarChanges: []
        });
    }

    if (!hasLocalHistory) {
        if (Array.isArray(localPolicy.rules) && localPolicy.rules.length) {
            history.push({
                id: 'derived-local-policy-history',
                scope: 'local',
                target: 'console-policy',
                timestamp: timestamp,
                summary: `Rule versions: ${buildConsolePolicyVersionLabel(localPolicy)}`,
                note: 'Current local console firewall rules loaded',
                listChanges: [],
                scalarChanges: []
            });
        } else if (localEngineRules && localEngineRules.version !== undefined) {
            history.push({
                id: 'derived-local-engine-history',
                scope: 'local',
                target: 'engine',
                timestamp: timestamp,
                summary: `version ${localEngineRules.version || 0} loaded`,
                note: 'Current local engine rules loaded',
                listChanges: [],
                scalarChanges: []
            });
        }
    }

    return history.sort((left, right) => new Date(right.timestamp) - new Date(left.timestamp));
}

function buildLatestChangeText(entry) {
    if (!entry) {
        return 'No changes yet';
    }

    return `${entry.summary || 'Rules changed'} - ${getTimeAgo(entry.timestamp)}`;
}

function formatVersion(version) {
    const normalized = version || 0;
    return `v${normalized}`;
}

function getTimeAgo(timestamp) {
    const currentTime = Date.now();
    const value = new Date(timestamp).getTime();
    const diffMs = currentTime - value;

    if (!Number.isFinite(diffMs) || diffMs < 60000) {
        return 'just now';
    }

    const diffMinutes = Math.floor(diffMs / 60000);
    if (diffMinutes < 60) {
        return `${diffMinutes}m ago`;
    }

    const diffHours = Math.floor(diffMs / 3600000);
    if (diffHours < 24) {
        return `${diffHours}h ago`;
    }

    const diffDays = Math.floor(diffMs / 86400000);
    return `${diffDays}d ago`;
}

function setText(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value;
    }
}

function testConnection() {
    const statusElement = document.getElementById('serverStatus');
    if (statusElement) {
        statusElement.textContent = 'Testing...';
        statusElement.className = 'status-value warning';
    }

    if (!hasConfiguredEndpointConfig(getCurrentEndpointConfig())) {
        if (statusElement) {
            statusElement.textContent = 'Config Required';
            statusElement.className = 'status-value warning';
        }
        showNotification('Connection Test', TUNNEL_CONFIG_REQUIRED_MESSAGE);
        return;
    }

    refreshServerStatus();
    showNotification('Connection Test', 'Backend status check started');
}

function launchAutomatedBrowser() {
    const config = getAutomatedBrowserConfig();

    chrome.runtime.sendMessage({ action: 'launchAutomatedBrowser', config: config }, (response) => {
        if (response && response.success) {
            updateAutomationSessionDisplay({
                sessionId: response.sessionId,
                type: 'automated_browser',
                status: 'active',
                config: config
            });
            checkSessionId();
            showNotification('Browser Launch', 'Automated browser launched successfully');
        } else {
            showNotification('Browser Launch', 'Failed to launch automated browser');
        }
    });
}

function getSearchEngineBases() {
    const bases = [];
    const addBase = (value) => {
        const normalized = normalizeBaseUrl(value, '');
        if (normalized && !bases.includes(normalized)) {
            bases.push(normalized);
        }
    };

    addBase(SEARCH_APP_BASE_OVERRIDE);
    addBase(SEARCH_APP_BASE);
    addBase(SEARCH_APP_FALLBACK_BASE);

    return bases;
}

function applySearchEngineStatus(statusText, previewText, baseUrl) {
    const statusElement = document.getElementById('searchEngineStatus');
    const urlElement = document.getElementById('searchEngineUrl');
    const previewElement = document.getElementById('searchEnginePreview');

    if (statusElement) {
        statusElement.textContent = statusText;
    }
    if (urlElement) {
        urlElement.textContent = baseUrl || SEARCH_APP_BASE;
    }
    if (previewElement) {
        previewElement.textContent = previewText;
    }
}

async function resolveSearchEngineBase() {
    for (const baseUrl of getSearchEngineBases()) {
        try {
            const healthUrl = `${baseUrl}/health`;
            const response = await fetch(healthUrl, createTunnelAwareRequestOptions(healthUrl));
            if (!response.ok) {
                continue;
            }

            const payload = await response.json();
            return {
                baseUrl,
                payload
            };
        } catch (error) {
            // Try the next candidate base.
        }
    }

    return null;
}

async function refreshSearchEngineStatus(showNotification) {
    const resolved = await resolveSearchEngineBase();
    if (resolved) {
        applySearchEngineStatus(
            'Ready',
            'Search engine is running. Click Launch Search Engine to open it in a browser tab.',
            resolved.baseUrl
        );
        if (showNotification) {
            showNotification('Search Engine', 'Search engine is online');
        }
        return;
    }

    applySearchEngineStatus(
        'Offline',
        'Search engine is offline. Start it with: python search/search.py',
        SEARCH_APP_BASE
    );
    if (showNotification) {
        showNotification('Search Engine', 'Start it with: python search/search.py');
    }
}

async function launchSearchEngine() {
    const resolved = await resolveSearchEngineBase();
    if (!resolved) {
        applySearchEngineStatus(
            'Offline',
            'Search engine is offline. Start it with: python search/search.py',
            SEARCH_APP_BASE
        );
        showNotification('Search Engine', 'Search engine is offline. Start python search/search.py first');
        return;
    }

    chrome.tabs.create({
        url: resolved.baseUrl,
        active: true
    });
}

async function requestLocalRunner(path, options = {}) {
    if (!popupCspAllowsLocalhostConnections()) {
        throw new Error(LOCALHOST_CSP_REQUIRED_MESSAGE);
    }

    const candidateBases = getLocalRunnerApiBases();
    let lastError = null;
    let runnerEndpointMissing = false;

    for (const baseUrl of candidateBases) {
        const url = `${baseUrl}${path}`;

        try {
            const response = await fetch(url, createTunnelAwareRequestOptions(url, options));
            let payload = null;

            try {
                payload = await response.json();
            } catch (error) {
                payload = null;
            }

            if (response.ok && payload && payload.success !== false) {
                return payload;
            }

            if (response.status === 404) {
                const serverRoot = baseUrl.replace(/\/api\/local-browser$/i, '');
                const serverStatusAvailable = await probeLocalRunnerServerStatus(serverRoot);
                if (serverStatusAvailable) {
                    runnerEndpointMissing = true;
                }
            }

            const message = payload?.error || `Local runner request failed (${response.status})`;
            lastError = new Error(message);
        } catch (error) {
            lastError = error instanceof Error ? error : new Error(String(error));
        }
    }

    if (runnerEndpointMissing) {
        throw new Error('Runner endpoint missing on the active extension server. Restart extension services with start_firewall.bat option 8 or rerun start_dev_tunnels.sh.');
    }

    throw new Error(normalizeLocalRunnerNetworkError(lastError, path, candidateBases));
}

function getLocalRunnerApiBases() {
    const bases = [];
    const addBase = (value) => {
        const normalized = normalizeBaseUrl(value, '');
        if (normalized && !bases.includes(normalized)) {
            bases.push(normalized);
        }
    };

    const tunnelPrimary = normalizeBaseUrl(
        LOCAL_RUNNER_API_BASE_OVERRIDE || toLocalRunnerApiBase(deriveExtensionServerBaseFromBackendApi(API_BASE)),
        ''
    );
    const useTunnelOnly = isDevTunnelUrl(tunnelPrimary);

    addBase(tunnelPrimary);

    if (!useTunnelOnly) {
        addBase(LOCAL_RUNNER_API_BASE);
        addBase(LOCAL_RUNNER_FALLBACK_API_BASE);
    }

    try {
        const localEngineUrl = new URL(normalizeBaseUrl(LOCAL_ENGINE, ''));
        const hostname = localEngineUrl.hostname.toLowerCase();
        if (!useTunnelOnly && (hostname === 'localhost' || hostname === '127.0.0.1')) {
            addBase(`${localEngineUrl.protocol}//${hostname}:6000/api/local-browser`);
        }
    } catch (error) {
        // Keep default candidates when local engine endpoint is unavailable.
    }

    return bases;
}

async function probeLocalRunnerServerStatus(serverRoot) {
    try {
        const statusUrl = `${serverRoot}/api/status`;
        const response = await fetch(statusUrl, createTunnelAwareRequestOptions(statusUrl));
        return response.status >= 200 && response.status < 500;
    } catch (error) {
        return false;
    }
}

function normalizeLocalRunnerNetworkError(error, path, candidateBases) {
    const message = error && error.message ? error.message : String(error || '');
    if (/failed to fetch|networkerror|load failed|fetch failed/i.test(message)) {
        const urls = candidateBases.map((base) => `${base}${path}`).join(' or ');
        return `Unable to reach runner API (${urls}). Ensure Dev Tunnel port 6000 is active, then click Refresh Status.`;
    }

    return message || 'Local runner request failed';
}

function refreshLocalRunnerStatus(showNotification) {
    requestLocalRunner('/status')
        .then((payload) => {
            applyLocalRunnerStatus(payload.runner || {}, payload.runner?.last_result || null);
            if (showNotification) {
                showNotificationMessage('Local Runner', 'Status refreshed');
            }
        })
        .catch((error) => {
            const statusElement = document.getElementById('localRunnerStatus');
            const summaryElement = document.getElementById('localRunnerSummary');
            const previewElement = document.getElementById('localRunnerPreview');

            if (statusElement) {
                statusElement.textContent = 'Unavailable';
            }
            if (summaryElement) {
                summaryElement.textContent = 'Runner offline';
            }
            if (previewElement) {
                previewElement.textContent = error.message;
            }
            if (showNotification) {
                showNotificationMessage('Local Runner', error.message);
            }
        });
}

function normalizeRunnableTargetValue(value) {
    return typeof value === 'string' ? value.trim() : '';
}

function normalizeRunnableTargetUrl(value) {
    const candidate = normalizeRunnableTargetValue(value);
    return /^https?:\/\//i.test(candidate) ? candidate : '';
}

function getStoredCurrentSessionUrl() {
    return new Promise((resolve) => {
        chrome.storage.local.get('firewall_guard_sessions', (result) => {
            const sessionUrl = normalizeRunnableTargetUrl(
                result?.firewall_guard_sessions?.currentSession?.url
            );
            resolve(sessionUrl);
        });
    });
}

function getActivePageUrl() {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: 'getSiteInfo' }, (response) => {
            if (chrome.runtime.lastError || !response?.success) {
                resolve('');
                return;
            }

            resolve(normalizeRunnableTargetUrl(response?.siteInfo?.url));
        });
    });
}

async function resolveLocalRunnerTargetValue(options = {}) {
    const targetInput = document.getElementById('localRunnerUrl');
    const manualTarget = normalizeRunnableTargetValue(targetInput ? targetInput.value : '');
    if (manualTarget) {
        return manualTarget;
    }

    if (options.initiatedFromAutomationControl) {
        const sessionUrl = await getStoredCurrentSessionUrl();
        if (sessionUrl) {
            if (targetInput) {
                targetInput.value = sessionUrl;
            }
            return sessionUrl;
        }
    }

    const activePageUrl = await getActivePageUrl();
    if (activePageUrl) {
        if (targetInput) {
            targetInput.value = activePageUrl;
        }
        return activePageUrl;
    }

    return '';
}

async function runLocalRunnerTask(options = {}) {
    const notificationTitle = options.initiatedFromAutomationControl ? 'Headless Browser' : 'Local Runner';
    const targetValue = await resolveLocalRunnerTargetValue(options);

    if (!targetValue) {
        showNotificationMessage(
            notificationTitle,
            options.initiatedFromAutomationControl
                ? 'No active browser URL found. Launch a browser session first or enter a URL or search query below.'
                : 'Enter a target URL or search query first'
        );
        return;
    }

    const statusElement = document.getElementById('localRunnerStatus');
    const summaryElement = document.getElementById('localRunnerSummary');

    if (statusElement) {
        statusElement.textContent = 'Running';
    }
    if (summaryElement) {
        summaryElement.textContent = 'Task in progress...';
    }

    const payload = {
        url: targetValue,
        ...getLocalRunnerConfig(),
        timeoutSeconds: 25
    };

    requestLocalRunner('/run', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
    })
        .then((responsePayload) => {
            const result = responsePayload.result || null;
            latestLocalRunnerResult = result;
            applyLocalRunnerStatus(
                {
                    running: false,
                    last_completed_at: result?.timestamp || new Date().toISOString(),
                    last_result: result,
                    playwright_available: true
                },
                result
            );
            openLocalRunnerResultPage({
                result,
                active: true,
                silent: true
            });
        })
        .catch((error) => {
            const statusValue = document.getElementById('localRunnerStatus');
            const summaryValue = document.getElementById('localRunnerSummary');
            const previewValue = document.getElementById('localRunnerPreview');

            if (statusValue) {
                statusValue.textContent = 'Error';
            }
            if (summaryValue) {
                summaryValue.textContent = 'Task failed';
            }
            if (previewValue) {
                previewValue.textContent = error.message;
            }
            showNotificationMessage(notificationTitle, error.message);
        });
}

function getLocalRunnerResultUrl(result) {
    const finalUrl = typeof result?.final_url === 'string' ? result.final_url.trim() : '';
    if (finalUrl) {
        return finalUrl;
    }

    const targetUrl = typeof result?.target_url === 'string' ? result.target_url.trim() : '';
    return targetUrl;
}

function updateLocalRunnerPageButton(result) {
    const button = document.getElementById('openLocalRunnerPageBtn');
    if (!button) {
        return;
    }

    const url = getLocalRunnerResultUrl(result);
    button.disabled = !url;
    button.title = url || 'Run a headless task first';
}

function openLocalRunnerResultPage(options = {}) {
    const result = options.result || latestLocalRunnerResult;
    const url = getLocalRunnerResultUrl(result);
    if (!url) {
        if (!options.silent) {
            showNotificationMessage('Local Runner', 'No webpage available yet');
        }
        return;
    }

    chrome.tabs.create({
        url,
        active: options.active !== false
    });
}

function truncateLocalRunnerText(value, maxLength = 56) {
    const text = typeof value === 'string' ? value.trim() : '';
    if (!text || text.length <= maxLength) {
        return text;
    }

    return `${text.slice(0, maxLength - 1).trim()}...`;
}

function buildLocalRunnerSummary(result) {
    if (!result) {
        return 'No result yet';
    }

    if (result.mode === 'search') {
        const query = truncateLocalRunnerText(result.query || result.input || 'Search', 34);
        const count = result.search_result_count || 0;
        const source = truncateLocalRunnerText(result.source_title || result.title || '', 24);
        return source
            ? `Search: ${query} | ${count} results | ${source}`
            : `Search: ${query} | ${count} results`;
    }

    return `${result.title || 'Untitled'} | ${result.text_length || 0} chars | ${result.image_count || 0} images`;
}

function buildLocalRunnerPreview(result) {
    if (!result) {
        return 'No headless result yet.';
    }

    const lines = [];
    const openedUrl = result.search_page_url || result.target_url || '';
    const finalUrl = result.final_url || '';

    if (openedUrl) {
        lines.push(`Opened page: ${openedUrl}`);
    }
    if (finalUrl && finalUrl !== openedUrl) {
        lines.push(`Final page: ${finalUrl}`);
    }
    if (lines.length) {
        lines.push('');
    }

    if (result.text_preview) {
        lines.push(result.text_preview);
        return lines.join('\n');
    }

    if (result.answer) {
        lines.push(result.answer);
        return lines.join('\n');
    }

    lines.push('No headless result yet.');
    return lines.join('\n');
}

function applyLocalRunnerStatus(runner, result) {
    const statusElement = document.getElementById('localRunnerStatus');
    const lastRunElement = document.getElementById('localRunnerLastRun');
    const summaryElement = document.getElementById('localRunnerSummary');
    const previewElement = document.getElementById('localRunnerPreview');

    const available = Boolean(runner.playwright_available);
    const running = Boolean(runner.running);
    const activeResult = result || runner.last_result || null;
    latestLocalRunnerResult = activeResult;
    updateLocalRunnerPageButton(activeResult);

    if (statusElement) {
        if (!available) {
            statusElement.textContent = 'Setup Required';
        } else if (running) {
            statusElement.textContent = 'Running';
        } else {
            statusElement.textContent = 'Ready';
        }
    }

    if (lastRunElement) {
        if (runner.last_completed_at) {
            lastRunElement.textContent = getTimeAgo(runner.last_completed_at);
        } else {
            lastRunElement.textContent = 'None';
        }
    }

    if (summaryElement) {
        if (!available && runner.playwright_error) {
            summaryElement.textContent = 'Install Playwright';
        } else if (activeResult) {
            summaryElement.textContent = buildLocalRunnerSummary(activeResult);
        } else {
            summaryElement.textContent = 'No result yet';
        }
    }

    if (previewElement) {
        if (!available && runner.playwright_error) {
            previewElement.textContent = 'Playwright missing. Run: pip install playwright && python -m playwright install chromium';
        } else if (activeResult) {
            previewElement.textContent = buildLocalRunnerPreview(activeResult);
        } else if (runner.last_error) {
            previewElement.textContent = runner.last_error;
        } else {
            previewElement.textContent = 'No headless result yet.';
        }
    }
}

function refreshAutomationSessions(showMessage) {
    chrome.runtime.sendMessage({ action: 'getActiveSessions' }, (response) => {
        if (chrome.runtime.lastError) {
            if (showMessage) {
                showNotification('Sessions', chrome.runtime.lastError.message);
            }
            return;
        }

        if (!response || !response.success) {
            updateAutomationSessionDisplay(null);
            if (showMessage) {
                showNotification('Sessions', response?.error || 'Failed to get active sessions');
            }
            return;
        }

        const sessions = Array.isArray(response.sessions) ? response.sessions : [];
        updateAutomationSessionDisplay(sessions[0] || null);

        if (showMessage) {
            showNotification('Sessions', sessions.length ? `${sessions.length} active session(s) found` : 'No active session');
        }
    });
}

function bindAutomationOptionChangeHandlers() {
    AUTOMATION_OPTION_FIELDS.forEach((id) => {
        const element = document.getElementById(id);
        if (!element) {
            return;
        }

        element.addEventListener('change', saveAutomatedBrowserSettings);
    });
}

function bindLocalRunnerOptionChangeHandlers() {
    LOCAL_RUNNER_OPTION_FIELDS.forEach((id) => {
        const element = document.getElementById(id);
        if (!element) {
            return;
        }

        element.addEventListener('change', () => {
            saveLocalRunnerSettings();
            refreshAutomationModeUI();
        });
    });
}

function loadAutomatedBrowserSettings() {
    chrome.storage.local.get(AUTOMATION_OPTIONS_KEY, (result) => {
        const options = result[AUTOMATION_OPTIONS_KEY] || {};

        setCheckboxValue('incognitoMode', Boolean(options.incognito));
        setCheckboxValue('blockAdsMode', options.blockAds !== false);
        setCheckboxValue('disableCssMode', Boolean(options.disableCss));
        setCheckboxValue('interceptClicksMode', Boolean(options.interceptClicks));
        setCheckboxValue('interceptFormsMode', Boolean(options.interceptForms));
    });
}

function loadLocalRunnerSettings() {
    chrome.storage.local.get(LOCAL_RUNNER_OPTIONS_KEY, (result) => {
        const options = result[LOCAL_RUNNER_OPTIONS_KEY] || {};

        setCheckboxValue('localRunnerHeadless', options.headless !== false);
        setCheckboxValue('localRunnerLightweight', options.lightweightMode !== false);
        setCheckboxValue('localRunnerTextOnly', Boolean(options.textOnlyMode));
        setCheckboxValue('localRunnerAllowImages', options.allowImages !== false);
        refreshAutomationModeUI();
    });
}

function saveAutomatedBrowserSettings() {
    chrome.storage.local.set({
        [AUTOMATION_OPTIONS_KEY]: getAutomatedBrowserConfig()
    });
}

function saveLocalRunnerSettings() {
    chrome.storage.local.set({
        [LOCAL_RUNNER_OPTIONS_KEY]: getLocalRunnerConfig()
    });
}

function getAutomatedBrowserConfig() {
    return {
        headless: false,
        incognito: isChecked('incognitoMode'),
        blockAds: isChecked('blockAdsMode'),
        disableCss: isChecked('disableCssMode'),
        interceptClicks: isChecked('interceptClicksMode'),
        interceptForms: isChecked('interceptFormsMode')
    };
}

function getLocalRunnerConfig() {
    return {
        headless: isChecked('localRunnerHeadless'),
        lightweightMode: isChecked('localRunnerLightweight'),
        textOnlyMode: isChecked('localRunnerTextOnly'),
        allowImages: isChecked('localRunnerAllowImages')
    };
}

function refreshAutomationModeUI() {
    const primaryLabel = document.getElementById('automationPrimaryLabel');
    const launchButton = document.getElementById('launchBrowserBtn');
    const helperNote = document.getElementById('automationHelperNote');
    const sessionRow = document.getElementById('automationSessionRow');
    const sessionsButton = document.getElementById('getSessionsBtn');

    if (primaryLabel) {
        primaryLabel.textContent = 'Automated Browser Actions';
    }

    if (launchButton) {
        launchButton.textContent = 'Launch Browser';
    }

    if (helperNote) {
        helperNote.textContent = 'Launch Browser opens a visible extension-controlled browser. Use the search engine section below to launch the local search app from the search folder.';
    }

    if (sessionsButton) {
        sessionsButton.disabled = false;
        sessionsButton.title = '';
    }

    if (sessionRow) {
        sessionRow.style.opacity = '1';
    }
}

function updateAutomationSessionDisplay(session) {
    const element = document.getElementById('automationCurrentSession');
    if (!element) {
        return;
    }

    if (!session || !session.sessionId) {
        element.textContent = 'No active session';
        element.title = '';
        return;
    }

    const sessionType = humanizeSessionType(session.type || 'automated_browser');
    element.textContent = `${session.sessionId} (${sessionType})`;

    const optionSummary = buildSessionOptionSummary(session.config || {});
    element.title = optionSummary ? `Options: ${optionSummary}` : sessionType;
}

function buildSessionOptionSummary(config) {
    const enabled = [];

    if (config.incognito) {
        enabled.push('Incognito');
    }
    if (config.blockAds !== false) {
        enabled.push('Block Ads');
    }
    if (config.disableCss) {
        enabled.push('Disable CSS');
    }
    if (config.interceptClicks) {
        enabled.push('Intercept Clicks');
    }
    if (config.interceptForms) {
        enabled.push('Intercept Forms');
    }

    return enabled.join(', ');
}

function humanizeSessionType(type) {
    return String(type || 'session').replace(/[_-]+/g, ' ');
}

function isChecked(id) {
    const element = document.getElementById(id);
    return Boolean(element && element.checked);
}

function setCheckboxValue(id, checked) {
    const element = document.getElementById(id);
    if (element) {
        element.checked = checked;
    }
}

function forceSessionForCurrentTab() {
    chrome.runtime.sendMessage({ action: 'forceCreateSession' }, (response) => {
        if (response && response.success) {
            checkSessionId();
            showNotification('Session Created', `Forced session created: ${response.sessionId}`);
            return;
        }

        showNotification('Session Error', response?.error || 'Failed to create forced session');
    });
}

function clearCurrentSession() {
    chrome.runtime.sendMessage({ action: 'forceCleanupSessions' }, (response) => {
        if (response && response.success) {
            checkSessionId();
            showNotification('Session Cleared', response.message || 'Current session cleared');
            return;
        }

        showNotification('Session Error', response?.error || 'Failed to clear current session');
    });
}

function openDashboard() {
    chrome.tabs.create({ url: chrome.runtime.getURL('browser_control.html') });
}

function checkUpdate() {
    chrome.runtime.sendMessage({ action: 'checkUpdate' }, (response) => {
        if (response && response.success) {
            refreshFirewallRuleState(false);
            showNotification('Update Check', response.message || 'Firewall rule check completed');
        } else {
            showNotification('Update Check', response?.error || 'Failed to check for updates');
        }
    });
}

function showConsoleCommands() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const activeTab = tabs && tabs[0] ? tabs[0] : null;

        chrome.runtime.sendMessage({
            action: 'startConsoleCapture',
            tabId: activeTab ? activeTab.id : null
        }, () => {
            void chrome.runtime.lastError;
            chrome.tabs.create({ url: chrome.runtime.getURL('console_popup.html') });
        });
    });
}

function openAITestingPanel() {
    chrome.tabs.create({
        url: chrome.runtime.getURL('ai_testing_panel_working.html'),
        active: true
    });
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function showNotification(title, message) {
    console.log(`[Popup] Notification: ${title} - ${message}`);

    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 10px;
        right: 10px;
        background: #333;
        color: white;
        padding: 10px;
        border-radius: 5px;
        z-index: 10000;
        font-size: 12px;
        max-width: 300px;
    `;
    notification.innerHTML = `
        <div style="font-weight: 600; margin-bottom: 4px;">${escapeHtml(title)}</div>
        <div>${escapeHtml(message)}</div>
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
        }
    }, 3000);
}

function showNotificationMessage(title, message) {
    showNotification(title, message);
}
