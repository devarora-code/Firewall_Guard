(function () {
    const { useEffect, useRef, useState } = React;
    const e = React.createElement;
    const DEFAULT_API_BASE = 'http://localhost:5000/api';
    const DEFAULT_LOCAL_ENGINE = 'http://localhost:7000/api';
    const AUTOMATION_OPTIONS_KEY = 'automated_browser_options';
    const RULE_STORAGE_KEYS = [
        'firewall_rules',
        'rules_version',
        'console_firewall_policy',
        'local_engine_rules',
        'local_engine_status',
        'rule_change_history'
    ];
    const OPTION_LABELS = {
        headlessMode: 'Headless Mode',
        incognitoMode: 'Incognito Mode',
        blockAdsMode: 'Block Ads',
        interceptClicksMode: 'Intercept Clicks',
        interceptFormsMode: 'Intercept Forms'
    };

    function cls(base, tone) {
        return tone && tone !== 'neutral' ? `${base} ${tone}` : base;
    }

    function message(payload) {
        return new Promise((resolve, reject) => {
            try {
                chrome.runtime.sendMessage(payload, (response) => {
                    if (chrome.runtime.lastError) {
                        reject(new Error(chrome.runtime.lastError.message));
                        return;
                    }
                    resolve(response);
                });
            } catch (error) {
                reject(error);
            }
        });
    }

    function getStorage(keys) {
        return new Promise((resolve) => chrome.storage.local.get(keys, resolve));
    }

    function setStorage(value) {
        return new Promise((resolve, reject) => {
            chrome.storage.local.set(value, () => {
                if (chrome.runtime.lastError) {
                    reject(new Error(chrome.runtime.lastError.message));
                    return;
                }
                resolve();
            });
        });
    }

    function createTab(url, active) {
        return new Promise((resolve, reject) => {
            chrome.tabs.create({ url: url, active: active !== false }, (tab) => {
                if (chrome.runtime.lastError) {
                    reject(new Error(chrome.runtime.lastError.message));
                    return;
                }
                resolve(tab);
            });
        });
    }

    function queryTabs(queryInfo) {
        return new Promise((resolve, reject) => {
            chrome.tabs.query(queryInfo, (tabs) => {
                if (chrome.runtime.lastError) {
                    reject(new Error(chrome.runtime.lastError.message));
                    return;
                }
                resolve(tabs);
            });
        });
    }

    function normalizeApiBase(value, fallback) {
        const normalized = (typeof value === 'string' && value.trim() ? value.trim() : fallback).replace(/\/+$/, '');
        return /\/api$/i.test(normalized) ? normalized : `${normalized}/api`;
    }

    function isHttpUrl(value) {
        try {
            const url = new URL(value);
            return url.protocol === 'http:' || url.protocol === 'https:';
        } catch (error) {
            return false;
        }
    }

    function summarizeEndpoint(value) {
        try {
            const url = new URL(value);
            const path = url.pathname && url.pathname !== '/' ? url.pathname.replace(/\/+$/, '') : '';
            return `${url.host}${path}`;
        } catch (error) {
            return value || 'not configured';
        }
    }

    function buildEndpointMode(mode, config) {
        const backendHost = summarizeEndpoint(config.backendApiBase);
        const localHost = summarizeEndpoint(config.localEngineApiBase);
        return mode === 'dev_tunnel'
            ? { mode: 'dev-tunnel', text: `Dev Tunnel mode active: backend ${backendHost} | engine ${localHost}` }
            : { mode: 'localhost', text: `Localhost mode active: backend ${backendHost} | engine ${localHost}` };
    }

    function formatVersion(version) {
        return `v${version || 0}`;
    }

    function timeAgo(timestamp) {
        const diffMs = Date.now() - new Date(timestamp).getTime();
        if (!Number.isFinite(diffMs) || diffMs < 60000) {
            return 'just now';
        }
        if (diffMs < 3600000) {
            return `${Math.floor(diffMs / 60000)}m ago`;
        }
        if (diffMs < 86400000) {
            return `${Math.floor(diffMs / 3600000)}h ago`;
        }
        return `${Math.floor(diffMs / 86400000)}d ago`;
    }

    function humanize(value, fallback) {
        return String(value || fallback || '').replace(/[_-]+/g, ' ');
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
        if (!entry || typeof entry !== 'object' || entry.target !== 'console-policy') {
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

    function latestChange(entry) {
        return entry ? `${entry.summary || 'Rules changed'} - ${timeAgo(entry.timestamp)}` : 'No changes yet';
    }

    function buildHistory(data) {
        const globalRules = data.firewall_rules || {};
        const localPolicy = data.console_firewall_policy || {};
        const localEngineRules = data.local_engine_rules || {};
        const history = (Array.isArray(data.rule_change_history) ? data.rule_change_history : [])
            .map((entry) => normalizeRuleHistoryEntry(entry, { localPolicy }));
        const stamp = new Date().toISOString();

        if (!history.some((entry) => entry && entry.scope === 'global') && (Array.isArray(globalRules.blocked_domains) || Array.isArray(globalRules.rule_sets))) {
            history.push({
                id: 'derived-global-history',
                scope: 'global',
                target: 'server-rules',
                timestamp: stamp,
                summary: `version ${globalRules.version || data.rules_version || 0} loaded`,
                note: 'Current global firewall rules loaded',
                listChanges: [],
                scalarChanges: []
            });
        }

        if (!history.some((entry) => entry && entry.scope === 'local')) {
            if (Array.isArray(localPolicy.rules) && localPolicy.rules.length) {
                history.push({
                    id: 'derived-local-policy-history',
                    scope: 'local',
                    target: 'console-policy',
                    timestamp: stamp,
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
                    timestamp: stamp,
                    summary: `version ${localEngineRules.version || 0} loaded`,
                    note: 'Current local engine rules loaded',
                    listChanges: [],
                    scalarChanges: []
                });
            }
        }

        return history.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 5);
    }

    function buildRuleState(data) {
        const globalRules = data.firewall_rules || {};
        const localPolicy = data.console_firewall_policy || {};
        const localEngineRules = data.local_engine_rules || {};
        const localEngineStatus = data.local_engine_status || {};
        const history = buildHistory(data);
        const globalChange = history.find((entry) => entry.scope === 'global');
        const localChange = history.find((entry) => entry.scope === 'local' && entry.target === 'console-policy')
            || history.find((entry) => entry.scope === 'local');
        const blockedCount = Array.isArray(globalRules.blocked_domains)
            ? globalRules.blocked_domains.length
            : (Array.isArray(globalRules.rule_sets) ? globalRules.rule_sets.length : 0);

        let engineText = 'Checking...';
        let engineTone = 'warning';
        let engineRulesText = 'Checking...';

        if (localEngineStatus.available) {
            engineText = 'Running';
            engineTone = 'ok';
            engineRulesText = `Online ${formatVersion(localEngineStatus.rules_version || localEngineRules.version || 0)}`;
        } else if (Array.isArray(localPolicy.rules) && localPolicy.rules.length) {
            engineText = 'Policy Active';
            engineTone = 'warning';
            engineRulesText = 'Offline - policy active';
        } else if (localEngineStatus.error) {
            engineText = 'Offline';
            engineTone = 'error';
            engineRulesText = 'Offline';
        }

        return {
            rulesVersion: formatVersion(data.rules_version || globalRules.version || 0),
            globalRulesVersion: formatVersion(globalRules.version || data.rules_version || 0),
            globalBlockedCount: String(blockedCount),
            globalRulesChange: latestChange(globalChange),
            localPolicyRuleCount: String(Array.isArray(localPolicy.rules) ? localPolicy.rules.length : 0),
            localRulesChange: latestChange(localChange),
            localEngineText: engineText,
            localEngineTone: engineTone,
            localEngineRulesText: engineRulesText,
            history: history
        };
    }

    function defaultRuleState() {
        return {
            rulesVersion: 'v0',
            globalRulesVersion: 'v0',
            globalBlockedCount: '0',
            globalRulesChange: 'No changes yet',
            localPolicyRuleCount: '0',
            localRulesChange: 'No changes yet',
            localEngineText: 'Checking...',
            localEngineTone: 'warning',
            localEngineRulesText: 'Checking...',
            history: []
        };
    }

    function defaultOptions() {
        return {
            headlessMode: false,
            incognitoMode: false,
            blockAdsMode: true,
            interceptClicksMode: false,
            interceptFormsMode: false
        };
    }

    function sessionSummary(config) {
        const enabled = [];
        if (config.headless) enabled.push('Headless');
        if (config.incognito) enabled.push('Incognito');
        if (config.blockAds !== false) enabled.push('Block Ads');
        if (config.interceptClicks) enabled.push('Intercept Clicks');
        if (config.interceptForms) enabled.push('Intercept Forms');
        return enabled.join(', ');
    }

    function StatusRow(props) {
        return e('div', { className: 'status-item' },
            e('span', { className: 'status-label' }, props.label),
            e('div', { className: 'status-item-end' },
                e('span', {
                    className: props.page
                        ? cls('page-status', props.tone)
                        : `${cls('status-value', props.tone)}${props.onValueClick ? ' clickable' : ''}`,
                    onClick: props.onValueClick || undefined,
                    title: props.title || ''
                }, props.value),
                props.button ? e('button', {
                    type: 'button',
                    className: props.button.className || 'refresh-btn',
                    onClick: props.button.onClick,
                    title: props.button.title || ''
                }, props.button.label) : null
            )
        );
    }

    function RuleHistory(props) {
        if (!props.items.length) {
            return e('div', { className: 'empty-history' }, 'No rule changes recorded yet.');
        }
        return props.items.map((entry) => {
            const details = [];
            (entry.listChanges || []).slice(0, 2).forEach((change) => {
                const counts = [];
                if (change.addedCount) counts.push(`+${change.addedCount}`);
                if (change.removedCount) counts.push(`-${change.removedCount}`);
                if (change.changedCount) counts.push(`~${change.changedCount}`);
                details.push(`${humanize(change.key, 'rules')} ${counts.join(' / ')}`);
            });
            if (entry.scalarChanges && entry.scalarChanges.length) {
                details.push(`${entry.scalarChanges.length} property changes`);
            }
            if (entry.note) {
                details.unshift(entry.note);
            }
            return e('div', { key: entry.id || `${entry.scope}-${entry.target}-${entry.timestamp}`, className: 'rule-change-item' },
                e('div', { className: 'rule-change-top' },
                    e('span', { className: cls('rule-change-badge', entry.scope || 'local') }, entry.scope || 'local'),
                    e('span', { className: 'rule-change-target' }, humanize(entry.target, 'rules')),
                    e('span', { className: 'rule-change-time' }, timeAgo(entry.timestamp))
                ),
                e('div', { className: 'rule-change-summary' }, entry.summary || 'Rules changed'),
                details.length ? e('div', { className: 'rule-change-detail' }, details.join(' | ')) : null
            );
        });
    }

    function NotificationStack(props) {
        return e('div', { className: 'notification-stack' },
            props.items.map((item) => e('div', { key: item.id, className: cls('popup-notification', item.tone) },
                e('div', { className: 'popup-notification-title' }, item.title),
                e('div', { className: 'popup-notification-message' }, item.message)
            ))
        );
    }

    function App() {
        const [pageStatus, setPageStatus] = useState({ value: 'Checking...', tone: 'neutral' });
        const [serverStatus, setServerStatus] = useState({ value: 'Checking...', tone: 'neutral' });
        const [sessionStatus, setSessionStatus] = useState({ value: 'None', tone: 'neutral', clickable: false, title: '' });
        const [currentSession, setCurrentSession] = useState(null);
        const [automationSession, setAutomationSession] = useState(null);
        const [ruleState, setRuleState] = useState(defaultRuleState());
        const [options, setOptions] = useState(defaultOptions());
        const [endpoints, setEndpoints] = useState({ backendApiBase: DEFAULT_API_BASE, localEngineApiBase: DEFAULT_LOCAL_ENGINE });
        const [endpointMode, setEndpointMode] = useState(buildEndpointMode('localhost', { backendApiBase: DEFAULT_API_BASE, localEngineApiBase: DEFAULT_LOCAL_ENGINE }));
        const [notifications, setNotifications] = useState([]);
        const endpointRef = useRef(endpoints);
        const optionsHydrated = useRef(false);
        const notificationId = useRef(0);

        useEffect(() => {
            endpointRef.current = endpoints;
        }, [endpoints]);

        function notify(title, body, tone) {
            const id = notificationId.current + 1;
            notificationId.current = id;
            setNotifications((current) => current.concat({ id: id, title: title, message: body, tone: tone || 'info' }));
            window.setTimeout(() => {
                setNotifications((current) => current.filter((item) => item.id !== id));
            }, 3000);
        }

        async function loadEndpoints() {
            try {
                const response = await message({ action: 'getEndpointConfig' });
                if (response && response.success && response.config) {
                    const config = {
                        backendApiBase: normalizeApiBase(response.config.backendApiBase, DEFAULT_API_BASE),
                        localEngineApiBase: normalizeApiBase(response.config.localEngineApiBase, DEFAULT_LOCAL_ENGINE)
                    };
                    setEndpoints(config);
                    setEndpointMode(buildEndpointMode(response.mode || 'localhost', config));
                    return config;
                }
            } catch (error) {
                console.warn('[Popup React] Failed to load endpoints:', error.message);
            }

            const fallback = { backendApiBase: DEFAULT_API_BASE, localEngineApiBase: DEFAULT_LOCAL_ENGINE };
            setEndpoints(fallback);
            setEndpointMode(buildEndpointMode('localhost', fallback));
            return fallback;
        }

        async function refreshPageStatus() {
            try {
                const response = await message({ action: 'getSiteInfo' });
                if (response && response.success && response.siteInfo) {
                    const url = response.siteInfo.url || '';
                    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
                        setPageStatus({ value: 'Secure Page', tone: 'neutral' });
                    } else if (url.startsWith('http://localhost') || url.startsWith('https://localhost')) {
                        setPageStatus({ value: 'Local Page', tone: 'ok' });
                    } else {
                        setPageStatus({ value: 'External Page', tone: 'warning' });
                    }
                    return;
                }
            } catch (error) {
                console.warn('[Popup React] Site info failed:', error.message);
            }

            setPageStatus({ value: 'No Site Info', tone: 'neutral' });
        }

        async function refreshServerStatus(config) {
            const activeConfig = config || endpointRef.current;
            const apiBase = normalizeApiBase(activeConfig.backendApiBase, DEFAULT_API_BASE);

            try {
                const response = await fetch(`${apiBase}/status`);
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }
                const data = await response.json();
                const healthy = Boolean(data && (data.success === true || data.status === 'running' || data.status === 'online' || data.server === 'running' || data.version));
                setServerStatus({ value: healthy ? 'Connected' : 'Unavailable', tone: healthy ? 'ok' : 'warning' });
                return;
            } catch (error) {
                console.warn('[Popup React] Backend fetch failed:', error.message);
            }

            try {
                const fallback = await message({ action: 'getBackendStatus' });
                setServerStatus({ value: fallback && fallback.connected ? 'Connected' : 'Offline', tone: fallback && fallback.connected ? 'ok' : 'error' });
            } catch (error) {
                setServerStatus({ value: 'Offline', tone: 'error' });
            }
        }

        async function refreshSession() {
            const result = await getStorage('firewall_guard_sessions');
            const storage = result.firewall_guard_sessions;

            if (storage && storage.currentSession && storage.currentSession.sessionId) {
                setCurrentSession(storage.currentSession);
                setSessionStatus({
                    value: storage.currentSession.sessionId,
                    tone: 'ok',
                    clickable: true,
                    title: 'Click to open Dashboard'
                });
                return;
            }

            setCurrentSession(null);
            setSessionStatus({ value: 'None', tone: 'neutral', clickable: false, title: '' });
        }

        async function loadStoredRules() {
            const result = await getStorage(RULE_STORAGE_KEYS);
            setRuleState(buildRuleState(result));
        }

        async function refreshRules(remote, toast) {
            try {
                const response = await message({ action: 'refreshRuleSnapshots', refreshRemote: Boolean(remote) });
                if (response && response.success) {
                    setRuleState(buildRuleState({
                        firewall_rules: response.globalRules,
                        rules_version: response.globalVersion,
                        console_firewall_policy: response.localPolicy,
                        local_engine_rules: response.localEngineRules,
                        local_engine_status: response.localEngineStatus,
                        rule_change_history: response.history
                    }));
                    if (toast) {
                        notify('Rules Refreshed', 'Global and local firewall rule snapshots updated', 'success');
                    }
                    return;
                }
            } catch (error) {
                console.warn('[Popup React] Rule refresh failed:', error.message);
            }

            await loadStoredRules();
            if (toast) {
                notify('Rules Refreshed', 'Loaded latest stored firewall rule history', 'info');
            }
        }

        async function refreshAutomationSessions(showToast) {
            try {
                const response = await message({ action: 'getActiveSessions' });
                const sessions = response && response.success && Array.isArray(response.sessions) ? response.sessions : [];
                setAutomationSession(sessions[0] || null);
                if (showToast) {
                    notify('Sessions', sessions.length ? `${sessions.length} active session(s) found` : 'No active session', sessions.length ? 'success' : 'info');
                }
            } catch (error) {
                setAutomationSession(null);
                if (showToast) {
                    notify('Sessions', error.message, 'error');
                }
            }
        }

        async function loadOptions() {
            const result = await getStorage(AUTOMATION_OPTIONS_KEY);
            const saved = result[AUTOMATION_OPTIONS_KEY] || {};
            setOptions({
                headlessMode: Boolean(saved.headless),
                incognitoMode: Boolean(saved.incognito),
                blockAdsMode: saved.blockAds !== false,
                interceptClicksMode: Boolean(saved.interceptClicks),
                interceptFormsMode: Boolean(saved.interceptForms)
            });
            optionsHydrated.current = true;
        }

        function launchConfig() {
            return {
                headless: options.headlessMode,
                incognito: options.incognitoMode,
                blockAds: options.blockAdsMode,
                interceptClicks: options.interceptClicksMode,
                interceptForms: options.interceptFormsMode
            };
        }

        async function saveEndpoints() {
            const config = {
                backendApiBase: normalizeApiBase(endpoints.backendApiBase, DEFAULT_API_BASE),
                localEngineApiBase: normalizeApiBase(endpoints.localEngineApiBase, DEFAULT_LOCAL_ENGINE)
            };

            if (!isHttpUrl(config.backendApiBase)) {
                notify('Endpoint Error', 'Backend API must be a valid http:// or https:// URL', 'error');
                return;
            }
            if (!isHttpUrl(config.localEngineApiBase)) {
                notify('Endpoint Error', 'Local engine must be a valid http:// or https:// URL', 'error');
                return;
            }

            try {
                const response = await message({ action: 'setEndpointConfig', config: config });
                if (!response || !response.success) {
                    notify('Endpoint Error', response && response.error ? response.error : 'Failed to save endpoints', 'error');
                    return;
                }

                const saved = {
                    backendApiBase: normalizeApiBase(response.config.backendApiBase, DEFAULT_API_BASE),
                    localEngineApiBase: normalizeApiBase(response.config.localEngineApiBase, DEFAULT_LOCAL_ENGINE)
                };
                setEndpoints(saved);
                setEndpointMode(buildEndpointMode(response.mode || 'localhost', saved));
                await refreshServerStatus(saved);
                await refreshRules(false, false);
                notify('Endpoints Saved', 'Runtime endpoints updated for this extension', 'success');
            } catch (error) {
                notify('Endpoint Error', error.message, 'error');
            }
        }

        async function resetEndpoints() {
            try {
                const response = await message({ action: 'resetEndpointConfig' });
                if (!response || !response.success) {
                    notify('Endpoint Error', response && response.error ? response.error : 'Failed to reset endpoints', 'error');
                    return;
                }

                const reset = {
                    backendApiBase: normalizeApiBase(response.config.backendApiBase, DEFAULT_API_BASE),
                    localEngineApiBase: normalizeApiBase(response.config.localEngineApiBase, DEFAULT_LOCAL_ENGINE)
                };
                setEndpoints(reset);
                setEndpointMode(buildEndpointMode(response.mode || 'localhost', reset));
                await refreshServerStatus(reset);
                await refreshRules(false, false);
                notify('Endpoints Reset', 'Switched back to localhost defaults', 'success');
            } catch (error) {
                notify('Endpoint Error', error.message, 'error');
            }
        }

        async function testConnection() {
            setServerStatus({ value: 'Testing...', tone: 'warning' });
            await refreshServerStatus();
            notify('Connection Test', 'Backend status check started', 'info');
        }

        async function launchBrowser() {
            try {
                const config = launchConfig();
                const response = await message({ action: 'launchAutomatedBrowser', config: config });
                if (response && response.success) {
                    setAutomationSession({
                        sessionId: response.sessionId,
                        windowId: response.windowId,
                        tabId: response.tabId,
                        url: response.url,
                        type: 'automated_browser',
                        status: 'active',
                        config: config
                    });
                    await refreshSession();
                    notify('Browser Launch', options.headlessMode ? 'Automated browser launched. Headless preference was saved, but extension-controlled Chrome windows remain visible.' : 'Automated browser launched successfully', 'success');
                    return;
                }
                notify('Browser Launch', 'Failed to launch automated browser', 'error');
            } catch (error) {
                notify('Browser Launch', error.message, 'error');
            }
        }

        async function forceSession() {
            try {
                const response = await message({ action: 'forceCreateSession' });
                if (response && response.success) {
                    await refreshSession();
                    notify('Session Created', `Forced session created: ${response.sessionId}`, 'success');
                    return;
                }
                notify('Session Error', response && response.error ? response.error : 'Failed to create forced session', 'error');
            } catch (error) {
                notify('Session Error', error.message, 'error');
            }
        }

        async function clearSession() {
            try {
                const response = await message({ action: 'forceCleanupSessions' });
                if (response && response.success) {
                    await refreshSession();
                    notify('Session Cleared', response.message || 'Current session cleared', 'success');
                    return;
                }
                notify('Session Error', response && response.error ? response.error : 'Failed to clear current session', 'error');
            } catch (error) {
                notify('Session Error', error.message, 'error');
            }
        }

        async function openDashboard() {
            try {
                await createTab(chrome.runtime.getURL('browser_control.html'));
            } catch (error) {
                notify('Dashboard', error.message, 'error');
            }
        }

        async function checkUpdate() {
            try {
                const response = await message({ action: 'checkUpdate' });
                if (response && response.success) {
                    await refreshRules(false, false);
                    notify('Update Check', response.message || 'Firewall rule check completed', 'success');
                    return;
                }
                notify('Update Check', response && response.error ? response.error : 'Failed to check for updates', 'error');
            } catch (error) {
                notify('Update Check', error.message, 'error');
            }
        }

        async function openConsoleCommands() {
            try {
                const tabs = await queryTabs({ active: true, currentWindow: true });
                const activeTab = tabs && tabs[0] ? tabs[0] : null;
                try {
                    await message({ action: 'startConsoleCapture', tabId: activeTab ? activeTab.id : null });
                } catch (error) {
                    console.warn('[Popup React] Console capture start failed:', error.message);
                }
                await createTab(chrome.runtime.getURL('console_popup.html'));
            } catch (error) {
                notify('Console Commands', error.message, 'error');
            }
        }

        async function openAITestingPanel() {
            try {
                await createTab(chrome.runtime.getURL('ai_testing_panel_working.html'));
            } catch (error) {
                notify('AI Testing Panel', error.message, 'error');
            }
        }

        useEffect(() => {
            if (!optionsHydrated.current) {
                return;
            }
            void setStorage({
                [AUTOMATION_OPTIONS_KEY]: {
                    headless: options.headlessMode,
                    incognito: options.incognitoMode,
                    blockAds: options.blockAdsMode,
                    interceptClicks: options.interceptClicksMode,
                    interceptForms: options.interceptFormsMode
                }
            }).catch((error) => {
                console.warn('[Popup React] Failed to persist options:', error.message);
            });
        }, [options]);

        useEffect(() => {
            let live = true;
            (async () => {
                const config = await loadEndpoints();
                if (!live) {
                    return;
                }
                await loadOptions();
                await Promise.all([
                    refreshPageStatus(),
                    refreshServerStatus(config),
                    refreshSession(),
                    refreshRules(false, false),
                    refreshAutomationSessions(false)
                ]);
            })();
            return () => {
                live = false;
            };
        }, []);

        useEffect(() => {
            function onMessage(incoming) {
                if (!incoming || !incoming.action) {
                    return;
                }
                if (incoming.action === 'sessionEnded') {
                    notify('Session Ended', `Session ended: ${incoming.reason}`, 'info');
                    void refreshSession();
                }
                if (incoming.action === 'ruleHistoryUpdated') {
                    void loadStoredRules();
                }
            }
            chrome.runtime.onMessage.addListener(onMessage);
            return () => chrome.runtime.onMessage.removeListener(onMessage);
        }, []);

        useEffect(() => {
            function onChanged(changes, namespace) {
                if (namespace !== 'local') {
                    return;
                }
                if (changes.firewall_guard_sessions) {
                    void refreshSession();
                }
                if (changes.firewall_rules || changes.rules_version || changes.console_firewall_policy || changes.local_engine_rules || changes.local_engine_status || changes.rule_change_history) {
                    void loadStoredRules();
                }
            }
            chrome.storage.onChanged.addListener(onChanged);
            return () => chrome.storage.onChanged.removeListener(onChanged);
        }, []);

        useEffect(() => {
            const timers = [
                window.setInterval(() => void refreshPageStatus(), 5000),
                window.setInterval(() => void refreshSession(), 10000),
                window.setInterval(() => void refreshServerStatus(), 15000),
                window.setInterval(() => void refreshAutomationSessions(false), 15000),
                window.setInterval(() => void refreshRules(false, false), 15000)
            ];
            return () => timers.forEach((timer) => window.clearInterval(timer));
        }, []);

        const activeAutomation = automationSession || currentSession;
        const automationText = activeAutomation && activeAutomation.sessionId
            ? `${activeAutomation.sessionId} (${humanize(activeAutomation.type, 'automated browser')})`
            : 'No active session';
        const automationSummary = activeAutomation && activeAutomation.config ? sessionSummary(activeAutomation.config) : '';
        const automationTitle = automationSummary ? `Options: ${automationSummary}` : '';

        return e(
            React.Fragment,
            null,
            e(NotificationStack, { items: notifications }),
            e('div', { className: 'app-shell' },
                e('h1', { className: 'popup-title' }, 'Firewall Guard'),
                e('div', { className: 'status-box' },
                    e(StatusRow, { label: 'Page Status', value: pageStatus.value, tone: pageStatus.tone, page: true }),
                    e(StatusRow, { label: 'Server Status', value: serverStatus.value, tone: serverStatus.tone }),
                    e(StatusRow, { label: 'Local Engine', value: ruleState.localEngineText, tone: ruleState.localEngineTone }),
                    e(StatusRow, { label: 'Rules Version', value: ruleState.rulesVersion, tone: 'neutral' }),
                    e(StatusRow, { label: 'Auto-Update', value: 'Enabled', tone: 'ok' }),
                    e(StatusRow, {
                        label: 'Session ID',
                        value: sessionStatus.value,
                        tone: sessionStatus.tone,
                        title: sessionStatus.title,
                        onValueClick: sessionStatus.clickable ? () => void openDashboard() : null,
                        button: { label: 'Refresh', onClick: () => void refreshSession() }
                    })
                ),
                e('div', { className: 'rules-box' },
                    e('div', { className: 'rules-header-row' },
                        e('span', { className: 'rules-title' }, 'Rule Visibility'),
                        e('button', { type: 'button', className: 'refresh-btn', onClick: () => void refreshRules(true, true) }, 'Refresh')
                    ),
                    e('div', { className: 'rules-grid' },
                        e('div', { className: 'rule-card' },
                            e('div', { className: 'rule-card-title' }, 'Global Firewall Rules'),
                            e('div', { className: 'rule-row' }, e('span', { className: 'rule-label' }, 'Version'), e('span', { className: 'rule-value' }, ruleState.globalRulesVersion)),
                            e('div', { className: 'rule-row' }, e('span', { className: 'rule-label' }, 'Blocked Domains'), e('span', { className: 'rule-value' }, ruleState.globalBlockedCount)),
                            e('div', { className: 'rule-row' }, e('span', { className: 'rule-label' }, 'Last Change'), e('span', { className: 'rule-value' }, ruleState.globalRulesChange))
                        ),
                        e('div', { className: 'rule-card' },
                            e('div', { className: 'rule-card-title' }, 'Local Firewall Rules'),
                            e('div', { className: 'rule-row' }, e('span', { className: 'rule-label' }, 'Engine Status'), e('span', { className: 'rule-value' }, ruleState.localEngineRulesText)),
                            e('div', { className: 'rule-row' }, e('span', { className: 'rule-label' }, 'Policy Rules'), e('span', { className: 'rule-value' }, ruleState.localPolicyRuleCount)),
                            e('div', { className: 'rule-row' }, e('span', { className: 'rule-label' }, 'Last Change'), e('span', { className: 'rule-value' }, ruleState.localRulesChange))
                        )
                    ),
                    e('div', { className: 'rule-history-card' },
                        e('div', { className: 'rule-card-title' }, 'Recent Rule Changes'),
                        e('div', { className: 'rule-history-list' }, e(RuleHistory, { items: ruleState.history }))
                    )
                ),
                e('div', { className: 'automation-box' },
                    e('div', { className: 'automation-title' }, 'Automated Browser Control'),
                    e('div', { className: 'automation-row' },
                        e('span', { className: 'automation-label' }, 'Launch New Automated Browser'),
                        e('div', { className: 'automation-actions' },
                            e('button', { type: 'button', className: 'automation-btn', onClick: () => void launchBrowser() }, 'Launch Browser'),
                            e('button', { type: 'button', className: 'automation-btn secondary-btn', onClick: () => void refreshAutomationSessions(true) }, 'Get Sessions')
                        )
                    ),
                    e('div', { className: 'automation-row' },
                        e('span', { className: 'automation-label' }, 'Current Session'),
                        e('span', { className: 'automation-session-value', title: automationTitle }, automationText)
                    ),
                    e('div', { className: 'automation-options' },
                        e('div', { className: 'automation-options-title' }, 'Browser Options'),
                        Object.keys(OPTION_LABELS).map((key) => e('label', { key: key, className: 'option-checkbox' },
                            e('input', {
                                type: 'checkbox',
                                checked: options[key],
                                onChange: (event) => setOptions((current) => ({ ...current, [key]: Boolean(event.target.checked) }))
                            }),
                            e('span', null, OPTION_LABELS[key])
                        ))
                    )
                ),
                e('div', { className: 'endpoint-box' },
                    e('div', { className: 'endpoint-title' }, 'Connection Endpoints'),
                    e('div', { className: 'endpoint-help' }, 'Keep localhost for same-machine runs, or paste Dev Tunnel URLs here. Backend and local engine URLs are normalized to /api automatically.'),
                    e('div', { className: 'endpoint-grid' },
                        e('label', { className: 'endpoint-field' },
                            e('span', null, 'Backend API'),
                            e('input', {
                                type: 'url',
                                placeholder: 'https://your-backend.devtunnels.ms/api',
                                value: endpoints.backendApiBase,
                                onChange: (event) => setEndpoints((current) => ({ ...current, backendApiBase: event.target.value }))
                            })
                        ),
                        e('label', { className: 'endpoint-field' },
                            e('span', null, 'Local Engine API'),
                            e('input', {
                                type: 'url',
                                placeholder: 'https://your-engine.devtunnels.ms/api',
                                value: endpoints.localEngineApiBase,
                                onChange: (event) => setEndpoints((current) => ({ ...current, localEngineApiBase: event.target.value }))
                            })
                        )
                    ),
                    e('div', { className: 'endpoint-actions' },
                        e('button', { type: 'button', className: 'secondary-btn', onClick: () => void saveEndpoints() }, 'Save Endpoints'),
                        e('button', { type: 'button', className: 'clear-session-btn', onClick: () => void resetEndpoints() }, 'Use Localhost')
                    ),
                    e('div', { className: cls('endpoint-mode', endpointMode.mode) }, endpointMode.text)
                ),
                e('div', { className: 'button-group' },
                    e('button', { type: 'button', onClick: () => void testConnection() }, 'Test Connection'),
                    e('button', { type: 'button', onClick: () => void openDashboard() }, 'Dashboard'),
                    e('button', { type: 'button', onClick: () => void checkUpdate() }, 'Update'),
                    e('button', { type: 'button', onClick: () => void openConsoleCommands() }, 'Console Commands'),
                    e('button', { type: 'button', onClick: () => void openAITestingPanel() }, 'AI Testing Panel'),
                    e('button', { type: 'button', className: 'force-session-btn', onClick: () => void forceSession() }, 'Force Session'),
                    e('button', { type: 'button', className: 'clear-session-btn', onClick: () => void clearSession() }, 'Clear Session')
                )
            )
        );
    }

    ReactDOM.createRoot(document.getElementById('root')).render(e(App));
}());
