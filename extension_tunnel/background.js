const DEFAULT_API_BASE = '';
const DEFAULT_LOCAL_ENGINE = '';
const ENDPOINT_CONFIG_KEY = 'firewall_endpoint_config';
const RUNTIME_TUNNEL_CONFIG_PATH = 'runtime_tunnel_config.local.json';
const DEFAULT_ENDPOINT_CONFIG = Object.freeze({
    backendApiBase: DEFAULT_API_BASE,
    localEngineApiBase: DEFAULT_LOCAL_ENGINE
});
let API_BASE = DEFAULT_API_BASE;
let LOCAL_ENGINE = DEFAULT_LOCAL_ENGINE;
let currentRulesVersion = 0;
let automationSessions = new Map();
let downloadMonitor = new Map();
let adBlockRules = new Set();
let pageLogs = new Map();
let backendConnected = false;
let backendAuthRequired = false;
let externalPorts = new Map(); // Track external connections
let serversEnabled = true; // NEW: Server toggle state
let lastInspectableTabId = null;
const consoleDebuggerTabs = new Set();
const recentConsoleCaptureFingerprints = new Map();
const recentUrlBlockFingerprints = new Map();
const TUNNEL_CONFIG_REQUIRED_MESSAGE = 'Tunnel endpoints are not configured. Run start_dev_tunnels.sh to generate Dev Tunnel URLs.';
const EXTENSION_PAGES_CSP = chrome.runtime.getManifest()?.content_security_policy?.extension_pages || '';
const LOCALHOST_CSP_REQUIRED_MESSAGE = 'Localhost is blocked by the loaded extension CSP. Reload the updated unpacked extension.';

const DEFAULT_CONSOLE_FIREWALL_POLICY = {
    version: 2,
    mode: 'block',
    updatedAt: '2026-03-18T00:00:00.000Z',
    rules: [
        {
            id: 'dynamic-code-eval',
            appliesTo: ['eval', 'function'],
            pattern: '(?:^|[^a-z])eval\\s*\\(|(?:^|[^a-z])Function\\s*\\(|new\\s+Function\\s*\\(',
            severity: 'HIGH',
            block: false,
            reason: 'Dynamic code execution from console or eval-like context'
        },
        {
            id: 'cookie-storage-exfiltration',
            appliesTo: ['fetch', 'xhr', 'beacon', 'postMessage', 'eval', 'function'],
            pattern: '(?:document\\.cookie|localStorage|sessionStorage|authorization|bearer|token).*?(?:fetch|XMLHttpRequest|sendBeacon|postMessage)|(?:fetch|XMLHttpRequest|sendBeacon|postMessage).*?(?:document\\.cookie|localStorage|sessionStorage|authorization|bearer|token)',
            severity: 'CRITICAL',
            block: true,
            reason: 'Sensitive data exfiltration pattern'
        },
        {
            id: 'dom-script-injection',
            appliesTo: ['eval', 'function', 'domWrite', 'htmlInsert', 'open'],
            pattern: '(?:document\\.write|insertAdjacentHTML|innerHTML|outerHTML|window\\.open).*?(?:<script|javascript:|data:text/html|onerror\\s*=|onload\\s*=)|(?:<script|javascript:|data:text/html|onerror\\s*=|onload\\s*=)',
            severity: 'HIGH',
            block: true,
            reason: 'DOM or script injection pattern'
        },
        {
            id: 'dangerous-storage-write',
            appliesTo: ['storage', 'eval', 'function'],
            pattern: '(?:localStorage|sessionStorage)\\.(?:setItem|removeItem|clear).*?(?:token|cookie|script|javascript:|data:text/html|onerror\\s*=|onload\\s*=)',
            severity: 'HIGH',
            block: true,
            reason: 'Dangerous storage manipulation pattern'
        },
        {
            id: 'dangerous-protocol-network',
            appliesTo: ['fetch', 'xhr', 'beacon', 'open', 'eval', 'function'],
            pattern: 'javascript:|data:text/html|data:application/javascript|vbscript:',
            severity: 'HIGH',
            block: true,
            reason: 'Dangerous protocol or payload pattern'
        }
    ]
};

const RULE_CHANGE_HISTORY_KEY = 'rule_change_history';
const LOCAL_ENGINE_RULES_KEY = 'local_engine_rules';
const LOCAL_ENGINE_STATUS_KEY = 'local_engine_status';
const CONSOLE_ANALYSIS_CACHE_KEY = 'console_analysis_cache';
const AI_RESPONSE_HISTORY_KEY = 'ai_response_history';
const MAX_CONSOLE_ANALYSIS_CACHE_ENTRIES = 5000;
const MAX_AI_RESPONSE_HISTORY_ENTRIES = 5000;
const CONSOLE_ANALYSIS_CACHE_FEATURE_VERSION = 'console-cache-v1';

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

function sanitizeEndpointConfig(config) {
    const source = config && typeof config === 'object' ? config : {};

    return {
        backendApiBase: normalizeApiBase(source.backendApiBase, DEFAULT_ENDPOINT_CONFIG.backendApiBase),
        localEngineApiBase: normalizeApiBase(source.localEngineApiBase, DEFAULT_ENDPOINT_CONFIG.localEngineApiBase)
    };
}

function getCurrentEndpointConfig() {
    return sanitizeEndpointConfig({
        backendApiBase: API_BASE,
        localEngineApiBase: LOCAL_ENGINE
    });
}

function isEndpointConfigEmpty(config) {
    const effectiveConfig = sanitizeEndpointConfig(config);
    return !effectiveConfig.backendApiBase && !effectiveConfig.localEngineApiBase;
}

function isDevTunnelEndpoint(value) {
    try {
        const normalized = normalizeBaseUrl(value, '');
        if (!normalized) {
            return false;
        }

        const parsed = new URL(normalized);
        return parsed.protocol === 'https:' && parsed.hostname.toLowerCase().includes('devtunnels.ms');
    } catch (error) {
        return false;
    }
}

function isLocalhostEndpoint(value) {
    try {
        const normalized = normalizeBaseUrl(value, '');
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

function hasConfiguredEndpointConfig(config) {
    const effectiveConfig = sanitizeEndpointConfig(config);
    return isSupportedEndpoint(effectiveConfig.backendApiBase)
        && isSupportedEndpoint(effectiveConfig.localEngineApiBase);
}

function isSupportedEndpoint(value) {
    return isDevTunnelEndpoint(value) || isLocalhostEndpoint(value);
}

function getEndpointMode(config) {
    const effectiveConfig = sanitizeEndpointConfig(config);
    const backendConfigured = isSupportedEndpoint(effectiveConfig.backendApiBase);
    const localConfigured = isSupportedEndpoint(effectiveConfig.localEngineApiBase);

    if (!backendConfigured || !localConfigured) {
        return 'unconfigured';
    }

    const backendIsTunnel = isDevTunnelEndpoint(effectiveConfig.backendApiBase);
    const localIsTunnel = isDevTunnelEndpoint(effectiveConfig.localEngineApiBase);
    const localIsLoopback = isLocalhostEndpoint(effectiveConfig.localEngineApiBase);

    if (backendIsTunnel && localIsLoopback) {
        return 'hybrid';
    }

    if (backendIsTunnel || localIsTunnel) {
        return 'dev_tunnel';
    }

    return 'localhost';
}

function isAllowedTunnelUrl(value) {
    return isDevTunnelEndpoint(value);
}

function cspAllowsLocalhostConnections() {
    return /localhost|127\.0\.0\.1/i.test(EXTENSION_PAGES_CSP);
}

function createTunnelAwareRequestOptions(url, options = {}) {
    const nextOptions = { ...options };
    const headers = new Headers(options.headers || {});

    if (isAllowedTunnelUrl(url)) {
        nextOptions.credentials = 'include';
        headers.set('X-Tunnel-Skip-AntiPhishing-Page', 'true');

        if (!headers.has('Accept')) {
            headers.set('Accept', 'application/json, text/plain, */*');
        }
    }

    nextOptions.headers = headers;
    return nextOptions;
}

function createDirectRequestOptions(options = {}) {
    const nextOptions = { ...options };
    nextOptions.headers = new Headers(options.headers || {});

    if (Object.prototype.hasOwnProperty.call(nextOptions, 'credentials')) {
        delete nextOptions.credentials;
    }

    return nextOptions;
}

function deriveLocalhostFallbackUrl(value) {
    try {
        if (!isAllowedTunnelUrl(value) || !cspAllowsLocalhostConnections()) {
            return '';
        }

        const parsed = new URL(normalizeBaseUrl(value, ''));
        const portMatch = parsed.hostname.match(/-(\d+)\./);

        if (!portMatch) {
            return '';
        }

        return `http://localhost:${portMatch[1]}${parsed.pathname}${parsed.search}${parsed.hash}`;
    } catch (error) {
        return '';
    }
}

function buildFetchFailureError(url, errors) {
    const messages = [];

    (errors || []).forEach((error) => {
        const message = error && error.message ? error.message : String(error || '');
        if (message && !messages.includes(message)) {
            messages.push(message);
        }
    });

    if (!messages.length) {
        return new Error(`Failed to fetch ${url}`);
    }

    return new Error(`Failed to fetch ${url}: ${messages.join(' | ')}`);
}

async function fetchTunnelAware(url, options = {}) {
    if (typeof url !== 'string' || !/^[a-z][a-z0-9+.-]*:\/\//i.test(url.trim())) {
        throw new Error(TUNNEL_CONFIG_REQUIRED_MESSAGE);
    }

    if (isLocalhostEndpoint(url) && !cspAllowsLocalhostConnections()) {
        throw new Error(LOCALHOST_CSP_REQUIRED_MESSAGE);
    }

    assertSupportedEndpoint(url, 'Requested service URL');

    if (!isAllowedTunnelUrl(url)) {
        return fetch(url, createTunnelAwareRequestOptions(url, options));
    }

    const fetchErrors = [];

    try {
        return await fetch(url, createTunnelAwareRequestOptions(url, options));
    } catch (error) {
        fetchErrors.push(error);
        console.warn('[Fetch] Tunnel request failed, retrying without tunnel headers:', error.message);
    }

    try {
        return await fetch(url, createDirectRequestOptions(options));
    } catch (error) {
        fetchErrors.push(error);
        console.warn('[Fetch] Direct tunnel retry failed:', error.message);
    }

    const localhostFallbackUrl = deriveLocalhostFallbackUrl(url);
    if (localhostFallbackUrl) {
        try {
            console.warn(`[Fetch] Retrying via localhost fallback: ${localhostFallbackUrl}`);
            return await fetch(localhostFallbackUrl, createDirectRequestOptions(options));
        } catch (error) {
            fetchErrors.push(error);
            console.warn('[Fetch] Localhost fallback failed:', error.message);
        }
    }

    throw buildFetchFailureError(url, fetchErrors);
}

function assertSupportedEndpoint(value, label) {
    let parsed;

    try {
        parsed = new URL(normalizeBaseUrl(value, ''));
    } catch (error) {
        throw new Error(`${label} must be a valid http:// or https:// URL`);
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error(`${label} must use http:// or https://`);
    }

    if (!isSupportedEndpoint(parsed.toString())) {
        throw new Error(`${label} must use a Dev Tunnel or localhost URL`);
    }
}

function validateEndpointConfigInput(config) {
    const candidate = sanitizeEndpointConfig(config);

    if (!candidate.backendApiBase || !candidate.localEngineApiBase) {
        throw new Error(TUNNEL_CONFIG_REQUIRED_MESSAGE);
    }

    assertSupportedEndpoint(candidate.backendApiBase, 'Backend API endpoint');
    assertSupportedEndpoint(candidate.localEngineApiBase, 'Local engine endpoint');
}

async function applyEndpointConfig(config, options = {}) {
    const normalized = sanitizeEndpointConfig(config);

    if (isEndpointConfigEmpty(normalized)) {
        API_BASE = '';
        LOCAL_ENGINE = '';
        console.log('[Config] Dev Tunnel endpoints are not configured yet.');

        if (options.persist) {
            await chrome.storage.local.set({ [ENDPOINT_CONFIG_KEY]: normalized });
        }

        return normalized;
    }

    validateEndpointConfigInput(normalized);
    API_BASE = normalized.backendApiBase;
    LOCAL_ENGINE = normalized.localEngineApiBase;

    console.log('[Config] Active endpoints:', normalized);

    if (options.persist) {
        await chrome.storage.local.set({ [ENDPOINT_CONFIG_KEY]: normalized });
    }

    return normalized;
}

function configsMatch(left, right) {
    return Boolean(left && right)
        && normalizeApiBase(left.backendApiBase, DEFAULT_API_BASE) === normalizeApiBase(right.backendApiBase, DEFAULT_API_BASE)
        && normalizeApiBase(left.localEngineApiBase, DEFAULT_LOCAL_ENGINE) === normalizeApiBase(right.localEngineApiBase, DEFAULT_LOCAL_ENGINE);
}

async function loadBundledTunnelConfig() {
    try {
        const response = await fetch(chrome.runtime.getURL(RUNTIME_TUNNEL_CONFIG_PATH), { cache: 'no-store' });
        if (!response.ok) {
            return null;
        }

        const config = sanitizeEndpointConfig(await response.json());
        if (isEndpointConfigEmpty(config)) {
            return null;
        }
        validateEndpointConfigInput(config);
        return config;
    } catch (error) {
        console.warn('[Config] Failed to load bundled tunnel config:', error.message);
        return null;
    }
}

async function syncBundledTunnelConfig(options = {}) {
    const bundledConfig = await loadBundledTunnelConfig();
    if (!bundledConfig) {
        return getCurrentEndpointConfig();
    }

    const currentConfig = getCurrentEndpointConfig();
    if (configsMatch(bundledConfig, currentConfig)) {
        return currentConfig;
    }

    return applyEndpointConfig(bundledConfig, { persist: options.persist !== false });
}

async function loadEndpointConfig() {
    const bundledConfig = await loadBundledTunnelConfig();
    const config = await applyEndpointConfig(bundledConfig || DEFAULT_ENDPOINT_CONFIG, { persist: true });
    return config;
}

function safeRuntimeSendMessage(message) {
    try {
        chrome.runtime.sendMessage(message, () => {
            void chrome.runtime.lastError;
        });
    } catch (error) {
        // Ignore missing listeners during background broadcasts.
    }
}

function cloneConsoleFirewallPolicy(policy) {
    return JSON.parse(JSON.stringify(policy));
}

function normalizeConsoleFirewallPolicy(policy) {
    const defaults = cloneConsoleFirewallPolicy(DEFAULT_CONSOLE_FIREWALL_POLICY);
    const sourcePolicy = policy && typeof policy === 'object' ? policy : {};
    const mergedRules = new Map();

    defaults.rules.forEach((rule) => {
        mergedRules.set(rule.id, { ...rule });
    });

    if (Array.isArray(sourcePolicy.rules)) {
        sourcePolicy.rules.forEach((rule) => {
            if (!rule || typeof rule !== 'object' || !rule.id) {
                return;
            }

            const defaultRule = mergedRules.get(rule.id) || {};
            mergedRules.set(rule.id, {
                ...defaultRule,
                ...rule
            });
        });
    }

    return {
        ...defaults,
        ...sourcePolicy,
        version: sourcePolicy.version || defaults.version,
        rules: Array.from(mergedRules.values())
    };
}

function mergeLearnedConsoleRulesIntoPolicy(remotePolicy, localPolicy) {
    const nextPolicy = normalizeConsoleFirewallPolicy(remotePolicy);
    const currentPolicy = normalizeConsoleFirewallPolicy(localPolicy);
    const mergedRules = Array.isArray(nextPolicy.rules)
        ? nextPolicy.rules.map((rule) => ({ ...rule }))
        : [];
    let preservedLocalLearnedRules = false;

    for (const localRule of currentPolicy.rules || []) {
        if (!localRule || !localRule.id || localRule.learned !== true) {
            continue;
        }

        const existingIndex = mergedRules.findIndex((rule) => rule && rule.id === localRule.id);

        if (existingIndex >= 0) {
            const remoteRule = mergedRules[existingIndex];
            const mergedRule = {
                ...remoteRule,
                ...localRule,
                block: Boolean(remoteRule.block) || Boolean(localRule.block),
                enabled: remoteRule.enabled !== false && localRule.enabled !== false,
                learned: true,
                severity: getHigherRiskLevel(remoteRule.severity, localRule.severity),
                hitCount: Math.max(Number(remoteRule.hitCount || 0), Number(localRule.hitCount || 0)),
                updatedAt: localRule.updatedAt || remoteRule.updatedAt || new Date().toISOString()
            };

            if (JSON.stringify(mergedRule) !== JSON.stringify(remoteRule)) {
                mergedRules[existingIndex] = mergedRule;
                preservedLocalLearnedRules = true;
            }

            continue;
        }

        mergedRules.unshift({ ...localRule });
        preservedLocalLearnedRules = true;
    }

    const mergedPolicy = normalizeConsoleFirewallPolicy({
        ...nextPolicy,
        rules: mergedRules,
        updatedAt: preservedLocalLearnedRules
            ? new Date().toISOString()
            : nextPolicy.updatedAt
    });

    if (preservedLocalLearnedRules) {
        mergedPolicy.version = Date.now();
    }

    return {
        policy: mergedPolicy,
        preservedLocalLearnedRules: preservedLocalLearnedRules
    };
}

let consoleFirewallPolicyMutationQueue = Promise.resolve();

function queueConsoleFirewallPolicyMutation(mutator) {
    const task = consoleFirewallPolicyMutationQueue
        .catch(() => {})
        .then(async () => {
            const storage = await chrome.storage.local.get(['console_firewall_policy']);
            const currentPolicy = normalizeConsoleFirewallPolicy(storage.console_firewall_policy);
            return mutator(currentPolicy);
        });

    consoleFirewallPolicyMutationQueue = task.then(() => undefined, () => undefined);
    return task;
}

function ensureConsoleFirewallPolicy() {
    chrome.storage.local.get(['console_firewall_policy'], (result) => {
        const currentPolicy = result.console_firewall_policy;
        const normalizedPolicy = normalizeConsoleFirewallPolicy(currentPolicy);

        if (JSON.stringify(currentPolicy || null) !== JSON.stringify(normalizedPolicy)) {
            chrome.storage.local.set({
                'console_firewall_policy': {
                    ...normalizedPolicy,
                    updatedAt: new Date().toISOString()
                }
            });
        }
    });
}

function normalizeRuleObject(rules) {
    return rules && typeof rules === 'object' ? rules : {};
}

function normalizeRuleList(value) {
    if (!Array.isArray(value)) {
        return [];
    }

    return [...new Set(value.map((item) => String(item)))].sort((left, right) => left.localeCompare(right));
}

function buildConsolePolicyVersionLabel(policy) {
    const rules = Array.isArray(policy && policy.rules) ? policy.rules : [];
    const activeRules = rules.filter((rule) => rule && rule.enabled !== false);
    const blockingRules = activeRules.filter((rule) => rule.block);

    return activeRules.length
        ? `1:${activeRules.length}:b${blockingRules.length}`
        : `0:0:b${blockingRules.length}`;
}

function normalizeConsolePolicyRuleForDiff(rule) {
    if (!rule || typeof rule !== 'object' || !rule.id) {
        return null;
    }

    return {
        id: String(rule.id),
        appliesTo: normalizeRuleList(rule.appliesTo),
        pattern: String(rule.pattern || ''),
        severity: String(rule.severity || 'UNKNOWN').toUpperCase(),
        block: Boolean(rule.block),
        enabled: rule.enabled !== false
    };
}

function buildConsolePolicyRuleMap(policy) {
    const ruleMap = new Map();

    for (const rule of Array.isArray(policy && policy.rules) ? policy.rules : []) {
        const normalizedRule = normalizeConsolePolicyRuleForDiff(rule);
        if (!normalizedRule) {
            continue;
        }

        ruleMap.set(normalizedRule.id, normalizedRule);
    }

    return ruleMap;
}

function buildConsolePolicyDiff(previousRules, nextRules) {
    const previousPolicy = normalizeConsoleFirewallPolicy(previousRules);
    const nextPolicy = normalizeConsoleFirewallPolicy(nextRules);
    const previousVersion = buildConsolePolicyVersionLabel(previousPolicy);
    const nextVersion = buildConsolePolicyVersionLabel(nextPolicy);
    const previousRuleMap = buildConsolePolicyRuleMap(previousPolicy);
    const nextRuleMap = buildConsolePolicyRuleMap(nextPolicy);
    const ruleIds = Array.from(new Set([
        ...previousRuleMap.keys(),
        ...nextRuleMap.keys()
    ])).sort((left, right) => left.localeCompare(right));
    const added = [];
    const removed = [];
    const changed = [];

    ruleIds.forEach((ruleId) => {
        const previousRule = previousRuleMap.get(ruleId);
        const nextRule = nextRuleMap.get(ruleId);

        if (!previousRule && nextRule) {
            added.push(ruleId);
            return;
        }

        if (previousRule && !nextRule) {
            removed.push(ruleId);
            return;
        }

        if (previousRule && nextRule && JSON.stringify(previousRule) !== JSON.stringify(nextRule)) {
            changed.push(ruleId);
        }
    });

    const scalarChanges = [];
    if (String(previousPolicy.mode || 'unknown') !== String(nextPolicy.mode || 'unknown')) {
        scalarChanges.push({
            key: 'mode',
            from: String(previousPolicy.mode || 'unknown'),
            to: String(nextPolicy.mode || 'unknown')
        });
    }

    const listChanges = [];
    if (added.length || removed.length || changed.length) {
        listChanges.push({
            key: 'rules',
            addedCount: added.length,
            removedCount: removed.length,
            changedCount: changed.length,
            added: added.slice(0, 5),
            removed: removed.slice(0, 5),
            changed: changed.slice(0, 5)
        });
    }

    const hadPreviousRules = previousRuleMap.size > 0;
    const summary = hadPreviousRules && previousVersion !== nextVersion
        ? `Rule versions: ${previousVersion} -> ${nextVersion}`
        : `Rule versions: ${nextVersion}`;

    return {
        hasChanges: listChanges.length > 0 || scalarChanges.length > 0,
        previousVersion: previousVersion,
        nextVersion: nextVersion,
        totalAdded: added.length,
        totalRemoved: removed.length,
        totalChanged: changed.length,
        changedKeys: listChanges.map((change) => change.key),
        listChanges: listChanges,
        scalarChanges: scalarChanges.slice(0, 6),
        summary: summary
    };
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

function buildConsolePolicyHistorySummary(entry, policy) {
    const previousVersion = typeof entry?.previousVersion === 'string' && entry.previousVersion
        ? entry.previousVersion
        : '';
    const nextVersion = typeof entry?.nextVersion === 'string' && entry.nextVersion
        ? entry.nextVersion
        : buildConsolePolicyVersionLabel(policy);

    if (previousVersion && nextVersion && previousVersion !== nextVersion) {
        return `Rule versions: ${previousVersion} -> ${nextVersion}`;
    }

    return `Rule versions: ${nextVersion}`;
}

function normalizeRuleChangeHistoryEntry(entry, context = {}) {
    if (!entry || typeof entry !== 'object' || entry.target !== 'console-policy') {
        return entry;
    }

    const policy = normalizeConsoleFirewallPolicy(context.consoleFirewallPolicy);
    const nextVersion = typeof entry.nextVersion === 'string' && entry.nextVersion
        ? entry.nextVersion
        : buildConsolePolicyVersionLabel(policy);
    const normalizedSummary = isLegacyConsolePolicyHistorySummary(entry.summary)
        ? buildConsolePolicyHistorySummary({
            ...entry,
            nextVersion: nextVersion
        }, policy)
        : entry.summary;

    const changed = normalizedSummary !== entry.summary || nextVersion !== entry.nextVersion;
    if (!changed) {
        return entry;
    }

    return {
        ...entry,
        nextVersion: nextVersion,
        summary: normalizedSummary
    };
}

async function normalizeStoredRuleChangeHistory(storageSnapshot = null) {
    const storage = storageSnapshot && typeof storageSnapshot === 'object'
        ? storageSnapshot
        : await chrome.storage.local.get([
            RULE_CHANGE_HISTORY_KEY,
            'console_firewall_policy'
        ]);
    const history = Array.isArray(storage[RULE_CHANGE_HISTORY_KEY]) ? storage[RULE_CHANGE_HISTORY_KEY] : [];

    if (!history.length) {
        return history;
    }

    let changed = false;
    const normalizedHistory = history.map((entry) => {
        const normalizedEntry = normalizeRuleChangeHistoryEntry(entry, {
            consoleFirewallPolicy: storage.console_firewall_policy
        });

        if (normalizedEntry !== entry) {
            changed = true;
        }

        return normalizedEntry;
    });

    if (changed) {
        await chrome.storage.local.set({ [RULE_CHANGE_HISTORY_KEY]: normalizedHistory });
    }

    return normalizedHistory;
}

function previewRuleValue(value) {
    if (value === undefined || value === null || value === '') {
        return '';
    }

    const serialized = typeof value === 'string' ? value : JSON.stringify(value);
    return serialized.length > 120 ? `${serialized.slice(0, 117)}...` : serialized;
}

function buildRuleDiff(previousRules, nextRules, meta = {}) {
    if (meta && meta.target === 'console-policy') {
        return buildConsolePolicyDiff(previousRules, nextRules);
    }

    const previous = normalizeRuleObject(previousRules);
    const next = normalizeRuleObject(nextRules);
    const keys = Array.from(new Set([
        ...Object.keys(previous),
        ...Object.keys(next)
    ]));
    const listChanges = [];
    const scalarChanges = [];
    let totalAdded = 0;
    let totalRemoved = 0;

    keys.forEach((key) => {
        const previousValue = previous[key];
        const nextValue = next[key];

        if (Array.isArray(previousValue) || Array.isArray(nextValue)) {
            const previousList = normalizeRuleList(previousValue);
            const nextList = normalizeRuleList(nextValue);
            const previousSet = new Set(previousList);
            const nextSet = new Set(nextList);
            const added = nextList.filter((item) => !previousSet.has(item));
            const removed = previousList.filter((item) => !nextSet.has(item));

            if (added.length || removed.length) {
                totalAdded += added.length;
                totalRemoved += removed.length;
                listChanges.push({
                    key: key,
                    addedCount: added.length,
                    removedCount: removed.length,
                    added: added.slice(0, 5),
                    removed: removed.slice(0, 5)
                });
            }

            return;
        }

        const previousPreview = previewRuleValue(previousValue);
        const nextPreview = previewRuleValue(nextValue);

        if (previousPreview !== nextPreview) {
            scalarChanges.push({
                key: key,
                from: previousPreview || 'none',
                to: nextPreview || 'none'
            });
        }
    });

    const previousVersion = previous.version ?? previous.rules_version ?? null;
    const nextVersion = next.version ?? next.rules_version ?? null;
    const summaryParts = [];

    if (previousVersion !== null || nextVersion !== null) {
        summaryParts.push(`version ${previousVersion ?? 'none'} -> ${nextVersion ?? 'none'}`);
    }

    if (totalAdded) {
        summaryParts.push(`${totalAdded} added`);
    }

    if (totalRemoved) {
        summaryParts.push(`${totalRemoved} removed`);
    }

    if (!summaryParts.length && scalarChanges.length) {
        summaryParts.push(`${scalarChanges.length} property changes`);
    }

    return {
        hasChanges: listChanges.length > 0 || scalarChanges.length > 0,
        previousVersion: previousVersion,
        nextVersion: nextVersion,
        totalAdded: totalAdded,
        totalRemoved: totalRemoved,
        changedKeys: listChanges.map((change) => change.key),
        listChanges: listChanges,
        scalarChanges: scalarChanges.slice(0, 6),
        summary: summaryParts.join(', ') || 'Rules changed'
    };
}

async function appendRuleChangeHistory(entry) {
    const result = await chrome.storage.local.get([RULE_CHANGE_HISTORY_KEY]);
    const history = Array.isArray(result[RULE_CHANGE_HISTORY_KEY]) ? result[RULE_CHANGE_HISTORY_KEY] : [];

    history.unshift(entry);

    if (history.length > 75) {
        history.length = 75;
    }

    await chrome.storage.local.set({ [RULE_CHANGE_HISTORY_KEY]: history });

    try {
        chrome.runtime.sendMessage({ action: 'ruleHistoryUpdated', entry: entry }, () => {
            void chrome.runtime.lastError;
        });
    } catch (error) {
        // Ignore missing listeners.
    }
}

async function recordRuleChange(scope, target, previousRules, nextRules, meta = {}) {
    const diff = buildRuleDiff(previousRules, nextRules, {
        scope: scope,
        target: target
    });

    if (!diff.hasChanges && !meta.force) {
        return null;
    }

    const entry = {
        id: `${scope}-${target}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
        scope: scope,
        target: target,
        source: meta.source || target,
        note: meta.note || '',
        timestamp: meta.timestamp || new Date().toISOString(),
        ...diff
    };

    await appendRuleChangeHistory(entry);
    return entry;
}

async function ensureRuleVisibilityHistory() {
    const storage = await chrome.storage.local.get([
        'firewall_rules',
        'console_firewall_policy',
        LOCAL_ENGINE_RULES_KEY,
        RULE_CHANGE_HISTORY_KEY
    ]);
    const history = await normalizeStoredRuleChangeHistory(storage);
    const hasGlobalHistory = history.some((entry) => entry && entry.scope === 'global');
    const hasLocalHistory = history.some((entry) => entry && entry.scope === 'local');
    const tasks = [];

    if (!hasGlobalHistory && hasRuleContent(storage.firewall_rules)) {
        tasks.push(recordRuleChange('global', 'server-rules', {}, storage.firewall_rules, {
            source: 'visibility_seed',
            force: true,
            note: 'Current global firewall rules loaded'
        }));
    }

    if (!hasLocalHistory) {
        if (storage.console_firewall_policy && Array.isArray(storage.console_firewall_policy.rules) && storage.console_firewall_policy.rules.length) {
            tasks.push(recordRuleChange('local', 'console-policy', {}, storage.console_firewall_policy, {
                source: 'visibility_seed',
                force: true,
                note: 'Current local console firewall rules loaded'
            }));
        } else if (hasRuleContent(storage[LOCAL_ENGINE_RULES_KEY])) {
            tasks.push(recordRuleChange('local', 'engine', {}, storage[LOCAL_ENGINE_RULES_KEY], {
                source: 'visibility_seed',
                force: true,
                note: 'Current local engine rules loaded'
            }));
        }
    }

    if (tasks.length > 0) {
        await Promise.all(tasks);
    }
}

async function updateLocalEngineSnapshot(options = {}) {
    await syncBundledTunnelConfig();
    const snapshotTime = new Date().toISOString();
    const stored = await chrome.storage.local.get([LOCAL_ENGINE_RULES_KEY]);
    const previousRules = normalizeRuleObject(stored[LOCAL_ENGINE_RULES_KEY]);
    const endpointConfig = getCurrentEndpointConfig();

    if (!hasConfiguredEndpointConfig(endpointConfig)) {
        const status = {
            available: false,
            checkedAt: snapshotTime,
            configRequired: true,
            authRequired: false,
            error: TUNNEL_CONFIG_REQUIRED_MESSAGE
        };

        await chrome.storage.local.set({ [LOCAL_ENGINE_STATUS_KEY]: status });

        return {
            available: false,
            status: status,
            rules: previousRules
        };
    }

    if (isLocalhostEndpoint(endpointConfig.localEngineApiBase) && !cspAllowsLocalhostConnections()) {
        const status = {
            available: false,
            checkedAt: snapshotTime,
            configRequired: true,
            authRequired: false,
            error: LOCALHOST_CSP_REQUIRED_MESSAGE
        };

        await chrome.storage.local.set({ [LOCAL_ENGINE_STATUS_KEY]: status });

        return {
            available: false,
            status: status,
            rules: previousRules
        };
    }

    try {
        const [statusResponse, rulesResponse] = await Promise.all([
            fetchTunnelAware(`${LOCAL_ENGINE}/status`),
            fetchTunnelAware(`${LOCAL_ENGINE}/rules/current`)
        ]);

        if (!statusResponse.ok) {
            throw new Error(`Local engine status failed: ${statusResponse.status}`);
        }

        if (!rulesResponse.ok) {
            throw new Error(`Local engine rules failed: ${rulesResponse.status}`);
        }

        const statusData = await statusResponse.json();
        const rulesData = await rulesResponse.json();
        const status = {
            available: true,
            checkedAt: snapshotTime,
            ...statusData
        };

        await chrome.storage.local.set({
            [LOCAL_ENGINE_STATUS_KEY]: status,
            [LOCAL_ENGINE_RULES_KEY]: rulesData
        });

        if (!options.skipHistory && Object.keys(previousRules).length > 0) {
            await recordRuleChange('local', 'engine', previousRules, rulesData, {
                source: options.source || 'engine_snapshot',
                note: options.note || ''
            });
        }

        return {
            available: true,
            status: status,
            rules: rulesData
        };
    } catch (error) {
        const status = {
            available: false,
            checkedAt: snapshotTime,
            error: error.message,
            authRequired: /401/.test(error.message)
        };

        await chrome.storage.local.set({ [LOCAL_ENGINE_STATUS_KEY]: status });

        return {
            available: false,
            status: status,
            rules: previousRules
        };
    }
}

function hasRuleContent(rules) {
    if (!rules || typeof rules !== 'object') {
        return false;
    }

    return Boolean(
        Array.isArray(rules.blocked_domains) ||
        Array.isArray(rules.whitelisted_domains) ||
        Array.isArray(rules.dangerous_extensions) ||
        Array.isArray(rules.rule_sets) ||
        Array.isArray(rules.rules) ||
        rules.version !== undefined ||
        rules.rules_version !== undefined
    );
}

function normalizeBackendRulesPayload(data, fallbackVersion = 1) {
    const payload = data && typeof data === 'object' ? data : {};
    let rules = {};

    if (payload.rules && typeof payload.rules === 'object' && !Array.isArray(payload.rules)) {
        rules = { ...payload.rules };
    } else if (Array.isArray(payload.rules)) {
        const blockedDomains = payload.rules.flatMap((rule) => (
            rule && rule.enabled !== false && Array.isArray(rule.domains)
                ? rule.domains.map((domain) => String(domain))
                : []
        ));

        rules = {
            blocked_domains: [...new Set(blockedDomains)].sort((left, right) => left.localeCompare(right)),
            rule_sets: payload.rules
        };
    } else if (hasRuleContent(payload)) {
        rules = { ...payload };
    }

    if (!Array.isArray(rules.blocked_domains)) {
        rules.blocked_domains = [];
    }

    if (!Array.isArray(rules.dangerous_extensions)) {
        rules.dangerous_extensions = [];
    }

    if (rules.version === undefined || rules.version === null || rules.version === '') {
        rules.version = payload.server_version || payload.rules_version || fallbackVersion || 1;
    }

    if (!rules.last_updated) {
        rules.last_updated = payload.updated_at || payload.timestamp || new Date().toISOString();
    }

    return rules;
}

async function fetchBackendRulesSnapshot() {
    const fallbackVersion = currentRulesVersion || 1;
    const endpoints = [
        { url: `${API_BASE}/rules`, options: { method: 'GET', cache: 'no-store' } },
        { url: `${API_BASE}/rules/current`, options: { method: 'GET', cache: 'no-store' } },
        { url: `${API_BASE}/rules/update`, options: { method: 'GET', cache: 'no-store' } }
    ];
    let lastError = null;

    for (const endpoint of endpoints) {
        try {
            const response = await fetchTunnelAware(endpoint.url, endpoint.options);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const data = await response.json();
            const rules = normalizeBackendRulesPayload(data, fallbackVersion);

            if (hasRuleContent(rules)) {
                return {
                    success: true,
                    source: endpoint.url,
                    rules: rules
                };
            }

            lastError = new Error(`No rule payload in response from ${endpoint.url}`);
        } catch (error) {
            lastError = error;
            console.warn(`[Rules] Snapshot fetch failed for ${endpoint.url}:`, error.message);
        }
    }

    return {
        success: false,
        error: lastError ? lastError.message : 'Unable to fetch backend rules'
    };
}

function normalizeBackendConsolePolicyPayload(payload) {
    const source = payload && typeof payload === 'object' ? payload : {};
    const rawPolicy = source.policy && typeof source.policy === 'object'
        ? source.policy
        : source;
    return normalizeConsoleFirewallPolicy(rawPolicy);
}

async function fetchBackendConsolePolicy() {
    const endpoints = [
        { url: `${API_BASE}/console-policy`, options: { method: 'GET', cache: 'no-store' } },
        { url: `${API_BASE}/console-policy/current`, options: { method: 'GET', cache: 'no-store' } }
    ];
    let lastError = null;

    for (const endpoint of endpoints) {
        try {
            const response = await fetchTunnelAware(endpoint.url, endpoint.options);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const data = await response.json();
            const policy = normalizeBackendConsolePolicyPayload(data);

            if (policy && Array.isArray(policy.rules)) {
                return {
                    success: true,
                    source: endpoint.url,
                    policy: policy
                };
            }

            lastError = new Error(`No console policy payload in response from ${endpoint.url}`);
        } catch (error) {
            lastError = error;
            console.warn(`[Console Firewall] Policy fetch failed for ${endpoint.url}:`, error.message);
        }
    }

    return {
        success: false,
        error: lastError ? lastError.message : 'Unable to fetch backend console policy'
    };
}

async function syncConsoleFirewallPolicyFromBackend(options = {}) {
    const skipConnectCheck = Boolean(options.skipConnectCheck);

    if (!skipConnectCheck && !backendConnected) {
        const connected = await checkBackendConnection();
        if (!connected) {
            return { updated: false, reason: 'backend_disconnected' };
        }
    }

    try {
        await hydrateConsoleFirewallRulesFromHistory();
    } catch (error) {
        console.warn('[Console Firewall] Failed to hydrate learned rules before backend sync:', error.message);
    }

    const snapshot = await fetchBackendConsolePolicy();
    if (!snapshot.success || !snapshot.policy) {
        throw new Error(snapshot.error || 'No console firewall policy received from backend');
    }

    const result = await queueConsoleFirewallPolicyMutation(async (previousPolicy) => {
        const mergeResult = mergeLearnedConsoleRulesIntoPolicy(snapshot.policy, previousPolicy);
        const nextPolicy = mergeResult.policy;
        const changed = JSON.stringify(previousPolicy) !== JSON.stringify(nextPolicy);

        if (changed) {
            await chrome.storage.local.set({ 'console_firewall_policy': nextPolicy });
        }

        return {
            changed: changed,
            policy: nextPolicy,
            preservedLocalLearnedRules: mergeResult.preservedLocalLearnedRules
        };
    });

    if (result.preservedLocalLearnedRules) {
        saveConsoleFirewallPolicyToBackend(result.policy).catch((error) => {
            console.warn('[Console Firewall] Failed to persist merged learned rules to backend:', error.message);
        });
    }

    await normalizeStoredRuleChangeHistory();

    return {
        updated: result.changed,
        version: result.policy.version || null,
        policy: result.policy,
        source: snapshot.source
    };
}

async function saveConsoleFirewallPolicyToBackend(policy) {
    if (!backendConnected) {
        return { updated: false, reason: 'backend_disconnected' };
    }

    try {
        const normalizedPolicy = normalizeConsoleFirewallPolicy(policy);
        const response = await fetchTunnelAware(`${API_BASE}/console-policy`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ policy: normalizedPolicy })
        });

        if (!response.ok) {
            throw new Error(`Console policy sync failed: HTTP ${response.status}`);
        }

        const data = await response.json();
        const savedPolicy = normalizeBackendConsolePolicyPayload(data);

        return {
            updated: true,
            version: savedPolicy.version || null,
            policy: savedPolicy
        };
    } catch (error) {
        console.warn('[Console Firewall] Failed to sync policy to backend:', error.message);
        return { updated: false, error: error.message };
    }
}

function extractServerRuleVersion(data) {
    if (!data || typeof data !== 'object') {
        return currentRulesVersion;
    }

    return (
        data.server_version ??
        data.rules_version ??
        data.version ??
        data.latestVersion ??
        currentRulesVersion
    );
}

function responseIndicatesRuleUpdate(data, clientVersion, hasStoredRules) {
    if (!data || typeof data !== 'object') {
        return !hasStoredRules;
    }

    if (data.update_available === true || data.updatesAvailable === true || data.rulesUpdated === true) {
        return true;
    }

    const serverVersion = Number(extractServerRuleVersion(data));
    const currentVersionNumber = Number(clientVersion || 0);

    if (Number.isFinite(serverVersion) && Number.isFinite(currentVersionNumber) && serverVersion > currentVersionNumber) {
        return true;
    }

    return !hasStoredRules;
}

function isInjectableConsoleBridgeUrl(url) {
    return Boolean(url) &&
        !url.startsWith('chrome://') &&
        !url.startsWith('about:') &&
        !url.startsWith('chrome-extension://');
}

function rememberInspectableTab(tab) {
    if (tab && tab.id && isInjectableConsoleBridgeUrl(tab.url || '')) {
        lastInspectableTabId = tab.id;
    }
}

function buildConsoleCaptureFingerprint(commandData) {
    return [
        commandData.tabId || 'no-tab',
        commandData.type || 'unknown',
        commandData.source || 'unknown',
        commandData.command || ''
    ].join('|');
}

function shouldSkipDuplicateConsoleCapture(commandData) {
    const fingerprint = buildConsoleCaptureFingerprint(commandData);
    const now = Date.now();
    const captureMethod = String((commandData && commandData.captureMethod) || 'bridge').toLowerCase();
    const existing = recentConsoleCaptureFingerprints.get(fingerprint);

    for (const [key, entry] of recentConsoleCaptureFingerprints.entries()) {
        const entryTimestamp = entry && typeof entry === 'object'
            ? Number(entry.timestamp || 0)
            : Number(entry || 0);

        if (now - entryTimestamp > 4000) {
            recentConsoleCaptureFingerprints.delete(key);
        }
    }

    if (existing && typeof existing === 'object') {
        const existingTimestamp = Number(existing.timestamp || 0);
        const existingCaptureMethod = String(existing.captureMethod || 'bridge').toLowerCase();

        if (existingCaptureMethod !== captureMethod && now - existingTimestamp < 500) {
            recentConsoleCaptureFingerprints.set(fingerprint, {
                timestamp: now,
                captureMethod: captureMethod
            });
            return true;
        }
    }

    recentConsoleCaptureFingerprints.set(fingerprint, {
        timestamp: now,
        captureMethod: captureMethod
    });
    return false;
}

function matchesBenignConsoleNoiseText(text) {
    const normalized = String(text || '');

    return /getItem\s*->\s*Error in getting item from indexedDB:?.*Object store\s+["'`A-Za-z0-9_ -]+\s+does not exist/i.test(normalized) ||
        /Object store\s+["'`A-Za-z0-9_ -]+\s+does not exist/i.test(normalized) ||
        /Nothing to see here,\s*move along\./i.test(normalized) ||
        /react-i18next::\s*useTranslation:\s*You will need to pass in an i18next instance by using initReactI18next/i.test(normalized) ||
        /Legal Term Banner:\s*Fetching current user 401/i.test(normalized) ||
        /\[DEPRECATED\]\s*Default export is deprecated\.\s*Instead use\s*`?import\s*\{\s*create\s*\}\s*from\s*['"]zustand['"]`?/i.test(normalized) ||
        /\[DEPRECATED\]\s*`?getStorage`?,\s*`?serialize`?\s*and\s*`?deserialize`?\s*options are deprecated\.\s*Use\s*`?storage`?\s*option instead\./i.test(normalized);
}

function shouldIgnoreBenignConsoleCommand(commandData) {
    if (!commandData || typeof commandData !== 'object') {
        return false;
    }

    return [
        commandData.command,
        commandData.stackHint,
        commandData.filename,
        commandData.sourceLocation
    ].some((value) => matchesBenignConsoleNoiseText(value));
}

function serializeDebuggerRemoteObject(remoteObject) {
    if (!remoteObject) {
        return '';
    }

    if (remoteObject.type === 'string') {
        return remoteObject.value || '';
    }

    if (remoteObject.type === 'undefined') {
        return 'undefined';
    }

    if (remoteObject.type === 'object' && remoteObject.subtype === 'null') {
        return 'null';
    }

    if (remoteObject.value !== undefined) {
        try {
            return typeof remoteObject.value === 'string'
                ? remoteObject.value
                : JSON.stringify(remoteObject.value);
        } catch (error) {
            return String(remoteObject.value);
        }
    }

    if (remoteObject.description) {
        return remoteObject.description;
    }

    return remoteObject.type || 'unknown';
}

function formatDebuggerStackTrace(stackTrace) {
    if (!stackTrace || !Array.isArray(stackTrace.callFrames)) {
        return '';
    }

    return stackTrace.callFrames.map((frame) => {
        const functionName = frame.functionName || '<anonymous>';
        const url = frame.url || '';
        const lineNumber = typeof frame.lineNumber === 'number' ? frame.lineNumber + 1 : 0;
        const columnNumber = typeof frame.columnNumber === 'number' ? frame.columnNumber + 1 : 0;
        return `at ${functionName} (${url}:${lineNumber}:${columnNumber})`;
    }).join('\n');
}

function extractPrimaryStackLocation(stackText) {
    if (!stackText) {
        return '';
    }

    const lines = String(stackText)
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean);

    for (const line of lines) {
        const parenthesizedMatch = line.match(/\(([^)]+)\)$/);
        const directMatch = line.match(/^at\s+(.+)$/);
        const candidate = (parenthesizedMatch ? parenthesizedMatch[1] : (directMatch ? directMatch[1] : line)).trim();

        if (!candidate) {
            continue;
        }

        if (/chrome-extension:\/\//i.test(candidate)) {
            continue;
        }

        if (/console_bridge(?:_main)?\.js/i.test(candidate)) {
            continue;
        }

        return candidate;
    }

    return '';
}

function buildConsoleOriginMetadata(commandData) {
    const stackHint = commandData.stackHint || '';
    const runtimeLocation = [
        commandData.filename || '',
        commandData.lineNumber || '',
        commandData.columnNumber || ''
    ].filter(Boolean).join(':');
    const sourceLocation = extractPrimaryStackLocation(stackHint) || runtimeLocation || '';

    let originType = 'page';
    if (sourceLocation && /chrome-extension:\/\//i.test(sourceLocation)) {
        originType = 'extension';
    } else if (!sourceLocation && commandData.source === 'service-worker') {
        originType = 'extension';
    }

    return {
        stackHint: stackHint,
        sourceLocation: sourceLocation,
        originType: originType,
        captureMethod: commandData.captureMethod || 'bridge'
    };
}

function buildDebuggerConsoleCommandData(tabId, params) {
    const argsText = Array.isArray(params.args)
        ? params.args.map(serializeDebuggerRemoteObject).filter(Boolean).join(', ')
        : '';
    const stackText = formatDebuggerStackTrace(params.stackTrace);
    const commandText = params.type === 'trace'
        ? [argsText || 'console.trace()', stackText].filter(Boolean).join('\n')
        : argsText;

    return {
        tabId: tabId,
        type: params.type || 'log',
        source: 'console',
        captureMethod: 'debugger',
        command: commandText,
        timestamp: Date.now(),
        stackHint: stackText
    };
}

function buildDebuggerExceptionCommandData(tabId, params) {
    const details = params.exceptionDetails || {};
    const stackText = formatDebuggerStackTrace(details.stackTrace);
    const description = details.exception && details.exception.description
        ? details.exception.description
        : (details.text || 'Runtime exception');
    const location = [
        details.url || '',
        typeof details.lineNumber === 'number' ? details.lineNumber + 1 : '',
        typeof details.columnNumber === 'number' ? details.columnNumber + 1 : ''
    ].filter(Boolean).join(':');

    return {
        tabId: tabId,
        type: 'runtime-error',
        source: 'runtime-error',
        captureMethod: 'debugger',
        command: [
            `RuntimeError: ${description}`,
            location ? `Location: ${location}` : '',
            stackText
        ].filter(Boolean).join('\n'),
        timestamp: Date.now(),
        stackHint: stackText
    };
}

function normalizeAIResponseHistory(rawHistory) {
    return Array.isArray(rawHistory)
        ? rawHistory.filter((entry) => entry && typeof entry === 'object')
        : [];
}

function buildAIResponseHistoryEntry(commandEntry) {
    const entry = commandEntry && typeof commandEntry === 'object'
        ? commandEntry
        : {};

    return {
        id: `ai-response-${entry.id || Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
        commandId: entry.id || null,
        timestamp: entry.timestamp || Date.now(),
        command: entry.command || '',
        response: entry.analysis || '',
        riskLevel: entry.riskLevel || 'UNKNOWN',
        analysisSource: entry.analysisSource || entry.source || 'unknown',
        type: entry.type || 'unknown',
        domain: entry.domain || '',
        url: entry.url || '',
        blocked: Boolean(entry.blocked),
        fallback: Boolean(entry.fallback),
        cacheHit: Boolean(entry.cacheHit),
        originType: entry.originType || 'page',
        sourceLocation: entry.sourceLocation || '',
        captureMethod: entry.captureMethod || 'bridge'
    };
}

function escapeRegexLiteral(value) {
    return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function buildConsoleActionSet(commandData) {
    const commandText = String(commandData && commandData.command ? commandData.command : '');
    const actions = new Set();

    [commandData && commandData.type, commandData && commandData.source].forEach((value) => {
        const normalized = String(value || '').trim().toLowerCase();
        if (normalized) {
            actions.add(normalized);
        }
    });

    if (/eval\s*\(/i.test(commandText)) {
        actions.add('eval');
    }
    if (/(?:^|[^a-z])function\s*\(|new\s+function\s*\(/i.test(commandText)) {
        actions.add('function');
    }
    if (/fetch\s*\(/i.test(commandText)) {
        actions.add('fetch');
    }
    if (/xmlhttprequest/i.test(commandText)) {
        actions.add('xhr');
    }
    if (/sendbeacon\s*\(/i.test(commandText)) {
        actions.add('beacon');
    }
    if (/postmessage\s*\(/i.test(commandText)) {
        actions.add('postmessage');
    }
    if (/(?:localstorage|sessionstorage)/i.test(commandText)) {
        actions.add('storage');
    }
    if (/document\.write/i.test(commandText)) {
        actions.add('domwrite');
    }
    if (/(?:insertadjacenthtml|innerhtml|outerhtml)/i.test(commandText)) {
        actions.add('htmlinsert');
    }
    if (/window\.open\s*\(/i.test(commandText)) {
        actions.add('open');
    }

    return Array.from(actions);
}

function compareRiskLevel(left, right) {
    const ranking = {
        LOW: 1,
        MEDIUM: 2,
        HIGH: 3,
        CRITICAL: 4
    };

    const leftKey = String(left || 'LOW').toUpperCase();
    const rightKey = String(right || 'LOW').toUpperCase();

    return (ranking[rightKey] || 0) - (ranking[leftKey] || 0);
}

function getHigherRiskLevel(left, right) {
    return compareRiskLevel(left, right) >= 0
        ? String(right || left || 'LOW').toUpperCase()
        : String(left || right || 'LOW').toUpperCase();
}

async function loadConsoleFirewallPolicy() {
    const result = await chrome.storage.local.get(['console_firewall_policy']);
    return normalizeConsoleFirewallPolicy(result.console_firewall_policy);
}

function buildPingPayload() {
    return {
        pong: true,
        timestamp: Date.now(),
        sessions: automationSessions.size,
        cacheFeature: true,
        cacheFeatureVersion: CONSOLE_ANALYSIS_CACHE_FEATURE_VERSION
    };
}

async function getConsoleAnalysisCacheStats() {
    const cache = await getConsoleAnalysisCache();

    return {
        success: true,
        featureVersion: CONSOLE_ANALYSIS_CACHE_FEATURE_VERSION,
        entryCount: Object.keys(cache).length,
        maxEntries: MAX_CONSOLE_ANALYSIS_CACHE_ENTRIES
    };
}

function normalizeConsoleAnalysisCache(rawCache) {
    return rawCache && typeof rawCache === 'object' && !Array.isArray(rawCache)
        ? rawCache
        : {};
}

function normalizeConsoleCacheText(value) {
    return String(value || '')
        .trim()
        .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi, '<uuid>')
        .replace(/\b\d{4}-\d{2}-\d{2}t\d{2}:\d{2}:\d{2}(?:\.\d+)?z\b/gi, '<iso-ts>')
        .replace(/\b\d{10,}\b/g, '<big-num>')
        .replace(/\s+/g, ' ');
}

function buildConsoleAnalysisCacheKey(commandData) {
    const normalizedCommand = normalizeConsoleCacheText(commandData && commandData.command);
    if (!normalizedCommand) {
        return '';
    }

    return [
        String((commandData && commandData.domain) || '').trim().toLowerCase(),
        String((commandData && commandData.type) || '').trim().toLowerCase(),
        normalizedCommand.toLowerCase()
    ].join('||');
}

function pruneConsoleAnalysisCache(cache) {
    const entries = Object.entries(normalizeConsoleAnalysisCache(cache));
    if (entries.length <= MAX_CONSOLE_ANALYSIS_CACHE_ENTRIES) {
        return normalizeConsoleAnalysisCache(cache);
    }

    return Object.fromEntries(
        entries
            .sort((left, right) => {
                const leftTimestamp = Date.parse((left[1] || {}).lastSeenAt || '') || 0;
                const rightTimestamp = Date.parse((right[1] || {}).lastSeenAt || '') || 0;
                return rightTimestamp - leftTimestamp;
            })
            .slice(0, MAX_CONSOLE_ANALYSIS_CACHE_ENTRIES)
    );
}

async function getConsoleAnalysisCache() {
    const result = await chrome.storage.local.get(['ai_commands', CONSOLE_ANALYSIS_CACHE_KEY]);
    const storedCache = normalizeConsoleAnalysisCache(result[CONSOLE_ANALYSIS_CACHE_KEY]);

    if (Object.keys(storedCache).length > 0) {
        return storedCache;
    }

    const hydratedCache = buildConsoleAnalysisCacheFromHistory(result.ai_commands, storedCache);

    if (Object.keys(hydratedCache.cache).length > 0) {
        await chrome.storage.local.set({
            [CONSOLE_ANALYSIS_CACHE_KEY]: hydratedCache.cache
        });
    }

    return hydratedCache.cache;
}

async function findConsoleAnalysisCache(commandData) {
    const cacheKey = buildConsoleAnalysisCacheKey(commandData);
    if (!cacheKey) {
        return null;
    }

    const cache = await getConsoleAnalysisCache();
    const entry = cache[cacheKey];

    if (!entry || typeof entry !== 'object') {
        return null;
    }

    return {
        cacheKey: cacheKey,
        entry: entry
    };
}

function buildConsoleAnalysisCacheEntry(commandData, result, previousEntry, observedAt) {
    const now = observedAt || new Date().toISOString();

    return {
        command: String((commandData && commandData.command) || '').slice(0, 4000),
        normalizedCommand: normalizeConsoleCacheText(commandData && commandData.command),
        type: String((commandData && commandData.type) || 'unknown'),
        domain: String((commandData && commandData.domain) || ''),
        riskLevel: previousEntry
            ? getHigherRiskLevel(previousEntry.riskLevel, String((result && result.riskLevel) || 'UNKNOWN').toUpperCase())
            : String((result && result.riskLevel) || 'UNKNOWN').toUpperCase(),
        analysis: String((result && result.analysis) || (previousEntry && previousEntry.analysis) || ''),
        source: String((result && (result.analysisSource || result.source)) || 'unknown'),
        fallback: Boolean(result && result.fallback),
        firstSeenAt: (previousEntry && previousEntry.firstSeenAt) || now,
        lastSeenAt: now,
        seenCount: Number((previousEntry && previousEntry.seenCount) || 0) + 1
    };
}

function buildConsoleAnalysisCacheFromHistory(commands, initialCache = {}) {
    const cache = normalizeConsoleAnalysisCache(initialCache);
    const history = Array.isArray(commands) ? commands : [];
    const sortedCommands = [...history].sort((left, right) => {
        const leftTime = new Date(left && left.timestamp ? left.timestamp : 0).getTime() || 0;
        const rightTime = new Date(right && right.timestamp ? right.timestamp : 0).getTime() || 0;
        return leftTime - rightTime;
    });

    let hydrated = 0;

    for (const command of sortedCommands) {
        const cacheKey = buildConsoleAnalysisCacheKey(command);
        if (!cacheKey) {
            continue;
        }

        const previousEntry = cache[cacheKey];
        cache[cacheKey] = buildConsoleAnalysisCacheEntry(
            command,
            {
                analysis: command.analysis,
                riskLevel: command.riskLevel,
                source: command.analysisSource || command.source,
                fallback: command.fallback
            },
            previousEntry,
            normalizeObservedTimestamp(command.timestamp)
        );
        hydrated += 1;
    }

    return {
        cache: pruneConsoleAnalysisCache(cache),
        hydrated: hydrated,
        total: history.length
    };
}

async function rememberConsoleAnalysis(commandData, result) {
    const cacheKey = buildConsoleAnalysisCacheKey(commandData);
    if (!cacheKey) {
        return null;
    }

    const cache = await getConsoleAnalysisCache();
    const previousEntry = cache[cacheKey];
    cache[cacheKey] = buildConsoleAnalysisCacheEntry(commandData, result, previousEntry);

    await chrome.storage.local.set({
        [CONSOLE_ANALYSIS_CACHE_KEY]: pruneConsoleAnalysisCache(cache)
    });

    return cache[cacheKey];
}

function normalizeObservedTimestamp(value) {
    if (!value) {
        return new Date().toISOString();
    }

    const date = new Date(value);
    return Number.isNaN(date.getTime())
        ? new Date().toISOString()
        : date.toISOString();
}

async function hydrateConsoleAnalysisCacheFromHistory() {
    const storage = await chrome.storage.local.get(['ai_commands', CONSOLE_ANALYSIS_CACHE_KEY]);
    const commands = Array.isArray(storage.ai_commands) ? storage.ai_commands : [];

    if (!commands.length) {
        await chrome.storage.local.set({ [CONSOLE_ANALYSIS_CACHE_KEY]: {} });
        return { hydrated: 0, total: 0 };
    }

    const hydratedCache = buildConsoleAnalysisCacheFromHistory(
        commands,
        storage[CONSOLE_ANALYSIS_CACHE_KEY]
    );

    await chrome.storage.local.set({
        [CONSOLE_ANALYSIS_CACHE_KEY]: hydratedCache.cache
    });

    return { hydrated: hydratedCache.hydrated, total: hydratedCache.total };
}

function buildCachedConsoleAnalysisResult(entry) {
    const source = String((entry && entry.source) || 'unknown');

    return {
        analysis: String((entry && entry.analysis) || ''),
        riskLevel: String((entry && entry.riskLevel) || 'UNKNOWN').toUpperCase(),
        source: source,
        analysisSource: source,
        fallback: Boolean(entry && entry.fallback),
        cacheHit: true
    };
}

function extractAnalysisField(analysis, fieldName) {
    const text = String(analysis || '');
    if (!text) {
        return '';
    }

    const matcher = new RegExp(`^${fieldName}:\\s*(.+)$`, 'im');
    const match = text.match(matcher);
    return match ? String(match[1] || '').trim() : '';
}

function shouldBlockLearnedConsoleRule(commandData, severity) {
    const normalizedSeverity = String(severity || '').toUpperCase();
    return Boolean(commandData && commandData.blocked) || ['HIGH', 'CRITICAL'].includes(normalizedSeverity);
}

function buildRuleReasonFromAnalysis(commandData, severity) {
    const description = extractAnalysisField(commandData && commandData.analysis, 'DESCRIPTION');
    if (description) {
        return description;
    }

    return shouldBlockLearnedConsoleRule(commandData, severity)
        ? 'Security review marked this console pattern for blocking.'
        : 'Security review recorded this console pattern for monitoring.';
}

async function evaluateConsoleFirewallPolicy(commandData) {
    const policy = await loadConsoleFirewallPolicy();
    const actions = buildConsoleActionSet(commandData);
    const actionSet = new Set(actions.map((action) => String(action || '').toLowerCase()));
    const commandText = String(commandData && commandData.command ? commandData.command : '');

    for (const rule of policy.rules || []) {
        if (!rule || rule.enabled === false || !rule.pattern) {
            continue;
        }

        const appliesTo = Array.isArray(rule.appliesTo)
            ? rule.appliesTo.map((value) => String(value || '').toLowerCase()).filter(Boolean)
            : [];

        if (appliesTo.length > 0 && !appliesTo.some((value) => actionSet.has(value))) {
            continue;
        }

        let matcher = null;
        try {
            matcher = new RegExp(rule.pattern, 'i');
        } catch (error) {
            console.warn('[Console Firewall] Invalid rule pattern skipped:', rule.id, error.message);
            continue;
        }

        if (!matcher.test(commandText)) {
            continue;
        }

        const severity = String(rule.severity || 'HIGH').toUpperCase();
        const shouldBlock = policy.mode !== 'monitor'
            && (rule.block === true || (rule.block !== false && ['HIGH', 'CRITICAL'].includes(severity)));

        return {
            policy: policy,
            matchedRule: rule,
            actions: actions,
            severity: severity,
            shouldBlock: shouldBlock
        };
    }

    return {
        policy: policy,
        matchedRule: null,
        actions: actions,
        severity: 'LOW',
        shouldBlock: false
    };
}

function buildLearnedConsoleRule(commandData, actions) {
    const commandText = String(commandData && commandData.command ? commandData.command : '')
        .trim()
        .replace(/\s+/g, ' ');

    if (!commandText) {
        return null;
    }

    let hash = 0;
    for (let index = 0; index < commandText.length; index += 1) {
        hash = ((hash << 5) - hash) + commandText.charCodeAt(index);
        hash |= 0;
    }

    const severity = String(
        commandData.blockSeverity ||
        commandData.riskLevel ||
        'LOW'
    ).toUpperCase();
    const normalizedActions = Array.isArray(actions) && actions.length > 0
        ? actions.map((value) => String(value || '').toLowerCase()).filter(Boolean).slice(0, 6)
        : [String((commandData && (commandData.type || commandData.source)) || 'log').toLowerCase()].filter(Boolean);
    const shouldBlock = shouldBlockLearnedConsoleRule(commandData, severity);

    return {
        id: `console-pattern-${Math.abs(hash).toString(16)}`,
        appliesTo: normalizedActions,
        pattern: escapeRegexLiteral(commandText).replace(/\s+/g, '\\s+'),
        severity: severity,
        block: shouldBlock,
        enabled: true,
        learned: true,
        reason: buildRuleReasonFromAnalysis(commandData, severity),
        updatedAt: new Date().toISOString()
    };
}

async function promoteConsoleFirewallRule(commandData, policyDecision) {
    if (!commandData || !commandData.command || !commandData.analysis) {
        return null;
    }

    const riskLevel = String(
        commandData.blockSeverity ||
        commandData.riskLevel ||
        ''
    ).toUpperCase();

    const nextPolicy = await queueConsoleFirewallPolicyMutation(async (currentPolicy) => {
        const policy = normalizeConsoleFirewallPolicy(currentPolicy);
        const updatedPolicy = {
            ...policy,
            rules: Array.isArray(policy.rules) ? policy.rules.map((rule) => ({ ...rule })) : []
        };
        const now = new Date().toISOString();
        let changed = false;

        if (policyDecision && policyDecision.matchedRule) {
            const ruleIndex = updatedPolicy.rules.findIndex((rule) => rule && rule.id === policyDecision.matchedRule.id);
            if (ruleIndex >= 0) {
                const existingRule = updatedPolicy.rules[ruleIndex];
                const nextSeverity = getHigherRiskLevel(existingRule.severity, riskLevel || policyDecision.severity);
                const nextBlock = Boolean(existingRule.block) || shouldBlockLearnedConsoleRule(commandData, nextSeverity);
                const updatedRule = {
                    ...existingRule,
                    block: nextBlock,
                    enabled: true,
                    learned: existingRule.learned || Boolean(commandData.analysis),
                    severity: nextSeverity,
                    reason: commandData.blockReason || existingRule.reason,
                    updatedAt: now,
                    hitCount: Number(existingRule.hitCount || 0) + 1
                };

                if (JSON.stringify(updatedRule) !== JSON.stringify(existingRule)) {
                    updatedPolicy.rules[ruleIndex] = updatedRule;
                    changed = true;
                }
            }
        } else {
            const learnedRule = buildLearnedConsoleRule(commandData, policyDecision && policyDecision.actions);
            if (learnedRule) {
                const existingRuleIndex = updatedPolicy.rules.findIndex((rule) => rule && rule.id === learnedRule.id);

                if (existingRuleIndex >= 0) {
                    const existingRule = updatedPolicy.rules[existingRuleIndex];
                    const nextSeverity = getHigherRiskLevel(existingRule.severity, learnedRule.severity);
                    const nextBlock = Boolean(existingRule.block) || Boolean(learnedRule.block);
                    const updatedRule = {
                        ...existingRule,
                        block: nextBlock,
                        enabled: true,
                        learned: true,
                        severity: nextSeverity,
                        reason: commandData.blockReason || existingRule.reason || learnedRule.reason,
                        updatedAt: now,
                        hitCount: Number(existingRule.hitCount || 0) + 1
                    };

                    if (JSON.stringify(updatedRule) !== JSON.stringify(existingRule)) {
                        updatedPolicy.rules[existingRuleIndex] = updatedRule;
                        changed = true;
                    }
                } else {
                    updatedPolicy.rules.unshift({
                        ...learnedRule,
                        hitCount: 1
                    });
                    changed = true;
                }
            }
        }

        if (!changed) {
            return null;
        }

        updatedPolicy.updatedAt = now;
        updatedPolicy.version = Date.now();
        await chrome.storage.local.set({ 'console_firewall_policy': updatedPolicy });
        return updatedPolicy;
    });

    if (!nextPolicy) {
        return null;
    }

    await saveConsoleFirewallPolicyToBackend(nextPolicy);
    return nextPolicy;
}

async function hydrateConsoleFirewallRulesFromHistory() {
    const storage = await chrome.storage.local.get(['ai_commands']);
    const commands = Array.isArray(storage.ai_commands) ? storage.ai_commands : [];

    if (!commands.length) {
        return { updated: false, hydrated: 0, total: 0 };
    }

    const sortedCommands = [...commands].sort((left, right) => {
        const leftTime = new Date(left && left.timestamp ? left.timestamp : 0).getTime() || 0;
        const rightTime = new Date(right && right.timestamp ? right.timestamp : 0).getTime() || 0;
        return leftTime - rightTime;
    });
    const result = await queueConsoleFirewallPolicyMutation(async (currentPolicy) => {
        const nextPolicy = normalizeConsoleFirewallPolicy(currentPolicy);
        nextPolicy.rules = Array.isArray(nextPolicy.rules) ? nextPolicy.rules.map((rule) => ({ ...rule })) : [];

        let changed = false;
        let hydrated = 0;

        for (const command of sortedCommands) {
            if (!command || !command.command || !command.analysis) {
                continue;
            }

            const learnedRule = buildLearnedConsoleRule(command, buildConsoleActionSet(command));
            if (!learnedRule) {
                continue;
            }

            const existingRuleIndex = nextPolicy.rules.findIndex((rule) => rule && rule.id === learnedRule.id);
            if (existingRuleIndex >= 0) {
                const existingRule = nextPolicy.rules[existingRuleIndex];
                const nextSeverity = getHigherRiskLevel(existingRule.severity, learnedRule.severity);
                const nextBlock = Boolean(existingRule.block) || Boolean(learnedRule.block);
                const updatedRule = {
                    ...existingRule,
                    block: nextBlock,
                    enabled: true,
                    learned: true,
                    severity: nextSeverity,
                    reason: existingRule.reason || learnedRule.reason,
                    updatedAt: new Date(command.timestamp || Date.now()).toISOString(),
                    hitCount: Number(existingRule.hitCount || 0) + 1
                };

                if (JSON.stringify(updatedRule) !== JSON.stringify(existingRule)) {
                    nextPolicy.rules[existingRuleIndex] = updatedRule;
                    changed = true;
                }
            } else {
                nextPolicy.rules.unshift({
                    ...learnedRule,
                    hitCount: 1
                });
                changed = true;
            }

            hydrated += 1;
        }

        if (!changed) {
            return { updated: false, hydrated: hydrated, total: commands.length };
        }

        nextPolicy.updatedAt = new Date().toISOString();
        nextPolicy.version = Date.now();
        await chrome.storage.local.set({ 'console_firewall_policy': nextPolicy });

        return {
            updated: true,
            hydrated: hydrated,
            total: commands.length,
            policy: nextPolicy
        };
    });

    if (result.updated && result.policy) {
        await saveConsoleFirewallPolicyToBackend(result.policy);
    }

    return result;
}

function shouldSkipDuplicateUrlBlock(url, tabId) {
    const fingerprint = `${tabId || 'no-tab'}|${url || ''}`;
    const now = Date.now();
    const existing = recentUrlBlockFingerprints.get(fingerprint);

    for (const [key, timestamp] of recentUrlBlockFingerprints.entries()) {
        if (now - timestamp > 5000) {
            recentUrlBlockFingerprints.delete(key);
        }
    }

    if (existing && now - existing < 2000) {
        return true;
    }

    recentUrlBlockFingerprints.set(fingerprint, now);
    return false;
}

async function resolveConsoleCaptureTabId(preferredTabId) {
    if (preferredTabId) {
        try {
            const preferredTab = await chrome.tabs.get(preferredTabId);
            if (isInjectableConsoleBridgeUrl(preferredTab.url || '')) {
                rememberInspectableTab(preferredTab);
                return preferredTab.id;
            }
        } catch (error) {
            // Ignore stale tab ids.
        }
    }

    if (lastInspectableTabId) {
        try {
            const lastTab = await chrome.tabs.get(lastInspectableTabId);
            if (isInjectableConsoleBridgeUrl(lastTab.url || '')) {
                return lastTab.id;
            }
        } catch (error) {
            lastInspectableTabId = null;
        }
    }

    const tabs = await chrome.tabs.query({ lastFocusedWindow: true });
    const targetTab = tabs.find((tab) => isInjectableConsoleBridgeUrl(tab.url || ''));

    if (!targetTab) {
        return null;
    }

    rememberInspectableTab(targetTab);
    return targetTab.id;
}

async function processCapturedConsoleCommand(commandData) {
    const normalizedCommand = {
        ...commandData,
        timestamp: commandData.timestamp || Date.now()
    };

    if (shouldIgnoreBenignConsoleCommand(normalizedCommand)) {
        return { success: true, skipped: true, benign: true };
    }

    if (shouldSkipDuplicateConsoleCapture(normalizedCommand)) {
        return { success: true, skipped: true };
    }

    try {
        const policyDecision = await evaluateConsoleFirewallPolicy(normalizedCommand);

        if (policyDecision.shouldBlock && policyDecision.matchedRule) {
            normalizedCommand.blocked = true;
            normalizedCommand.blockRule = policyDecision.matchedRule.id || '';
            normalizedCommand.blockSeverity = policyDecision.severity || 'HIGH';
            normalizedCommand.blockReason = policyDecision.matchedRule.reason || 'Blocked by console firewall rule';
        }

        const cachedAnalysis = await findConsoleAnalysisCache(normalizedCommand);
        const baseResult = cachedAnalysis
            ? buildCachedConsoleAnalysisResult(cachedAnalysis.entry)
            : await consoleMonitor.analyzeWithOpenAI(normalizedCommand);

        await rememberConsoleAnalysis(normalizedCommand, {
            analysis: baseResult.analysis,
            riskLevel: baseResult.riskLevel,
            source: baseResult.analysisSource || baseResult.source,
            fallback: baseResult.fallback
        });

        const enrichedResult = consoleMonitor.applyFirewallMetadata(normalizedCommand, baseResult);
        const storedCommand = {
            ...normalizedCommand,
            ...enrichedResult,
            cacheHit: Boolean(cachedAnalysis),
            analysisSource: baseResult.analysisSource || baseResult.source || 'unknown',
            timestamp: normalizedCommand.timestamp || enrichedResult.timestamp || Date.now()
        };

        await promoteConsoleFirewallRule(storedCommand, policyDecision);

        if (storedCommand.blocked || storedCommand.riskLevel === 'HIGH' || storedCommand.riskLevel === 'CRITICAL') {
            consoleMonitor.executeBlock(storedCommand, {
                should_block: true,
                confidence: storedCommand.blocked ? 1 : 0.9,
                reason: storedCommand.blockReason || 'High risk console command detected'
            });
        }

        consoleMonitor.saveCommandToTestingPanel(storedCommand);
        return { success: true, result: enrichedResult, storedCommand: storedCommand };
    } catch (error) {
        console.error('[Background] Console command analysis error:', error);
        consoleMonitor.saveCommandToTestingPanel({
            ...normalizedCommand,
            analysis: 'Analysis failed: ' + error.message,
            riskLevel: 'UNKNOWN',
            timestamp: normalizedCommand.timestamp || Date.now()
        });
        return { success: false, error: error.message };
    }
}

async function injectMainWorldConsoleBridge(tabId) {
    try {
        await chrome.scripting.executeScript({
            target: { tabId: tabId, allFrames: false },
            files: ['console_bridge_main.js'],
            world: 'MAIN'
        });

        return { success: true };
    } catch (error) {
        console.warn('[Console Bridge] Main-world injection failed:', error.message);
        return { success: false, error: error.message };
    }
}

async function ensureDebuggerConsoleCapture(tabId) {
    const targetTabId = await resolveConsoleCaptureTabId(tabId);

    if (!targetTabId) {
        return { success: false, error: 'No inspectable browser tab found' };
    }

    try {
        if (!consoleDebuggerTabs.has(targetTabId)) {
            try {
                await chrome.debugger.attach({ tabId: targetTabId }, '1.3');
            } catch (error) {
                if (!String(error.message || '').includes('Another debugger is already attached')) {
                    throw error;
                }
            }
        }

        await chrome.debugger.sendCommand({ tabId: targetTabId }, 'Runtime.enable');
        await chrome.debugger.sendCommand({ tabId: targetTabId }, 'Log.enable');
        await chrome.debugger.sendCommand({ tabId: targetTabId }, 'Runtime.setAsyncCallStackDepth', { maxDepth: 8 });
        consoleDebuggerTabs.add(targetTabId);

        return { success: true, tabId: targetTabId };
    } catch (error) {
        console.warn('[Console Capture] Debugger attach failed:', error.message);
        return { success: false, error: error.message };
    }
}

// Console Monitor for AI Analysis
const consoleMonitor = {
    apiKey: "api key",
    commands: [],
    lastAnalysisTime: 0,
    analysisCooldown: 1000,
    consecutiveFailures: 0,
    maxConsecutiveFailures: 3,
    analysisDisabled: false,
    quotaExceeded: false,
    
    analyzeWithOpenAI: async function(commandData) {
        try {
            // Use backend API instead of direct OpenAI calls to avoid CORS issues
            const response = await fetchTunnelAware(`${API_BASE}/ai/analyze`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    command: commandData.command,
                    type: commandData.type,
                    source: commandData.source,
                    domain: commandData.domain,
                    url: commandData.url,
                    timestamp: commandData.timestamp
                })
            });
            
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Backend API error: ${response.status} ${response.statusText} - ${errorText}`);
            }
            
            const result = await response.json();
            
            if (!result.success) {
                throw new Error(result.error || 'Backend analysis failed');
            }
            
            // Extract risk level from backend response
            const analysis = result.analysis;
            const riskLevel = this.extractRiskLevel(analysis);
            
            // Reset consecutive failures on success
            this.consecutiveFailures = 0;
            this.analysisDisabled = false;
            
            return {
                analysis: analysis,
                riskLevel: riskLevel,
                command: commandData.command,
                type: commandData.type,
                timestamp: Date.now(),
                source: 'ai'
            };
            
        } catch (error) {
            console.warn('AI analysis failed, using local fallback:', error.message);
            this.consecutiveFailures++;
            
            // Always provide local analysis as fallback
            const localAnalysis = this.performLocalAnalysis(commandData);
            
            // Disable AI only after many consecutive failures
            if (this.consecutiveFailures >= this.maxConsecutiveFailures) {
                this.analysisDisabled = true;
                console.warn(`AI analysis disabled after ${this.consecutiveFailures} consecutive failures, using local analysis only`);
            }
            
            return {
                analysis: localAnalysis.analysis,
                riskLevel: localAnalysis.riskLevel,
                command: commandData.command,
                type: commandData.type,
                timestamp: Date.now(),
                source: 'local',
                fallback: true
            };
        }
    },
    
    performLocalAnalysis: function(commandData) {
        const command = commandData.command.toLowerCase();
        const type = commandData.type;
        
        // Define suspicious patterns
        const suspiciousPatterns = [
            /eval\s*\(/i,
            /document\.write/i,
            /innerhtml\s*=/i,
            /settimeout\s*\(/i,
            /setinterval\s*\(/i,
            /function\s*\(\s*\)\s*\{/i,
            /javascript:/i,
            /data:/i,
            /vbscript:/i,
            /onload\s*=/i,
            /onerror\s*=/i,
            /onclick\s*=/i
        ];
        
        const dangerousPatterns = [
            /document\.cookie/i,
            /localstorage/i,
            /sessionstorage/i,
            /window\.location/i,
            /fetch\s*\(/i,
            /xmlhttprequest/i,
            /postmessage/i,
            /atob\s*\(/i,
            /btoa\s*\(/i
        ];
        
        let riskScore = 0;
        let threatType = 'UNKNOWN';
        
        // Check for suspicious patterns
        for (const pattern of suspiciousPatterns) {
            if (pattern.test(command)) {
                riskScore += 2;
            }
        }
        
        // Check for dangerous patterns
        for (const pattern of dangerousPatterns) {
            if (pattern.test(command)) {
                riskScore += 5;
                threatType = 'CODE_INJECTION';
            }
        }
        
        // Determine risk level
        let riskLevel = 'LOW';
        if (riskScore >= 7) {
            riskLevel = 'HIGH';
        } else if (riskScore >= 4) {
            riskLevel = 'MEDIUM';
        }
        
        const analysis = `RISK_LEVEL: ${riskLevel}
THREAT_TYPE: ${threatType}
DESCRIPTION: Local analysis detected ${riskLevel.toLowerCase()} risk patterns in the console command.
RECOMMENDATION: ${riskLevel === 'HIGH' ? 'Block this command' : 'Monitor this command'}`;
        
        return {
            analysis: analysis,
            riskLevel: riskLevel
        };
    },
    
    extractRiskLevel: function(analysis) {
        if (!analysis || typeof analysis !== 'string') {
            return 'UNKNOWN';
        }
        
        const riskMatch = analysis.match(/RISK_LEVEL:\s*(LOW|MEDIUM|HIGH|CRITICAL)/i);
        return riskMatch ? riskMatch[1].toUpperCase() : 'UNKNOWN';
    },

    applyFirewallMetadata: function(commandData, result) {
        if (!commandData || !commandData.blocked) {
            return result;
        }

        const enforcedRisk = commandData.blockSeverity || result.riskLevel || 'HIGH';
        const prefix = [
            `RISK_LEVEL: ${enforcedRisk}`,
            'THREAT_TYPE: FIREWALL_BLOCK',
            'DESCRIPTION: Firewall blocked a harmful console pattern before execution.',
            `RECOMMENDATION: Execution prevented${commandData.blockReason ? ` - ${commandData.blockReason}` : ''}`
        ].join('\n');

        return {
            ...result,
            riskLevel: enforcedRisk,
            analysis: `${prefix}\n\n${result.analysis || ''}`.trim()
        };
    },
    
    saveCommandToTestingPanel: function(commandData) {
        try {
            console.log('[Testing Panel] Saving command:', commandData);
            
            chrome.storage.local.get(['ai_commands', AI_RESPONSE_HISTORY_KEY], (result) => {
                const commands = result.ai_commands || [];
                const aiResponses = normalizeAIResponseHistory(result[AI_RESPONSE_HISTORY_KEY]);
                
                const commandEntry = {
                    id: Date.now() + Math.random(),
                    timestamp: commandData.timestamp || Date.now(),
                    command: commandData.command || '',
                    type: commandData.type || 'unknown',
                    analysis: commandData.analysis || '',
                    riskLevel: commandData.riskLevel || 'UNKNOWN',
                    source: commandData.source || 'unknown',
                    domain: commandData.domain || '',
                    url: commandData.url || '',
                    blocked: commandData.blocked || false,
                    blockReason: commandData.blockReason || '',
                    blockRule: commandData.blockRule || '',
                    blockSeverity: commandData.blockSeverity || '',
                    fallback: commandData.fallback || false,
                    cacheHit: commandData.cacheHit || false,
                    analysisSource: commandData.analysisSource || commandData.source || 'unknown',
                    ...buildConsoleOriginMetadata(commandData)
                };
                
                commands.push(commandEntry);
                console.log('[Testing Panel] Added command entry:', commandEntry);
                console.log('[Testing Panel] Total commands now:', commands.length);
                
                if (commands.length > 1000) {
                    commands.splice(0, commands.length - 1000);
                }

                aiResponses.push(buildAIResponseHistoryEntry(commandEntry));

                if (aiResponses.length > MAX_AI_RESPONSE_HISTORY_ENTRIES) {
                    aiResponses.splice(0, aiResponses.length - MAX_AI_RESPONSE_HISTORY_ENTRIES);
                }
                
                chrome.storage.local.set({
                    'ai_commands': commands,
                    [AI_RESPONSE_HISTORY_KEY]: aiResponses
                }, () => {
                    console.log('[Testing Panel] Successfully saved to storage');

                    hydrateConsoleAnalysisCacheFromHistory().catch((error) => {
                        console.warn('[Console Cache] Failed to hydrate after saving command history:', error.message);
                    });
                    
                    // Notify AI Testing Panel about the update
                    safeRuntimeSendMessage({
                        action: 'commandsUpdated',
                        count: commands.length
                    });

                    safeRuntimeSendMessage({
                        action: 'aiResponsesUpdated',
                        count: aiResponses.length
                    });
                });
            });
        } catch (error) {
            console.warn('Failed to save command to testing panel:', error);
        }
    },
    
    notifyRisk: function(commandData) {
        try {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icon.png',
                title: `${commandData.riskLevel} Risk Detected`,
                message: `${commandData.type}: ${commandData.command.substring(0, 50)}...`
            });
        } catch (error) {
            console.error('Failed to show risk notification:', error);
        }
    },
    
    validateAndBlock: function(commandData) {
        console.warn('[Validation] Using local validation - backend not accessible');
        
        if (commandData.riskLevel === 'CRITICAL' || commandData.riskLevel === 'HIGH') {
            this.executeBlock(commandData, {
                should_block: true,
                confidence: 0.9,
                reason: 'High risk command blocked locally'
            });
        }
    },
    
    executeBlock: function(commandData, validationResult) {
        console.log(`[Validation] Executing block for ${commandData.riskLevel} risk command`);
        commandData.blocked = true;
        commandData.validation_result = validationResult;
        
        this.showBlockNotification(commandData, validationResult);
        this.logBlockDecision(commandData, validationResult);
    },
    
    showBlockNotification: function(commandData, validationResult) {
        try {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icon.png',
                title: '🛡️ Dangerous Command Blocked',
                message: `${commandData.riskLevel} risk: ${commandData.command.substring(0, 60)}...`
            });
        } catch (error) {
            console.error('Failed to show block notification:', error);
        }
    },
    
    logBlockDecision: function(commandData, validationResult) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            command: commandData.command,
            original_risk: commandData.riskLevel,
            blocked: true
        };
        
        chrome.storage.local.get(['block_decisions'], (result) => {
            const decisions = result.block_decisions || [];
            decisions.push(logEntry);
            
            if (decisions.length > 500) {
                decisions.splice(0, decisions.length - 500);
            }
            
            chrome.storage.local.set({ 'block_decisions': decisions });
        });
    }
};

chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace !== 'local') {
        return;
    }

    if (changes.ai_commands) {
        const nextCommands = Array.isArray(changes.ai_commands.newValue) ? changes.ai_commands.newValue : [];

        if (!nextCommands.length) {
            chrome.storage.local.set({ [CONSOLE_ANALYSIS_CACHE_KEY]: {} }).catch((error) => {
                console.warn('[Console Cache] Failed to clear cache after command history reset:', error.message);
            });
        } else {
            hydrateConsoleAnalysisCacheFromHistory().catch((error) => {
                console.warn('[Console Cache] Failed to sync cache from updated command history:', error.message);
            });

            hydrateConsoleFirewallRulesFromHistory().catch((error) => {
                console.warn('[Console Firewall] Failed to sync learned rules from updated command history:', error.message);
            });
        }
    }

    if (changes[ENDPOINT_CONFIG_KEY]) {
        applyEndpointConfig(changes[ENDPOINT_CONFIG_KEY].newValue || DEFAULT_ENDPOINT_CONFIG)
            .then((config) => {
                backendConnected = false;
                console.log(`[Config] Endpoint mode updated: ${getEndpointMode(config)}`);
            })
            .catch((error) => {
                console.warn('[Config] Failed to apply endpoint update:', error.message);
            });
    }

    if (!changes.console_firewall_policy) {
        return;
    }

    recordRuleChange(
        'local',
        'console-policy',
        changes.console_firewall_policy.oldValue || {},
        changes.console_firewall_policy.newValue || {},
        {
            source: 'console_firewall_policy',
            force: !changes.console_firewall_policy.oldValue,
            note: !changes.console_firewall_policy.oldValue
                ? 'Local console firewall policy initialized'
                : 'Local console firewall policy updated'
        }
    ).catch((error) => {
        console.warn('[Rules] Failed to record local console policy change:', error.message);
    });
});

async function initializeRuntimeServices() {
    await endpointConfigReady;

    try {
        await hydrateConsoleAnalysisCacheFromHistory();
    } catch (error) {
        console.warn('[Console Cache] Failed to hydrate from history:', error.message);
    }

    try {
        await hydrateConsoleFirewallRulesFromHistory();
    } catch (error) {
        console.warn('[Console Firewall] Failed to hydrate learned rules from history:', error.message);
    }

    try {
        await updateLocalEngineSnapshot({ skipHistory: true });
    } catch (error) {
        console.warn('[Local Engine] Snapshot refresh failed:', error.message);
    }

    try {
        await ensureRuleVisibilityHistory();
    } catch (error) {
        console.warn('[Rules] Failed to seed visibility history:', error.message);
    }

    initializeAdBlockRules();
    await checkBackendConnection();

    try {
        await syncConsoleFirewallPolicyFromBackend({ skipConnectCheck: true });
    } catch (error) {
        console.warn('[Console Firewall] Initial backend policy sync failed:', error.message);
    }

    try {
        await checkRuleUpdates({ forceDownload: true });
    } catch (error) {
        console.warn('[Rules] Initial sync failed:', error.message);
    }
}

ensureConsoleFirewallPolicy();
const endpointConfigReady = loadEndpointConfig().catch((error) => {
    console.warn('[Config] Failed to load bundled tunnel endpoints:', error.message);
    return applyEndpointConfig(DEFAULT_ENDPOINT_CONFIG);
});


class ServiceWorkerSessionStorage {
    constructor() {
        this.storageKey = 'firewall_guard_sessions';
        this.currentSessionKey = 'firewall_guard_current_session';
        this.sessionHistoryKey = 'firewall_guard_session_history';
        this.init();
    }

    init() {
        console.log('[SW SessionStorage] Initializing service worker session storage...');
        this.ensureStorageStructure();
    }

    async ensureStorageStructure() {
        try {
            const result = await chrome.storage.local.get(this.storageKey);
            if (!result[this.storageKey]) {
                const initialData = {
                    currentSession: null,
                    sessionHistory: [],
                    lastUpdated: null,
                    version: '1.0'
                };
                await chrome.storage.local.set({ [this.storageKey]: initialData });
                console.log('[SW SessionStorage] Created initial storage structure');
            }
        } catch (error) {
            console.error('[SW SessionStorage] Failed to ensure storage structure:', error);
        }
    }

    async storeCurrentSession(sessionData) {
        try {
            const result = await chrome.storage.local.get(this.storageKey);
            const storage = result[this.storageKey] || {
                currentSession: null,
                sessionHistory: [],
                lastUpdated: null,
                version: '1.0'
            };
            
            storage.currentSession = {
                sessionId: sessionData.sessionId,
                windowId: sessionData.windowId,
                tabId: sessionData.tabId,
                url: sessionData.url || 'https://google.com',
                startTime: sessionData.startTime || Date.now(),
                status: sessionData.status || 'active',
                lastActivity: Date.now(),
                type: sessionData.type || 'manual',
                controlled: Boolean(sessionData.controlled),
                forced: Boolean(sessionData.forced)
            };

            if (storage.currentSession.sessionId) {
                storage.sessionHistory = storage.sessionHistory.filter(
                    session => session.sessionId !== storage.currentSession.sessionId
                );
                
                storage.sessionHistory.unshift({...storage.currentSession});
                
                if (storage.sessionHistory.length > 10) {
                    storage.sessionHistory = storage.sessionHistory.slice(0, 10);
                }
            }

            storage.lastUpdated = Date.now();
            
            await chrome.storage.local.set({ [this.storageKey]: storage });
            
            console.log('[SW SessionStorage] Stored current session:', storage.currentSession);
            
            this.notifySessionUpdate('sessionStored', storage.currentSession);
            
            return true;
        } catch (error) {
            console.error('[SW SessionStorage] Failed to store session:', error);
            return false;
        }
    }

    async getCurrentSession() {
        try {
            const result = await chrome.storage.local.get(this.storageKey);
            const storage = result[this.storageKey] || {
                currentSession: null,
                sessionHistory: [],
                lastUpdated: null,
                version: '1.0'
            };
            
            console.log('[SW SessionStorage] Retrieved current session:', storage.currentSession);
            return storage.currentSession;
        } catch (error) {
            console.error('[SW SessionStorage] Failed to get current session:', error);
            return null;
        }
    }

    async getAllSessions() {
        try {
            const result = await chrome.storage.local.get(this.storageKey);
            const storage = result[this.storageKey] || {
                currentSession: null,
                sessionHistory: [],
                lastUpdated: null,
                version: '1.0'
            };
            
            const allSessions = [];
            
            if (storage.currentSession) {
                allSessions.push({
                    ...storage.currentSession,
                    isCurrent: true
                });
            }
            
            storage.sessionHistory.forEach(session => {
                allSessions.push({
                    ...session,
                    isCurrent: false
                });
            });
            
            console.log('[SW SessionStorage] Retrieved all sessions:', allSessions);
            return allSessions;
        } catch (error) {
            console.error('[SW SessionStorage] Failed to get all sessions:', error);
            return [];
        }
    }

    notifySessionUpdate(eventType, data) {
        try {
            safeRuntimeSendMessage({
                action: 'sessionStorageUpdate',
                type: eventType,
                data: data,
                timestamp: Date.now()
            });
            
            console.log('[SW SessionStorage] Notified session update:', eventType, data);
        } catch (error) {
            console.error('[SW SessionStorage] Failed to notify session update:', error);
        }
    }
}

const swSessionStorage = new ServiceWorkerSessionStorage();

async function updateExtensionBadge() {
    try {
        const currentSession = await swSessionStorage.getCurrentSession();
        
        if (currentSession && currentSession.sessionId) {
            chrome.action.setBadgeText({ text: '🛡️' });
            chrome.action.setTitle({ title: `Firewall Guard - Session: ${currentSession.sessionId}` });
            
            console.log('[Background] Extension badge updated with session:', currentSession.sessionId);
        } else {
            chrome.action.setBadgeText({ text: '' });
            chrome.action.setTitle({ title: 'Firewall Guard - No Session' });
            
            console.log('[Background] Extension badge cleared - no session');
        }
    } catch (error) {
        console.error('[Background] Failed to update extension badge:', error);
    }
}

setInterval(updateExtensionBadge, 5000);

setInterval(checkAndCleanupExpiredSessions, 10000);

updateExtensionBadge();

checkAndCleanupExpiredSessions();

async function checkAndCleanupExpiredSessions() {
    try {
        console.log('[Session Cleanup] Checking for expired sessions...');
        
        const result = await chrome.storage.local.get('firewall_guard_sessions');
        const storage = result.firewall_guard_sessions;
        
        if (!storage || !storage.currentSession) {
            console.log('[Session Cleanup] No current session found');
            return;
        }
        
        const currentSession = storage.currentSession;
        const now = Date.now();
        const sessionAge = now - currentSession.startTime;
        const lastActivity = currentSession.lastActivity || currentSession.startTime;
        const inactiveTime = now - lastActivity;
        
        console.log('[Session Cleanup] Session analysis:', {
            sessionId: currentSession.sessionId,
            sessionAge: sessionAge,
            lastActivity: lastActivity,
            inactiveTime: inactiveTime,
            status: currentSession.status
        });
        
        let shouldCleanup = false;
        let cleanupReason = '';
        
        if (sessionAge > 2 * 60 * 60 * 1000) {
            shouldCleanup = true;
            cleanupReason = 'Session expired (older than 2 hours)';
        }
        
        if (inactiveTime > 30 * 60 * 1000) {
            shouldCleanup = true;
            cleanupReason = 'Session inactive (older than 30 minutes)';
        }
        
        if (currentSession.forced && sessionAge > 5 * 60 * 1000) {
            shouldCleanup = true;
            cleanupReason = 'Forced session expired (5 minutes)';
        }
        
        if (currentSession.windowId) {
            try {
                const windows = await chrome.windows.getAll();
                const sessionWindow = windows.find(w => w.id === currentSession.windowId);
                
                if (!sessionWindow) {
                    shouldCleanup = true;
                    cleanupReason = 'Browser window closed';
                }
            } catch (error) {
                console.warn('[Session Cleanup] Failed to check windows:', error);
                shouldCleanup = true;
                cleanupReason = 'Window check failed';
            }
        }
        
        if (currentSession.tabId && !shouldCleanup) {
            try {
                const tabs = await chrome.tabs.query({});
                const sessionTab = tabs.find(t => t.id === currentSession.tabId);
                
                if (!sessionTab) {
                    shouldCleanup = true;
                    cleanupReason = 'Browser tab closed';
                }
            } catch (error) {
                console.warn('[Session Cleanup] Failed to check tabs:', error);
                shouldCleanup = true;
                cleanupReason = 'Tab check failed';
            }
        }
        
        if (shouldCleanup) {
            console.log(`[Session Cleanup] Cleaning up session: ${cleanupReason}`);
            
            const endedSession = {
                ...currentSession,
                status: 'ended',
                endTime: now,
                cleanupReason: cleanupReason
            };
            
            const updatedStorage = {
                currentSession: null,
                sessionHistory: [endedSession, ...(storage.sessionHistory || [])].slice(0, 10),
                lastUpdated: now,
                version: '1.0'
            };
            
            await chrome.storage.local.set({ 'firewall_guard_sessions': updatedStorage });
            
            console.log('[Session Cleanup] Session moved to history:', endedSession);
            
            await updateExtensionBadge();
            
            chrome.notifications.create({
                type: 'basic',
                iconUrl: chrome.runtime.getURL('icon.png'),
                title: 'Session Ended',
                message: `Session ${currentSession.sessionId} ended: ${cleanupReason}`
            });
            
            safeRuntimeSendMessage({
                action: 'sessionEnded',
                sessionId: currentSession.sessionId,
                reason: cleanupReason
            });
            
        } else {
            console.log('[Session Cleanup] Session is still active');
        }
        
    } catch (error) {
        console.error('[Session Cleanup] Failed to check sessions:', error);
    }
}

chrome.runtime.onInstalled.addListener(() => {
    console.log('[Service Worker] Extension installed/updated');
    initializeAdBlockRules();
    ensureConsoleFirewallPolicy();
    hydrateConsoleAnalysisCacheFromHistory().catch((error) => {
        console.warn('[Console Cache] Install hydration failed:', error.message);
    });
    checkBackendConnection();
    updateLocalEngineSnapshot({ skipHistory: true }).catch((error) => {
        console.warn('[Local Engine] Initial snapshot refresh failed:', error.message);
    });
    ensureRuleVisibilityHistory().catch((error) => {
        console.warn('[Rules] Failed to seed initial visibility history:', error.message);
    });
});

chrome.tabs.onRemoved.addListener(async (tabId, removeInfo) => {
    console.log(`[Tab Cleanup] Tab ${tabId} closed, checking for associated sessions...`);
    console.log(`[Tab Cleanup] Remove info:`, removeInfo);
    
    try {
        const result = await chrome.storage.local.get('firewall_guard_sessions');
        console.log(`[Tab Cleanup] Storage result:`, result);
        const storage = result.firewall_guard_sessions;
        
        if (!storage) {
            console.log(`[Tab Cleanup] No storage found for firewall_guard_sessions`);
            return;
        }
        
        console.log(`[Tab Cleanup] Current session:`, storage.currentSession);
        console.log(`[Tab Cleanup] Looking for tabId ${tabId} in session tabId ${storage.currentSession?.tabId}`);
        
        if (storage && storage.currentSession && storage.currentSession.tabId === tabId) {
            console.log(`[Tab Cleanup] Found session ${storage.currentSession.sessionId} for closed tab ${tabId}`);
            
            const endedSession = {
                ...storage.currentSession,
                status: 'ended',
                endTime: Date.now(),
                cleanupReason: 'Tab closed by user'
            };
            
            const updatedStorage = {
                currentSession: null,
                sessionHistory: [endedSession, ...(storage.sessionHistory || [])].slice(0, 10),
                lastUpdated: Date.now(),
                version: '1.0'
            };
            
            await chrome.storage.local.set({ 'firewall_guard_sessions': updatedStorage });
            
            console.log(`[Tab Cleanup] Session ${storage.currentSession.sessionId} deleted and moved to history`);
            
            await updateExtensionBadge();
            
            safeRuntimeSendMessage({
                action: 'sessionCleanup',
                type: 'tabClosed',
                data: {
                    sessionId: storage.currentSession.sessionId,
                    tabId: tabId,
                    reason: 'Tab closed by user'
                },
                timestamp: Date.now()
            });
        } else {
            console.log(`[Tab Cleanup] No active session found for tab ${tabId}`);
            
            if (storage && storage.currentSession && 
                storage.currentSession.forced && 
                storage.currentSession.tabId === null) {
                
                console.log(`[Tab Cleanup] Found forced session ${storage.currentSession.sessionId}, cleaning up...`);
                
                const endedSession = {
                    ...storage.currentSession,
                    status: 'ended',
                    endTime: Date.now(),
                    cleanupReason: 'Forced session cleaned up on tab close'
                };
                
                const updatedStorage = {
                    currentSession: null,
                    sessionHistory: [endedSession, ...(storage.sessionHistory || [])].slice(0, 10),
                    lastUpdated: Date.now(),
                    version: '1.0'
                };
                
                await chrome.storage.local.set({ 'firewall_guard_sessions': updatedStorage });
                
                console.log(`[Tab Cleanup] Forced session ${storage.currentSession.sessionId} cleaned up`);
                
                await updateExtensionBadge();
                
                safeRuntimeSendMessage({
                    action: 'sessionCleanup',
                    type: 'forcedSessionCleanup',
                    data: {
                        sessionId: storage.currentSession.sessionId,
                        reason: 'Forced session cleaned up on tab close'
                    },
                    timestamp: Date.now()
                });
            }
            
            if (storage && storage.sessionHistory) {
                const historySession = storage.sessionHistory.find(s => s.tabId === tabId);
                if (historySession) {
                    console.log(`[Tab Cleanup] Found tab ${tabId} in session history: ${historySession.sessionId}`);
                }
            }
        }
        
        if (automationSessions.has(tabId)) {
            const session = automationSessions.get(tabId);
            console.log(`[Tab Cleanup] Cleaning up automation session for tab ${tabId}`);
            automationSessions.delete(tabId);
            
            if (pageLogs.has(tabId)) {
                pageLogs.delete(tabId);
            }
            if (downloadMonitor.has(tabId)) {
                downloadMonitor.delete(tabId);
            }
        }
        
    } catch (error) {
        console.error('[Tab Cleanup] Failed to clean up session for closed tab:', error);
    }
});

chrome.windows.onRemoved.addListener(async (windowId) => {
    console.log(`[Window Cleanup] Window ${windowId} closed, checking for associated sessions...`);
    
    try {
        const result = await chrome.storage.local.get('firewall_guard_sessions');
        const storage = result.firewall_guard_sessions;
        
        if (storage && storage.currentSession && storage.currentSession.windowId === windowId) {
            console.log(`[Window Cleanup] Found session ${storage.currentSession.sessionId} for closed window ${windowId}`);
            
            const endedSession = {
                ...storage.currentSession,
                status: 'ended',
                endTime: Date.now(),
                cleanupReason: 'Window closed by user'
            };
            
            const updatedStorage = {
                currentSession: null,
                sessionHistory: [endedSession, ...(storage.sessionHistory || [])].slice(0, 10),
                lastUpdated: Date.now(),
                version: '1.0'
            };
            
            await chrome.storage.local.set({ 'firewall_guard_sessions': updatedStorage });
            
            console.log(`[Window Cleanup] Session ${storage.currentSession.sessionId} deleted and moved to history`);
            
            await updateExtensionBadge();
            
            safeRuntimeSendMessage({
                action: 'sessionCleanup',
                type: 'windowClosed',
                data: {
                    sessionId: storage.currentSession.sessionId,
                    windowId: windowId,
                    reason: 'Window closed by user'
                },
                timestamp: Date.now()
            });
        }
    } catch (error) {
        console.error('[Window Cleanup] Failed to clean up session for closed window:', error);
    }
});

async function forceCleanupAllSessions() {
    console.log('[Force Cleanup] Starting manual cleanup of all sessions...');
    
    try {
        const result = await chrome.storage.local.get('firewall_guard_sessions');
        const storage = result.firewall_guard_sessions;
        
        if (!storage) {
            console.log('[Force Cleanup] No storage found');
            return { success: false, message: 'No storage found' };
        }
        
        console.log('[Force Cleanup] Current sessions:', storage);
        
        if (storage.currentSession) {
            const endedSession = {
                ...storage.currentSession,
                status: 'ended',
                endTime: Date.now(),
                cleanupReason: 'Manual force cleanup'
            };
            
            const updatedStorage = {
                currentSession: null,
                sessionHistory: [endedSession, ...(storage.sessionHistory || [])].slice(0, 10),
                lastUpdated: Date.now(),
                version: '1.0'
            };
            
            await chrome.storage.local.set({ 'firewall_guard_sessions': updatedStorage });
            console.log('[Force Cleanup] All sessions cleared');
            
            await updateExtensionBadge();
            
            return { 
                success: true, 
                message: 'All sessions cleared',
                clearedSession: storage.currentSession.sessionId
            };
        } else {
            console.log('[Force Cleanup] No current session to clear');
            return { success: true, message: 'No current session to clear' };
        }
        
    } catch (error) {
        console.error('[Force Cleanup] Error:', error);
        return { success: false, error: error.message };
    }
}

async function debugSessionState() {
    console.log('[Debug] Checking current session state...');
    
    try {
        const result = await chrome.storage.local.get('firewall_guard_sessions');
        console.log('[Debug] Storage result:', result);
        
        const tabs = await chrome.tabs.query({});
        console.log('[Debug] All open tabs:', tabs.map(t => ({ id: t.id, url: t.url, title: t.title })));
        
        const windows = await chrome.windows.getAll();
        console.log('[Debug] All open windows:', windows.map(w => ({ id: w.id, focused: w.focused })));
        
        console.log('[Debug] Automation sessions:', Array.from(automationSessions.entries()));
        
        return {
            storage: result,
            tabs: tabs,
            windows: windows,
            automationSessions: Array.from(automationSessions.entries())
        };
        
    } catch (error) {
        console.error('[Debug] Error:', error);
        return { error: error.message };
    }
}

initializeRuntimeServices().catch((error) => {
    console.warn('[Runtime] Failed to initialize runtime services:', error.message);
});

setInterval(() => {
    if (backendConnected) {
        checkRuleUpdates();
    }
}, 60000);

setInterval(() => {
    syncConsoleFirewallPolicyFromBackend({ skipConnectCheck: true }).catch((error) => {
        console.warn('[Console Firewall] Periodic backend policy sync failed:', error.message);
    });
}, 60000);

setInterval(() => {
    updateLocalEngineSnapshot({ skipHistory: true }).catch((error) => {
        console.warn('[Local Engine] Periodic snapshot refresh failed:', error.message);
    });
}, 60000);

const SEARCH_PAGE_FETCH_MAX_CHARS = 400000;

function isSearchBridgeSenderAllowed(sender) {
    try {
        const senderUrl = new URL(sender && sender.url ? sender.url : '');
        return (
            (senderUrl.hostname === 'localhost' || senderUrl.hostname === '127.0.0.1') &&
            senderUrl.port === '4000'
        );
    } catch (error) {
        return false;
    }
}

async function fetchPageHtmlForSearch(url) {
    let parsedUrl;

    try {
        parsedUrl = new URL(String(url || '').trim());
    } catch (error) {
        throw new Error('Invalid URL');
    }

    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        throw new Error('Only http:// and https:// URLs are supported');
    }

    const response = await fetch(parsedUrl.toString(), {
        method: 'GET',
        redirect: 'follow',
        credentials: 'omit',
        headers: {
            Accept: 'text/html,application/xhtml+xml,text/plain'
        }
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const contentType = String(response.headers.get('content-type') || '');
    if (
        contentType &&
        !/^text\//i.test(contentType) &&
        !/html|xml|json/i.test(contentType)
    ) {
        throw new Error(`Unsupported content type: ${contentType}`);
    }

    const html = await response.text();

    return {
        success: true,
        url: response.url || parsedUrl.toString(),
        html: html.slice(0, SEARCH_PAGE_FETCH_MAX_CHARS),
        contentType: contentType
    };
}

setInterval(checkBackendConnection, 30000);
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('[Background] Message received:', message);
    console.log('[Background] Sender:', sender);

    // Legacy console popup API compatibility
    if (message.type === 'GET_CONSOLE_COMMANDS') {
        chrome.storage.local.get(['ai_commands'], (result) => {
            sendResponse({ commands: result.ai_commands || [] });
        });
        return true;
    }

    if (message.type === 'CLEAR_CONSOLE_COMMANDS') {
        chrome.storage.local.set({
            'ai_commands': [],
            [AI_RESPONSE_HISTORY_KEY]: [],
            [CONSOLE_ANALYSIS_CACHE_KEY]: {}
        }, () => {
            sendResponse({ status: 'cleared' });
        });
        return true;
    }

    if (message.action === 'ensureMainWorldConsoleBridge') {
        const tabId = sender && sender.tab ? sender.tab.id : null;

        if (!tabId) {
            sendResponse({ success: false, error: 'No active tab context for console bridge injection' });
            return false;
        }

        injectMainWorldConsoleBridge(tabId).then(sendResponse);
        return true;
    }

    if (message.action === 'startConsoleCapture') {
        const preferredTabId = message.tabId || (sender && sender.tab ? sender.tab.id : null);
        ensureDebuggerConsoleCapture(preferredTabId).then(sendResponse);
        return true;
    }

    if (message.action === 'searchFetchPageHtml') {
        if (!isSearchBridgeSenderAllowed(sender)) {
            sendResponse({ success: false, error: 'Search bridge request denied' });
            return false;
        }

        fetchPageHtmlForSearch(message.url)
            .then(sendResponse)
            .catch((error) => {
                sendResponse({
                    success: false,
                    error: error && error.message ? error.message : 'Extension fetch failed'
                });
            });
        return true;
    }
    
    // Handle special debug/cleanup actions first
    if (message.action === 'forceCleanupSessions') {
        forceCleanupAllSessions().then(result => {
            sendResponse(result);
        });
        return true; // Keep message channel open for async response
    }

    if (message.action === 'forceCreateSession') {
        forceCreateSessionForActiveTab().then(result => {
            sendResponse(result);
        });
        return true;
    }
    
    if (message.action === 'debugSessionState') {
        debugSessionState().then(result => {
            sendResponse(result);
        });
        return true; // Keep message channel open for async response
    }

    if (message.action === 'openBrowserControl') {
        const controlUrl = message.tab
            ? `${chrome.runtime.getURL('browser_control.html')}?tab=${encodeURIComponent(message.tab)}`
            : chrome.runtime.getURL('browser_control.html');

        chrome.tabs.create({ url: controlUrl, active: true });
        sendResponse({ success: true });
        return true;
    }

    if (message.action === 'openAITestingPanel') {
        chrome.tabs.create({ url: chrome.runtime.getURL('ai_testing_panel_working.html') });
        sendResponse({ success: true });
        return true;
    }

    if (message.action === 'openConsoleCommands') {
        chrome.tabs.create({ url: chrome.runtime.getURL('console_popup.html') });
        sendResponse({ success: true });
        return true;
    }

    if (message.action === 'openSandboxTest') {
        chrome.tabs.create({ url: chrome.runtime.getURL('sandbox_native.html') });
        sendResponse({ success: true });
        return true;
    }
    
    // Handle console command analysis requests
    if (message.action === 'analyzeCommand') {
        processCapturedConsoleCommand(message.commandData)
            .then((result) => {
                if (result.success) {
                    sendResponse({ success: true, result: result.result || null, skipped: result.skipped || false });
                } else {
                    sendResponse({ success: false, error: result.error });
                }
            });
        return true; // Keep message channel open for async response
    }
    
    // Handle console command captured from content script
    if (message.action === 'consoleCommandCaptured') {
        processCapturedConsoleCommand({
            ...message.command,
            tabId: sender && sender.tab ? sender.tab.id : message.command.tabId
        }).then((result) => {
            if (result.success) {
                sendResponse({ success: true, result: result.result || null, skipped: result.skipped || false });
            } else {
                sendResponse({ success: false, error: result.error });
            }
        });
        return true; // Keep message channel open for async response
    }
    
    handleAutomationMessage(message, sender, sendResponse).catch(error => {
        console.error('[Background] Error handling message:', error);
        sendResponse({ error: error.message });
    });
    
    if (message.action === 'sessionCreated' || message.action === 'sessionUpdated') {
        updateExtensionBadge();
    }
    
    return true;
});

chrome.runtime.onConnectExternal.addListener((port) => {
    console.log('[Automation] External connection from:', port.sender);
    console.log('[Automation] External connection details:', {
        id: port.sender.id,
        url: port.sender.url,
        name: port.name
    });
    
    externalPorts.set(port.sender.id, port);
    
    port.onMessage.addListener(async (message) => {
        try {
            let response;
            switch (message.action) {
                case 'launchAutomatedBrowser':
                    response = getActiveSessions();
                    break;
                case 'ping':
                    response = buildPingPayload();
                    break;
                default:
                    response = { error: 'Unknown action' };
            }
            port.postMessage(response);
        } catch (error) {
            console.error('[Automation] External port message error:', error);
            port.postMessage({ error: error.message });
        }
    });
    
    port.onDisconnect.addListener(() => {
        console.log('[Automation] External port disconnected:', port.sender.id);
        externalPorts.delete(port.sender.id);
    });
});

chrome.runtime.onConnect.addListener((port) => {
    console.log('[Automation] Internal connection from:', port.sender);
    console.log('[Automation] Internal connection details:', {
        id: port.sender.id,
        url: port.sender.url,
        name: port.name
    });
    
    externalPorts.set('internal_' + port.name, port);
    
    port.onMessage.addListener(async (message) => {
        try {
            console.log('[Automation] Received internal port message:', message);
            let response;
            switch (message.action) {
                case 'ping':
                    response = buildPingPayload();
                    break;
                case 'toggleServers':
                    response = toggleServers();
                    break;
                case 'getServerStatus':
                    response = { enabled: serversEnabled, connected: backendConnected };
                    break;
                default:
                    response = { error: 'Unknown action' };
            }
            port.postMessage(response);
        } catch (error) {
            console.error('[Automation] Internal port message error:', error);
            port.postMessage({ error: error.message });
        }
    });
    
    port.onDisconnect.addListener(() => {
        console.log('[Automation] Internal port disconnected:', port.name);
        externalPorts.delete('internal_' + port.name);
    });
});

async function handleAutomationMessage(message, sender, sendResponse) {
    try {
        switch (message.action) {
            case 'ping':
                sendResponse(buildPingPayload());
                break;
            case 'getConsoleAnalysisCacheStats':
                sendResponse(await getConsoleAnalysisCacheStats());
                break;
            case 'getSiteInfo':
                chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                    if (tabs[0]) {
                        sendResponse({
                            success: true,
                            siteInfo: {
                                url: tabs[0].url,
                                title: tabs[0].title,
                                id: tabs[0].id
                            }
                        });
                    } else {
                        sendResponse({ success: false, error: 'No active tab found' });
                    }
                });
                break;
            case 'setupControlledBrowser':
                try {
                    const setupResult = await setupControlledBrowser(message.windowId, message.url);
                    sendResponse({ success: true, ...setupResult });
                } catch (error) {
                    console.error('[Automation] Controlled browser setup error:', error);
                    sendResponse({ success: false, error: error.message });
                }
                break;
            case 'establishControl':
                console.log('[Background] Establishing control for session:', message.sessionId);
                try {
                    const result = await chrome.storage.local.get('firewall_guard_sessions');
                    if (result.firewall_guard_sessions && result.firewall_guard_sessions.currentSession) {
                        const updatedSession = {
                            ...result.firewall_guard_sessions,
                            currentSession: {
                                ...result.firewall_guard_sessions.currentSession,
                                controlled: true,
                                lastActivity: Date.now()
                            }
                        };
                        await chrome.storage.local.set({ 'firewall_guard_sessions': updatedSession });
                        console.log('[Background] Control established for session:', message.sessionId);
                        sendResponse({ success: true });
                    } else {
                        sendResponse({ success: false, error: 'No session found' });
                    }
                } catch (error) {
                    sendResponse({ success: false, error: error.message });
                }
                break;
            case 'navigateTo':
                console.log('[Background] Received navigateTo message:', message);
                console.log('[Background] Session ID:', message.sessionId, 'URL:', message.url);
                
                try {
                    const result = await chrome.storage.local.get('firewall_guard_sessions');
                    const storage = result.firewall_guard_sessions;
                    
                    if (storage && storage.currentSession && storage.currentSession.tabId) {
                        const tabId = storage.currentSession.tabId;
                        console.log('[Background] Attempting direct navigation to tab:', tabId, 'URL:', message.url);
                        
                        try {
                            const tab = await chrome.tabs.get(tabId);
                            console.log('[Background] Tab verified:', tab.id, 'Current URL:', tab.url);
                            
                            await chrome.tabs.update(tabId, { url: message.url });
                            console.log('[Background] Direct navigation completed successfully');
                            
                            const updatedSession = {
                                ...storage,
                                currentSession: {
                                    ...storage.currentSession,
                                    url: message.url,
                                    lastActivity: Date.now()
                                }
                            };
                            await chrome.storage.local.set({ 'firewall_guard_sessions': updatedSession });
                            
                            sendResponse({ success: true, message: 'Navigation completed', tabId: tabId });
                        } catch (tabError) {
                            console.error('[Background] Tab not found or inaccessible:', tabError);
                            console.log('[Background] Trying fallback to current active tab...');
                            
                            try {
                                const [activeTab] = await chrome.tabs.query({active: true, currentWindow: true});
                                if (activeTab) {
                                    console.log('[Background] Using active tab fallback:', activeTab.id, activeTab.url);
                                    await chrome.tabs.update(activeTab.id, { url: message.url });
                                    console.log('[Background] Fallback navigation completed');
                                    
                                    sendResponse({ success: true, message: 'Navigation completed via fallback', tabId: activeTab.id });
                                } else {
                                    sendResponse({ success: false, error: 'No active tab found for fallback' });
                                }
                            } catch (fallbackError) {
                                console.error('[Background] Fallback navigation failed:', fallbackError);
                                sendResponse({ success: false, error: `Fallback failed: ${fallbackError.message}` });
                            }
                        }
                    } else {
                        console.log('[Background] No tab ID found in session');
                        sendResponse({ success: false, error: 'No tab ID found in session' });
                    }
                } catch (error) {
                    console.error('[Background] Direct navigation failed:', error);
                    sendResponse({ success: false, error: error.message });
                }
                break;
            case 'clickElement':
                await clickElement(message.sessionId, message.selector);
                sendResponse({ success: true });
                break;
            case 'fillForm':
                await fillForm(message.sessionId, message.formData);
                sendResponse({ success: true });
                break;
            case 'directNavigate':
                console.log('[Background] Received directNavigate request:', message);
                
                try {
                    const [activeTab] = await chrome.tabs.query({active: true, currentWindow: true});
                    
                    if (activeTab && activeTab[0]) {
                        const tabId = activeTab[0].id;
                        const targetUrl = message.url;
                        
                        console.log('[Background] Direct navigating active tab:', tabId);
                        console.log('[Background] Target URL:', targetUrl);
                        console.log('[Background] Current tab URL:', activeTab[0].url);
                        
                        if (!targetUrl || typeof targetUrl !== 'string') {
                            throw new Error('Invalid URL provided');
                        }
                        
                        let finalUrl = targetUrl;
                        if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
                            finalUrl = 'https://' + targetUrl;
                        }
                        
                        console.log('[Background] Final URL to navigate to:', finalUrl);
                        
                        await chrome.tabs.update(tabId, { url: finalUrl });
                        console.log('[Background] Direct navigation completed successfully');
                        
                        sendResponse({ success: true, message: 'Direct navigation completed', tabId: tabId, finalUrl: finalUrl });
                    } else {
                        console.log('[Background] No active tab found for direct navigation');
                        sendResponse({ success: false, error: 'No active tab found' });
                    }
                } catch (error) {
                    console.error('[Background] Direct navigation failed:', error);
                    sendResponse({ success: false, error: `Direct navigation failed: ${error.message}` });
                }
                break;
            case 'executeScript':
                const result = await executeScript(message.sessionId, message.script);
                sendResponse({ success: true, result: result });
                break;
            case 'takeScreenshot':
                const screenshot = await takeScreenshot(message.sessionId);
                sendResponse({ success: true, screenshot: screenshot });
                break;
            case 'getPageContent':
                const content = await getPageContent(message.sessionId);
                sendResponse({ success: true, content: content });
                break;
            case 'getBrowserInfo':
                const info = await getBrowserInfo(message.sessionId);
                sendResponse({ success: true, info: info });
                break;
            case 'getEndpointConfig':
                await endpointConfigReady;
                await syncBundledTunnelConfig();
                const endpointConfig = getCurrentEndpointConfig();
                sendResponse({
                    success: true,
                    config: endpointConfig,
                    mode: getEndpointMode(endpointConfig)
                });
                break;
            case 'setEndpointConfig':
                try {
                    validateEndpointConfigInput(message.config || {});
                    const savedConfig = await applyEndpointConfig(message.config || {}, { persist: true });
                    backendConnected = false;
                    const connected = await checkBackendConnection();
                    const localEngineSnapshot = await updateLocalEngineSnapshot({ skipHistory: true });

                    sendResponse({
                        success: true,
                        config: savedConfig,
                        mode: getEndpointMode(savedConfig),
                        connected: connected,
                        localEngineAvailable: localEngineSnapshot.available
                    });
                } catch (error) {
                    sendResponse({ success: false, error: error.message });
                }
                break;
            case 'resetEndpointConfig':
                try {
                    const bundledConfig = await loadBundledTunnelConfig();
                    const resetConfig = await applyEndpointConfig(bundledConfig || DEFAULT_ENDPOINT_CONFIG, { persist: true });
                    backendConnected = false;
                    const connected = await checkBackendConnection();
                    const localEngineSnapshot = await updateLocalEngineSnapshot({ skipHistory: true });

                    sendResponse({
                        success: true,
                        config: resetConfig,
                        mode: getEndpointMode(resetConfig),
                        connected: connected,
                        localEngineAvailable: localEngineSnapshot.available
                    });
                } catch (error) {
                    sendResponse({ success: false, error: error.message });
                }
                break;
            case 'getBackendStatus':
                await endpointConfigReady;
                const currentEndpointConfig = getCurrentEndpointConfig();
                sendResponse({
                    connected: backendConnected,
                    authRequired: backendAuthRequired,
                    config: currentEndpointConfig,
                    mode: getEndpointMode(currentEndpointConfig),
                    configRequired: !hasConfiguredEndpointConfig(currentEndpointConfig)
                });
                break;
            case 'checkUpdate':
                try {
                    const updateResult = await checkRuleUpdates({ forceDownload: true });
                    sendResponse({
                        success: true,
                        message: updateResult.updated
                            ? `Firewall rules updated to v${updateResult.version || currentRulesVersion}`
                            : 'Firewall rule check completed',
                        ...updateResult
                    });
                } catch (error) {
                    sendResponse({ success: false, error: error.message });
                }
                break;
            case 'updateConsolePolicy':
                try {
                    const incoming = message.policy;
                    if (!incoming || typeof incoming !== 'object') {
                        sendResponse({ success: false, error: 'No policy provided' });
                        break;
                    }
                    const result = await queueConsoleFirewallPolicyMutation(async (currentPolicy) => {
                        const nextPolicy = normalizeConsoleFirewallPolicy({
                            ...currentPolicy,
                            ...incoming,
                            rules: Array.isArray(incoming.rules) ? incoming.rules : currentPolicy.rules,
                            updatedAt: new Date().toISOString(),
                            version: Date.now()
                        });

                        await chrome.storage.local.set({ 'console_firewall_policy': nextPolicy });
                        return {
                            previousPolicy: currentPolicy,
                            policy: nextPolicy
                        };
                    });

                    await recordRuleChange('local', 'console-policy', result.previousPolicy, result.policy, {
                        source: 'user_edit',
                        note: 'Console firewall policy updated from AI Testing Panel'
                    });
                    saveConsoleFirewallPolicyToBackend(result.policy).catch(() => {});
                    sendResponse({ success: true, policy: result.policy });
                } catch (error) {
                    sendResponse({ success: false, error: error.message });
                }
                break;
            case 'refreshRuleSnapshots':
                try {
                    if (message.refreshRemote) {
                        await checkRuleUpdates({ forceDownload: true });
                    }

                    await hydrateConsoleFirewallRulesFromHistory();
                    const localEngine = await updateLocalEngineSnapshot({ skipHistory: true });
                    await ensureRuleVisibilityHistory();
                    const storage = await chrome.storage.local.get([
                        'firewall_rules',
                        'rules_version',
                        'console_firewall_policy',
                        RULE_CHANGE_HISTORY_KEY,
                        LOCAL_ENGINE_RULES_KEY,
                        LOCAL_ENGINE_STATUS_KEY
                    ]);

                    sendResponse({
                        success: true,
                        globalRules: storage.firewall_rules || {},
                        globalVersion: storage.rules_version || currentRulesVersion,
                        localPolicy: storage.console_firewall_policy || {},
                        localEngineRules: storage[LOCAL_ENGINE_RULES_KEY] || {},
                        localEngineStatus: storage[LOCAL_ENGINE_STATUS_KEY] || localEngine.status || {},
                        history: Array.isArray(storage[RULE_CHANGE_HISTORY_KEY]) ? storage[RULE_CHANGE_HISTORY_KEY] : []
                    });
                } catch (error) {
                    sendResponse({ success: false, error: error.message });
                }
                break;
            case 'updateConsolePolicy':
                try {
                    const storage = await chrome.storage.local.get(['console_firewall_policy']);
                    const current = normalizeConsoleFirewallPolicy(storage.console_firewall_policy);
                    const incoming = message.policy;

                    if (!incoming || typeof incoming !== 'object') {
                        sendResponse({ success: false, error: 'No policy provided' });
                        break;
                    }

                    const previousPolicy = JSON.parse(JSON.stringify(current));
                    const nextPolicy = normalizeConsoleFirewallPolicy({
                        ...current,
                        ...incoming,
                        rules: Array.isArray(incoming.rules) ? incoming.rules : current.rules,
                        version: (current.version || 0) + 1,
                        updatedAt: new Date().toISOString()
                    });

                    await chrome.storage.local.set({ 'console_firewall_policy': nextPolicy });

                    await recordRuleChange('local', 'console-policy', previousPolicy, nextPolicy, {
                        source: 'ui_edit',
                        note: 'Console firewall policy updated from UI'
                    });

                    saveConsoleFirewallPolicyToBackend(nextPolicy).catch((err) => {
                        console.warn('[Console Firewall] Background sync failed:', err.message);
                    });

                    sendResponse({ success: true, policy: nextPolicy });
                } catch (error) {
                    sendResponse({ success: false, error: error.message });
                }
                break;
            case 'setBackendStatus':
                backendConnected = message.connected;
                console.log('[Backend] Status updated:', backendConnected ? 'Connected' : 'Disconnected');
                sendResponse({ success: true, connected: backendConnected });
                break;
            case 'launchAutomatedBrowser':
                try {
                    const launchResult = await launchAutomatedBrowser(message.config);
                    sendResponse({ success: true, ...launchResult });
                } catch (error) {
                    console.error('[Automation] Launch error:', error);
                    sendResponse({ success: false, error: error.message });
                }
                break;
            case 'getActiveSessions':
                sendResponse({ success: true, sessions: getActiveSessions() });
                break;
            case 'startAutomation':
                const startResult = await startBrowserAutomation(message.config);
                sendResponse({ success: true, sessionId: startResult.sessionId });
                break;
            case 'stopAutomation':
                await stopBrowserAutomation(message.sessionId);
                sendResponse({ success: true });
                break;
            case 'getPageLogs':
                const logs = getPageLogs(message.sessionId);
                sendResponse({ success: true, logs: logs });
                break;
            case 'getDownloadInfo':
                const downloadInfo = getDownloadInfo(message.sessionId);
                sendResponse({ success: true, downloads: downloadInfo });
                break;
            default:
                sendResponse({ success: false, error: 'Unknown action' });
        }
    } catch (error) {
        console.error('[Automation] Message handler error:', error);
        sendResponse({ success: false, error: error.message });
    }
}

async function setupControlledBrowser(windowId, url) {
    try {
        console.log('[Controlled Browser] Setting up automation for window:', windowId);
        
        const tabs = await chrome.tabs.query({ windowId: windowId });
        const tab = tabs[0];
        
        if (!tab) {
            throw new Error('No tab found in controlled browser window');
        }
        
        const sessionId = generateSessionId();
        
        automationSessions.set(sessionId, {
            windowId: windowId,
            tabId: tab.id,
            url: url,
            startTime: Date.now(),
            downloads: [],
            logs: [],
            type: 'controlled_browser',
            status: 'active',
            isControlled: true,
            testSoftwareReady: true
        });
        
        try {
            await chrome.debugger.attach({ tabId: tab.id }, '1.3');
            
            await chrome.debugger.sendCommand({ tabId: tab.id }, 'Runtime.enable');
            await chrome.debugger.sendCommand({ tabId: tab.id }, 'Network.enable');
            await chrome.debugger.sendCommand({ tabId: tab.id }, 'Page.enable');
            await chrome.debugger.sendCommand({ tabId: tab.id }, 'DOM.enable');
            await chrome.debugger.sendCommand({ tabId: tab.id }, 'Input.enable');
            
            console.log(`[Controlled Browser] Debugger attached to tab ${tab.id}`);
        } catch (debuggerError) {
            console.warn('[Controlled Browser] Debugger attachment failed:', debuggerError);
        }
        
        chrome.scripting.executeScript({
            target: { tabId: tab.id },
            files: ['automation_script.js']
        }).catch(error => {
            console.warn('[Controlled Browser] Script injection failed:', error);
        });
        
        setupControlledBrowserMonitoring(sessionId, tab.id);
        
        const readyMessage = {
            action: 'controlledBrowserReady',
            sessionId: sessionId,
            windowId: windowId,
            tabId: tab.id,
            url: url
        };
        
        console.log('[Controlled Browser] Sending ready message:', readyMessage);
        
        externalPorts.forEach((port, portId) => {
            try {
                console.log(`[Controlled Browser] Sending to external port ${portId}:`, readyMessage);
                port.postMessage(readyMessage);
            } catch (error) {
                console.warn(`[Controlled Browser] Failed to send to port ${portId}:`, error);
            }
        });
        
        chrome.runtime.sendMessage(readyMessage, (response) => {
            if (chrome.runtime.lastError) {
            } else {
                console.debug('[Controlled Browser] Control panel notified:', response);
            }
        });
        
        console.log('[Controlled Browser] Ready message sent to all recipients');
        
        try {
            await swSessionStorage.storeCurrentSession({
                sessionId: sessionId,
                windowId: windowId,
                tabId: tab.id,
                url: url,
                startTime: Date.now(),
                status: 'active',
                type: 'controlled_browser',
                controlled: true  // Mark this as a controlled session
            });
            console.log('[Controlled Browser] Session stored in local storage');
            
            await updateExtensionBadge();
        } catch (storageError) {
            console.error('[Controlled Browser] Failed to store session in local storage:', storageError);
        }
        
        console.log(`[Controlled Browser] Setup complete for session ${sessionId}`);
        
        return {
            sessionId: sessionId,
            windowId: windowId,
            tabId: tab.id,
            type: 'controlled_browser',
            status: 'active',
            testSoftwareReady: true
        };
        
    } catch (error) {
        console.error('[Controlled Browser] Setup failed:', error);
        throw error;
    }
}

async function clickElement(sessionId, selector) {
    const session = automationSessions.get(sessionId);
    if (!session) throw new Error('Session not found');
    
    const result = await chrome.scripting.executeScript({
        target: { tabId: session.tabId },
        func: (elementSelector) => {
            const element = document.querySelector(elementSelector);
            if (element) {
                element.click();
                return { success: true, element: elementSelector };
            }
            return { success: false, error: 'Element not found' };
        },
        args: [selector]
    });
    
    addPageLog(sessionId, {
        type: 'click',
        selector: selector,
        timestamp: Date.now(),
        result: result[0].result
    });
    
    return result[0].result;
}

async function fillForm(sessionId, formData) {
    const session = automationSessions.get(sessionId);
    if (!session) throw new Error('Session not found');
    
    const result = await chrome.scripting.executeScript({
        target: { tabId: session.tabId },
        func: (data) => {
            const results = [];
            for (const [selector, value] of Object.entries(data)) {
                const element = document.querySelector(selector);
                if (element) {
                    element.value = value;
                    element.dispatchEvent(new Event('input', { bubbles: true }));
                    results.push({ selector, success: true });
                } else {
                    results.push({ selector, success: false, error: 'Element not found' });
                }
            }
            return results;
        },
        args: [formData]
    });
    
    addPageLog(sessionId, {
        type: 'form_fill',
        formData: formData,
        timestamp: Date.now(),
        result: result[0].result
    });
    
    return result[0].result;
}

async function executeScript(sessionId, script) {
    const session = automationSessions.get(sessionId);
    if (!session) throw new Error('Session not found');
    
    const result = await chrome.scripting.executeScript({
        target: { tabId: session.tabId },
        func: new Function(script)
    });
    
    addPageLog(sessionId, {
        type: 'script_execution',
        script: script.substring(0, 100) + '...',
        timestamp: Date.now(),
        result: result[0].result
    });
    
    return result[0].result;
}

async function takeScreenshot(sessionId) {
    const session = automationSessions.get(sessionId);
    if (!session) throw new Error('Session not found');
    
    try {
        const screenshot = await chrome.tabs.captureVisibleTab(session.windowId, { format: 'png' });
        
        addPageLog(sessionId, {
            type: 'screenshot',
            timestamp: Date.now(),
            success: true
        });
        
        return screenshot;
    } catch (error) {
        addPageLog(sessionId, {
            type: 'screenshot',
            timestamp: Date.now(),
            success: false,
            error: error.message
        });
        throw error;
    }
}

async function getPageContent(sessionId) {
    const session = automationSessions.get(sessionId);
    if (!session) throw new Error('Session not found');
    
    const result = await chrome.scripting.executeScript({
        target: { tabId: session.tabId },
        func: () => {
            return {
                title: document.title,
                url: window.location.href,
                html: document.documentElement.outerHTML,
                text: document.body.innerText
            };
        }
    });
    
    return result[0].result;
}

async function getBrowserInfo(sessionId) {
    const session = automationSessions.get(sessionId);
    if (!session) throw new Error('Session not found');
    
    const tab = await chrome.tabs.get(session.tabId);
    const window = await chrome.windows.get(session.windowId);
    
    return {
        sessionId: sessionId,
        windowId: session.windowId,
        tabId: session.tabId,
        url: tab.url,
        title: tab.title,
        windowState: window.state,
        windowFocused: window.focused,
        sessionAge: Date.now() - session.startTime,
        logsCount: pageLogs.has(sessionId) ? pageLogs.get(sessionId).length : 0,
        downloadsCount: session.downloads.length
    };
}

async function launchAutomatedBrowser(config) {
    try {
        console.log('[Automation] Launching new automated Chrome browser');
        console.log('[Automation] Launch config:', config);
        
        // Ensure config is an object with defaults
        const launchConfig = config || {};
        console.log('[Automation] Normalized config:', launchConfig);
        
        // Create window with better error handling
        const window = await chrome.windows.create({
            url: launchConfig.startUrl || 'https://google.com',
            type: 'normal',
            state: 'normal',
            focused: true,
            incognito: launchConfig.incognito || false,
            width: launchConfig.width || 1920,
            height: launchConfig.height || 1080
        });
        
        console.log(`[Automation] Window created with ID: ${window.id}`);
        
        // Get the tab from the new window
        const tabs = await chrome.tabs.query({ windowId: window.id });
        const tab = tabs[0];
        
        if (!tab) {
            throw new Error('Failed to create tab in new window');
        }
        
        console.log(`[Automation] Tab created with ID: ${tab.id}`);
        
        // Generate session ID
        const sessionId = generateSessionId();
        console.log(`[Automation] Generated session ID: ${sessionId}`);
        
        // Create session record
        automationSessions.set(sessionId, {
            windowId: window.id,
            tabId: tab.id,
            config: launchConfig || {},
            url: launchConfig.startUrl || 'https://google.com',
            startTime: Date.now(),
            downloads: [],
            logs: [],
            type: 'automated_browser',
            status: 'active',
            isTestingBrowser: true
        });
        
        console.log(`[Automation] Session record created for ${sessionId}`);
        
        // Set up monitoring (non-blocking)
        setupSessionMonitoring(sessionId, tab.id);
        
        // Set up automation features (non-blocking, won't fail launch)
        try {
            await setupAutomationFeatures(sessionId, tab.id);
        } catch (error) {
            console.warn(`[Automation] Automation setup failed for ${sessionId}, but continuing:`, error);
        }
        
        // Store session in persistent storage
        const sessionData = {
            currentSession: {
                sessionId: sessionId,
                windowId: window.id,
                tabId: tab.id,
                url: launchConfig.startUrl || 'https://google.com',
                startTime: Date.now(),
                status: 'active',
                lastActivity: Date.now(),
                controlled: true,
                type: 'automated_browser'
            },
            sessionHistory: [],
            lastUpdated: Date.now(),
            version: '1.0'
        };
        
        chrome.storage.local.set({ 'firewall_guard_sessions': sessionData }, () => {
            console.log(`[Automation] Session stored in persistent storage`);
        });
        
        // Show success notification
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icon.png',
            title: '🚀 Automated Browser Launched',
            message: `New Chrome browser ready (Session: ${sessionId})` 
        });
        
        console.log(`[Automation] Browser launched successfully with session ${sessionId}`);
        
        return {
            success: true,
            sessionId: sessionId,
            windowId: window.id,
            tabId: tab.id,
            url: launchConfig.startUrl || 'https://google.com'
        };
        
    } catch (error) {
        console.error('[Automation] Failed to launch automated browser:', error);
        
        // Show error notification
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icon.png',
            title: '❌ Browser Launch Failed',
            message: `Error: ${error.message}` 
        });
        
        throw error;
    }
}

async function setupSessionMonitoring(sessionId, tabId) {
    console.log(`[Controlled Browser] Setting up monitoring for session ${sessionId}`);
    
    const navigationListener = (details) => {
        if (details.tabId === tabId && details.frameId === 0) {
            addPageLog(sessionId, {
                type: 'navigation',
                url: details.url,
                timestamp: Date.now(),
                sessionId: sessionId
            });
            
            chrome.runtime.sendMessage({
                action: 'controlledBrowserNavigated',
                sessionId: sessionId,
                url: details.url
            }, (response) => {
                if (chrome.runtime.lastError) {
                }
            });
        }
    };
    
    chrome.webNavigation.onBeforeNavigate.addListener(navigationListener);
    chrome.webNavigation.onCompleted.addListener(navigationListener);
    
    const requestListener = (details) => {
        if (details.tabId === tabId) {
            const adBlockResult = blockAds(details);
            
            addPageLog(sessionId, {
                type: 'network_request',
                url: details.url,
                method: details.method,
                timestamp: Date.now(),
                blocked: adBlockResult.blocked,
                blockReason: adBlockResult.reason,
                sessionId: sessionId
            });
            
            if (details.type === 'main_frame' || adBlockResult.blocked) {
                chrome.runtime.sendMessage({
                    action: 'controlledBrowserRequest',
                    sessionId: sessionId,
                    url: details.url,
                    blocked: adBlockResult.blocked,
                    blockReason: adBlockResult.reason
                }, (response) => {
                    if (chrome.runtime.lastError) {
                    }
                });
            }
        }
    };
    
    chrome.webRequest.onBeforeRequest.addListener(
        requestListener,
        { urls: ['<all_urls>'], tabId: tabId }
    );
    
    downloadMonitor.set(sessionId, { 
        navigationListener, 
        requestListener,
        type: 'controlled_browser'
    });
}

function setupAutomationFeatures(sessionId, tabId) {
    console.log(`[Automation] Setting up automation features for session ${sessionId}, tab ${tabId}`);
    
    const session = automationSessions.get(sessionId);
    if (!session) {
        console.error(`[Automation] Session ${sessionId} not found for automation setup`);
        return;
    }
    
    // Inject automation script with better error handling
    chrome.scripting.executeScript({
        target: { tabId: tabId },
        files: ['automation_script.js']
    }).then(() => {
        console.log(`[Automation] Automation script injected successfully for session ${sessionId}`);
    }).catch(error => {
        console.error(`[Automation] Script injection failed for session ${sessionId}:`, error);
        // Don't fail the entire launch if script injection fails
    });
    
    // Set up debugger for advanced features
    chrome.debugger.attach({ tabId: tabId }, '1.3').then(() => {
        console.log(`[Automation] Debugger attached for session ${sessionId}`);
        
        // Apply debugger-based features
        applyDebuggerFeatures(sessionId, tabId, session.config);
        
    }).catch(error => {
        console.warn(`[Automation] Failed to attach debugger for session ${sessionId}:`, error);
        // Continue without debugger features
    });
    
    if (session.config.blockAds !== false) {
        console.log(`[Automation] Ad blocking enabled for session ${sessionId}`);
    }
    
    console.log(`[Automation] Basic setup completed for session ${sessionId}`);
}

function applyDebuggerFeatures(sessionId, tabId, config) {
    console.log(`[Automation] Applying debugger features for session ${sessionId}`);
    
    if (config.userAgent) {
        chrome.debugger.sendCommand({ tabId: tabId }, 'Network.setUserAgentOverride', {
            userAgent: config.userAgent
        }).catch(error => {
            console.warn(`[Automation] Failed to set user agent for session ${sessionId}:`, error);
        });
    }
    
    if (config.viewport) {
        chrome.debugger.sendCommand({ tabId: tabId }, 'Page.setDeviceMetricsOverride', {
            width: config.viewport.width || 1920,
            height: config.viewport.height || 1080,
            deviceScaleFactor: 1,
            mobile: false
        }).catch(error => {
            console.warn(`[Automation] Failed to set viewport for session ${sessionId}:`, error);
        });
    }
    
    const blockedUrls = [];
    if (config.disableImages) {
        blockedUrls.push('*.jpg*', '*.jpeg*', '*.png*', '*.gif*', '*.webp*', '*.svg*');
    }
    if (config.disableCss) {
        blockedUrls.push('*.css*');
    }

    if (blockedUrls.length) {
        chrome.debugger.sendCommand({ tabId: tabId }, 'Network.setBlockedURLs', {
            urls: blockedUrls
        }).catch(error => {
            console.warn(`[Automation] Failed to update blocked URL rules for session ${sessionId}:`, error);
        });
    }
    
    if (config.disableJavaScript) {
        chrome.debugger.sendCommand({ tabId: tabId }, 'Page.setJavaScriptEnabled', {
            enabled: false
        }).catch(error => {
            console.warn(`[Automation] Failed to disable JavaScript for session ${sessionId}:`, error);
        });
    }
    
    console.log(`[Automation] Debugger features applied for session ${sessionId}`);
}

function getActiveSessions() {
    const sessions = [];
    automationSessions.forEach((session, sessionId) => {
        sessions.push({
            sessionId: sessionId,
            windowId: session.windowId,
            tabId: session.tabId,
            type: session.type || 'automation',
            status: session.status || 'active',
            startTime: session.startTime,
            config: session.config,
            downloads: session.downloads || [],
            logs: session.logs || []
        });
    });
    return sessions;
}

async function startBrowserAutomation(config) {
    const sessionId = generateSessionId();
    
    const tab = await chrome.tabs.create({
        url: config.startUrl || 'about:blank',
        active: false
    });
    
    automationSessions.set(sessionId, {
        tabId: tab.id,
        config: config,
        startTime: Date.now(),
        downloads: [],
        logs: []
    });
    
    await chrome.debugger.attach({ tabId: tab.id }, '1.3');
    
    await chrome.debugger.sendCommand({ tabId: tab.id }, 'Runtime.enable');
    await chrome.debugger.sendCommand({ tabId: tab.id }, 'Network.enable');
    await chrome.debugger.sendCommand({ tabId: tab.id }, 'Page.enable');
    
    setupSessionMonitoring(sessionId, tab.id);
    
    console.log(`[Automation] Started session ${sessionId} for tab ${tab.id}`);
    
    return { sessionId, tabId: tab.id };
}

async function stopBrowserAutomation(sessionId) {
    const session = automationSessions.get(sessionId);
    if (!session) {
        throw new Error('Session not found');
    }
    
    try {
        await chrome.debugger.detach({ tabId: session.tabId });
    } catch (e) {
        console.warn('Failed to detach debugger:', e);
    }
    
    if (session.config.closeTabOnStop) {
        await chrome.tabs.remove(session.tabId);
    }
    
    automationSessions.delete(sessionId);
    downloadMonitor.delete(sessionId);
    pageLogs.delete(sessionId);
    
    console.log(`[Automation] Stopped session ${sessionId}`);
}

async function navigateToUrlUniversal(sessionId, url) {
    console.log('[Navigation] Universal navigate called:', sessionId, url);
    
    try {
        const result = await chrome.storage.local.get('firewall_guard_sessions');
        const storage = result.firewall_guard_sessions;
        
        console.log('[Navigation] Storage result:', storage);
        
        if (storage && storage.currentSession && storage.currentSession.sessionId === sessionId) {
            const session = storage.currentSession;
            
            console.log('[Navigation] Found matching session:', session);
            
            if (session.tabId) {
                console.log('[Navigation] Found session in storage, navigating tab:', session.tabId);

                const safetyCheck = await checkUrlSafety(url);
                if (!safetyCheck.safe) {
                    console.warn('[Navigation] URL blocked:', safetyCheck.reason);
                    return;
                }
                
                console.log('[Navigation] Executing chrome.tabs.update for tab:', session.tabId, 'URL:', url);
                await chrome.tabs.update(session.tabId, { url: url });
                console.log('[Navigation] Navigation successful for tab:', session.tabId);
                
                const updatedSession = {
                    ...storage,
                    currentSession: {
                        ...session,
                        url: url,
                        lastActivity: Date.now()
                    }
                };
                await chrome.storage.local.set({ 'firewall_guard_sessions': updatedSession });
                
                return;
            } else {
                console.log('[Navigation] Session has no tabId, cannot navigate');
            }
        }
        
        const automationSession = automationSessions.get(sessionId);
        if (automationSession && automationSession.tabId) {
            console.log('[Navigation] Found automation session, navigating tab:', automationSession.tabId);

            const safetyCheck = await checkUrlSafety(url);
            if (!safetyCheck.safe) {
                console.warn('[Navigation] URL blocked:', safetyCheck.reason);
                return;
            }
            
            await chrome.tabs.update(automationSession.tabId, { url: url });
            console.log('[Navigation] Automation navigation successful');
            return;
        }
        
        console.log('[Navigation] Session not found or no tab ID:', sessionId);
        throw new Error(`Session not found or no tab ID: ${sessionId}`);
        
    } catch (error) {
        console.error('[Navigation] Navigation failed:', error);
        throw error;
    }
}

async function navigateToUrl(sessionId, url) {
    const session = automationSessions.get(sessionId);
    if (!session) {
        throw new Error('Session not found');
    }

    const safetyCheck = await checkUrlSafety(url);
    if (!safetyCheck.safe) {
        throw new Error(`URL blocked: ${safetyCheck.reason}`);
    }
    
    await chrome.tabs.update(session.tabId, { url: url });
    
    await waitForPageLoad(session.tabId);
    
    addPageLog(sessionId, {
        type: 'navigation',
        url: url,
        timestamp: Date.now(),
        backendConnected: backendConnected
    });
}

async function checkUrlSafety(url) {
    try {
        const localResponse = await fetchWithRetry(`${LOCAL_ENGINE}/check_url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        if (!localResponse.ok) {
            throw new Error(`Local engine check failed: ${localResponse.status}`);
        }

        const localResult = await localResponse.json();

        if (localResult.status === 'blocked') {
            return { safe: false, reason: localResult.reason, source: 'local' };
        }

        if (localResult.status === 'warning') {
            return {
                safe: true,
                reason: localResult.reason || 'Suspicious pattern detected',
                risk: localResult.risk || 'medium',
                source: 'local'
            };
        }

        return {
            safe: true,
            reason: localResult.reason || 'Safe according to local engine',
            risk: localResult.risk || 'low',
            source: 'local'
        };
    } catch (error) {
        console.warn('[Safety] Local engine check failed:', error.message);
    }

    return { safe: true, source: 'fallback' };
}

async function waitForPageLoad(tabId) {
    return new Promise((resolve) => {
        const listener = (details) => {
            if (details.tabId === tabId && details.status === 'complete') {
                chrome.webNavigation.onCompleted.removeListener(listener);
                resolve();
            }
        };
        chrome.webNavigation.onCompleted.addListener(listener);
    });
}

function setupControlledBrowserMonitoring(sessionId, tabId) {
    console.log(`[Controlled Browser] Setting up monitoring for session ${sessionId}`);
    
    const navigationListener = (details) => {
        if (details.tabId === tabId && details.frameId === 0) {
            addPageLog(sessionId, {
                type: 'navigation',
                url: details.url,
                timestamp: Date.now(),
                sessionId: sessionId
            });
            
            chrome.runtime.sendMessage({
                action: 'controlledBrowserNavigated',
                sessionId: sessionId,
                url: details.url
            }, (response) => {
                if (chrome.runtime.lastError) {
                }
            });
        }
    };
    
    chrome.webNavigation.onBeforeNavigate.addListener(navigationListener);
    chrome.webNavigation.onCompleted.addListener(navigationListener);
    
    const requestListener = (details) => {
        if (details.tabId === tabId) {
            const adBlockResult = blockAds(details);
            
            addPageLog(sessionId, {
                type: 'network_request',
                url: details.url,
                method: details.method,
                timestamp: Date.now(),
                blocked: adBlockResult.blocked,
                blockReason: adBlockResult.reason,
                sessionId: sessionId
            });
            
            if (details.type === 'main_frame' || adBlockResult.blocked) {
                chrome.runtime.sendMessage({
                    action: 'controlledBrowserRequest',
                    sessionId: sessionId,
                    url: details.url,
                    blocked: adBlockResult.blocked,
                    blockReason: adBlockResult.reason
                }, (response) => {
                    if (chrome.runtime.lastError) {
                    }
                });
            }
        }
    };
    
    chrome.webRequest.onBeforeRequest.addListener(
        requestListener,
        { urls: ['<all_urls>'], tabId: tabId }
    );
    
    downloadMonitor.set(sessionId, { 
        navigationListener, 
        requestListener,
        type: 'controlled_browser'
    });
}

function monitorDownload(sessionId, downloadItem) {
    const session = automationSessions.get(sessionId);
    if (!session) return;
    
    const downloadInfo = {
        id: downloadItem.id,
        url: downloadItem.url,
        filename: downloadItem.filename,
        fileSize: downloadItem.fileSize,
        startTime: downloadItem.startTime,
        state: 'in_progress',
        multiFileDetected: false
    };
    
    if (isMultiFileDownload(downloadItem)) {
        downloadInfo.multiFileDetected = true;
        downloadInfo.warning = 'Multi-file download detected';
    }
    
    session.downloads.push(downloadInfo);
    
    addPageLog(sessionId, {
        type: 'download_started',
        download: downloadInfo,
        timestamp: Date.now()
    });
}

function isMultiFileDownload(downloadItem) {
    const multiFilePatterns = [
        /\.zip$/i,
        /\.rar$/i,
        /\.tar$/i,
        /\.7z$/i,
        /multiple.*files/i,
        /batch.*download/i,
        /download.*all/i
    ];
    
    return multiFilePatterns.some(pattern => pattern.test(downloadItem.url));
}

function updateDownloadStatus(sessionId, delta) {
    const session = automationSessions.get(sessionId);
    if (!session) return;
    
    const download = session.downloads.find(d => d.id === delta.id);
    if (download) {
        if (delta.state) {
            download.state = delta.state.current;
        }
        if (delta.totalBytes) {
            download.fileSize = delta.totalBytes.current;
        }
        
        if (download.state === 'complete') {
            addPageLog(sessionId, {
                type: 'download_completed',
                download: download,
                timestamp: Date.now()
            });
        }
    }
}

function initializeAdBlockRules() {
    const adDomains = [
        'googlesyndication.com',
        'googleadservices.com',
        'googletagmanager.com',
        'doubleclick.net',
        'facebook.com/tr',
        'google-analytics.com',
        'amazon-adsystem.com'
    ];
    
    const adPatterns = [
        '/ads/',
        '/advertising/',
        '/banner',
        '/popup',
        'ad.js',
        'analytics.js'
    ];
    
    adDomains.forEach(domain => adBlockRules.add(domain));
    adPatterns.forEach(pattern => adBlockRules.add(pattern));
}

function blockAds(details) {
    const url = new URL(details.url);
    
    if (adBlockRules.has(url.hostname)) {
        console.log('[AdBlock] Blocked ad domain:', url.hostname);
        return { blocked: true, reason: 'Ad domain' };
    }
    
    for (const pattern of adBlockRules) {
        if (url.pathname.includes(pattern)) {
            console.log('[AdBlock] Blocked ad pattern:', pattern);
            return { blocked: true, reason: 'Ad pattern' };
        }
    }
    
    return { blocked: false };
}

function logNetworkRequest(sessionId, details) {
    const session = automationSessions.get(sessionId);
    if (!session) return;
    
    const adBlockResult = blockAds(details);
    
    addPageLog(sessionId, {
        type: 'network_request',
        url: details.url,
        method: details.method,
        timestamp: Date.now(),
        blocked: adBlockResult.blocked,
        blockReason: adBlockResult.reason
    });
}

function addPageLog(sessionId, logEntry) {
    if (!pageLogs.has(sessionId)) {
        pageLogs.set(sessionId, []);
    }
    
    const logs = pageLogs.get(sessionId);
    logs.push(logEntry);
    
    if (logs.length > 1000) {
        logs.splice(0, logs.length - 1000);
    }
}

function getPageLogs(sessionId) {
    return pageLogs.get(sessionId) || [];
}

function getDownloadInfo(sessionId) {
    const session = automationSessions.get(sessionId);
    return session ? session.downloads : [];
}

function generateSessionId() {
    return 'auto_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

async function checkBackendConnection() {
    try {
        await syncBundledTunnelConfig();
        if (!serversEnabled) {
            console.log('[Backend] Servers are disabled, skipping connection check');
            backendConnected = false;
            backendAuthRequired = false;
            return false;
        }

        if (!hasConfiguredEndpointConfig(getCurrentEndpointConfig())) {
            backendConnected = false;
            backendAuthRequired = false;
            console.log('[Backend] Dev Tunnel endpoints are not configured yet.');
            return false;
        }
        
        console.log('[Backend] Checking backend connection...');
        
        const response = await fetchTunnelAware(`${API_BASE}/status`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' }
        });
        
        if (response.ok) {
            const data = await response.json();
            backendAuthRequired = false;
            if (data && data.rules_version) {
                currentRulesVersion = data.rules_version;
            }
            if (!backendConnected) {
                backendConnected = true;
                console.log('[Backend] Connected successfully:', data);
                chrome.notifications.create({
                    type: 'basic',
                    iconUrl: 'icon.png',
                    title: '🔗 Backend Connected',
                    message: `Firewall backend v${data.version} is online`
                });
            }
            return true;
        } else {
            throw new Error(`HTTP ${response.status}`);
        }
    } catch (error) {
        backendAuthRequired = /401/.test(error.message);
        if (backendConnected) {
            backendConnected = false;
            console.log('[Backend] Connection lost, working in offline mode:', error.message);
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icon.png',
                title: backendAuthRequired ? 'Tunnel Login Required' : 'Backend Disconnected',
                message: backendAuthRequired
                    ? 'Sign in to the Dev Tunnel in a regular browser tab, then reload the extension'
                    : 'Working in offline mode - backend unavailable',
                title: '⚠️ Backend Disconnected',
                message: 'Working in offline mode - backend unavailable',
                title: backendAuthRequired ? 'Tunnel Login Required' : 'Backend Disconnected',
                message: backendAuthRequired
                    ? 'Sign in to the Dev Tunnel in a regular browser tab, then reload the extension'
                    : 'Working in offline mode - backend unavailable'
            });
        } else {
            console.log('[Backend] Initial connection failed:', error.message);
        }
        return false;
    }
}

async function forceCreateSessionForActiveTab() {
    try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        const activeTab = tabs && tabs[0] ? tabs[0] : null;

        if (!activeTab) {
            return { success: false, error: 'No active tab found' };
        }

        const sessionId = generateSessionId();
        const stored = await swSessionStorage.storeCurrentSession({
            sessionId: sessionId,
            windowId: activeTab.windowId,
            tabId: activeTab.id,
            url: activeTab.url || 'about:blank',
            startTime: Date.now(),
            status: 'active',
            type: 'manual_session',
            controlled: false,
            forced: true
        });

        if (!stored) {
            return { success: false, error: 'Failed to store forced session' };
        }

        await updateExtensionBadge();

        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icon.png',
            title: 'Manual Session Created',
            message: `Session ${sessionId} attached to the current tab`
        });

        return {
            success: true,
            sessionId: sessionId,
            tabId: activeTab.id,
            windowId: activeTab.windowId
        };
    } catch (error) {
        console.error('[Force Session] Failed to create forced session:', error);
        return { success: false, error: error.message };
    }
}

async function fetchWithRetry(url, options = {}, retries = 3) {
    for (let i = 0; i < retries; i++) {
        try {
            const response = await fetchTunnelAware(url, options);
            return response;
        } catch (error) {
            console.warn(`[Fetch] Attempt ${i + 1} failed:`, error.message);
            if (i === retries - 1) throw error;
            await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
        }
    }
}

async function checkRuleUpdates(options = {}) {
    const forceDownload = Boolean(options.forceDownload);

    if (!backendConnected) {
        const connected = await checkBackendConnection();
        if (!connected) {
            console.log('[Rules] Backend not connected, skipping update check');
            return { checked: false, updated: false, reason: 'backend_disconnected' };
        }
    }
    
    try {
        if (forceDownload) {
            const updateResult = await downloadAndUpdateRules();
            return {
                checked: true,
                forced: true,
                updated: Boolean(updateResult.updated),
                ...updateResult
            };
        }

        const storedRules = await chrome.storage.local.get(['firewall_rules']);
        const hasStoredRules = hasRuleContent(storedRules.firewall_rules);
        const response = await fetchTunnelAware(`${API_BASE}/rules/check-update`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ version: currentRulesVersion })
        });

        if (!response.ok) {
            throw new Error(`Rule check failed: HTTP ${response.status}`);
        }

        const data = await response.json();
        const updateAvailable = responseIndicatesRuleUpdate(data, currentRulesVersion, hasStoredRules);
        const serverVersion = extractServerRuleVersion(data);

        if (updateAvailable) {
            console.log(`[Firewall] New rules available or snapshot missing. Server version: ${serverVersion}`);
            const updateResult = await downloadAndUpdateRules();
            return {
                checked: true,
                updated: Boolean(updateResult.updated),
                serverVersion: serverVersion,
                ...updateResult
            };
        }

        const consolePolicyResult = await syncConsoleFirewallPolicyFromBackend({ skipConnectCheck: true });

        return {
            checked: true,
            updated: Boolean(consolePolicyResult.updated),
            serverVersion: serverVersion || currentRulesVersion,
            consolePolicyUpdated: Boolean(consolePolicyResult.updated),
            consolePolicyVersion: consolePolicyResult.version || null
        };
    } catch (e) {
        console.warn('[Rules] Update check failed, attempting direct snapshot sync:', e.message);
        const fallbackResult = await downloadAndUpdateRules();

        if (fallbackResult.updated) {
            return {
                checked: true,
                updated: true,
                fallback: true,
                ...fallbackResult
            };
        }

        return { checked: false, updated: false, error: fallbackResult.error || e.message };
    }
}

async function downloadAndUpdateRules() {
    if (!backendConnected) {
        const connected = await checkBackendConnection();
        if (!connected) {
            console.log('[Rules] Backend not connected, skipping download');
            return { updated: false, reason: 'backend_disconnected' };
        }
    }
    
    try {
        const storedRules = await chrome.storage.local.get(['firewall_rules']);
        const previousRules = storedRules.firewall_rules || {};
        const snapshot = await fetchBackendRulesSnapshot();

        if (!snapshot.success || !snapshot.rules) {
            throw new Error(snapshot.error || 'No rules received from backend');
        }

        const nextRules = snapshot.rules;
        const nextVersion = nextRules.version || currentRulesVersion || 1;

        await chrome.storage.local.set({
            'firewall_rules': nextRules,
            'rules_version': nextVersion
        });

        await recordRuleChange('global', 'server-rules', previousRules, nextRules, {
            source: 'backend_sync',
            note: 'Global firewall rules updated from backend'
        });

        currentRulesVersion = nextVersion;
        console.log(`[Firewall] Rules updated to v${currentRulesVersion}`);

        await updateLocalEngine(nextRules);
        let consolePolicyResult = { updated: false, version: null };

        try {
            consolePolicyResult = await syncConsoleFirewallPolicyFromBackend({ skipConnectCheck: true });
        } catch (policyError) {
            console.warn('[Rules] Console firewall policy sync failed:', policyError.message);
        }

        return {
            updated: true,
            version: currentRulesVersion,
            consolePolicyUpdated: Boolean(consolePolicyResult.updated),
            consolePolicyVersion: consolePolicyResult.version || null
        };
    } catch (e) {
        console.error('Failed to download rules:', e.message);
        backendConnected = false;
        return { updated: false, error: e.message };
    }
}

async function checkLocalEngineStatus() {
    const snapshot = await updateLocalEngineSnapshot({ skipHistory: true });
    return snapshot.available;
}

async function updateLocalEngine(rules) {
    const beforeSnapshot = await updateLocalEngineSnapshot({ skipHistory: true });

    if (!beforeSnapshot.available) {
        console.log('[Local Engine] Local engine unavailable - skipping update');
        return { updated: false, reason: 'local_engine_unavailable' };
    }

    try {
        const response = await fetchTunnelAware(`${LOCAL_ENGINE}/rules/update`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ rules: rules })
        });

        if (!response.ok) {
            throw new Error(`Local engine update failed: ${response.status}`);
        }

        const result = await response.json();

        if (!result.success) {
            throw new Error(result.error || 'Local engine rejected the rule update');
        }

        const afterSnapshot = await updateLocalEngineSnapshot({
            source: 'backend_sync',
            note: 'Local engine rules synced from global firewall rules'
        });

        console.log('[Local Engine] Rules synchronized with local engine');
        return {
            updated: true,
            available: afterSnapshot.available
        };
    } catch (error) {
        console.error('[Local Engine] Failed to update local engine:', error.message);

        await chrome.storage.local.set({
            [LOCAL_ENGINE_STATUS_KEY]: {
                available: false,
                checkedAt: new Date().toISOString(),
                error: error.message
            }
        });

        return {
            updated: false,
            error: error.message
        };
    }
}

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
    try {
        const tab = await chrome.tabs.get(tabId);
        rememberInspectableTab(tab);
    } catch (error) {
        // Ignore stale activations.
    }
});

chrome.debugger.onEvent.addListener((source, method, params) => {
    if (!source || !source.tabId || !consoleDebuggerTabs.has(source.tabId)) {
        return;
    }

    if (method === 'Runtime.consoleAPICalled') {
        const commandData = buildDebuggerConsoleCommandData(source.tabId, params || {});
        processCapturedConsoleCommand(commandData).catch((error) => {
            console.warn('[Console Capture] Failed to process debugger console event:', error.message);
        });
        return;
    }

    if (method === 'Runtime.exceptionThrown') {
        const commandData = buildDebuggerExceptionCommandData(source.tabId, params || {});
        processCapturedConsoleCommand(commandData).catch((error) => {
            console.warn('[Console Capture] Failed to process debugger exception event:', error.message);
        });
    }
});

chrome.debugger.onDetach.addListener((source) => {
    if (source && source.tabId) {
        consoleDebuggerTabs.delete(source.tabId);
    }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    console.log('[Tab Update] Tab updated:', {
        tabId: tabId,
        url: tab.url,
        title: tab.title,
        status: tab.status,
        changeInfo: changeInfo
    });
    
    if (tab.url && tab.url.startsWith('chrome-extension://')) {
        console.log('[Tab Update] Skipping extension URL:', tab.url);
        return;
    }
    
    if (tab.url && (tab.url.startsWith('chrome://') || tab.url.startsWith('about:'))) {
        console.log('[Tab Update] Skipping internal browser page:', tab.url);
        return;
    }

    rememberInspectableTab(tab);
    
    chrome.storage.local.get('firewall_guard_sessions', (result) => {
        if (result.firewall_guard_sessions && result.firewall_guard_sessions.currentSession) {
            const session = result.firewall_guard_sessions.currentSession;
            
            if (session.tabId === tabId) {
                const updatedSession = {
                    ...result.firewall_guard_sessions,
                    currentSession: {
                        ...session,
                        url: tab.url,
                        title: tab.title,
                        lastActivity: Date.now(),
                        controlled: session.controlled || false
                    }
                };
                
                chrome.storage.local.set({ 'firewall_guard_sessions': updatedSession });
                console.log('[Tab Update] Session updated with new URL:', tab.url, 'Controlled status preserved:', updatedSession.currentSession.controlled);
            }
        }
    });
});

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0) {
        if (details.url && details.url.startsWith('chrome-extension://')) {
            console.log('[Navigation] Skipping extension URL:', details.url);
            return;
        }
        
        if (details.url && (details.url.startsWith('chrome://') || details.url.startsWith('about:'))) {
            console.log('[Navigation] Skipping internal browser page:', details.url);
            return;
        }
        
        console.log('[Navigation] Before navigate:', details.url);
        checkUrlWithLocalEngine(details.url, details.tabId);
    }
});

chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId !== 0 || !isInjectableConsoleBridgeUrl(details.url || '')) {
        return;
    }

    injectMainWorldConsoleBridge(details.tabId).catch((error) => {
        console.warn('[Console Bridge] Navigation injection failed:', error.message);
    });
});

chrome.webNavigation.onCompleted.addListener((details) => {
    if (details.frameId === 0) {
        if (details.url && details.url.startsWith('chrome-extension://')) {
            console.log('[Navigation] Skipping extension URL completion:', details.url);
            return;
        }
        
        if (details.url && (details.url.startsWith('chrome://') || details.url.startsWith('about:'))) {
            console.log('[Navigation] Skipping internal browser page completion:', details.url);
            return;
        }
        
        console.log('[Navigation] Page completed:', details.url);
    }
});

chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        if (details.type === 'main_frame') {
            if (details.url && details.url.startsWith('chrome-extension://')) {
                console.log('[WebRequest] Skipping extension URL request:', details.url);
                return { cancel: false };
            }
            
            if (details.url && (details.url.startsWith('chrome://') || details.url.startsWith('about:'))) {
                console.log('[WebRequest] Skipping internal browser page request:', details.url);
                return { cancel: false };
            }
            
            console.log('[WebRequest] Main frame request:', details.url);
            checkUrlWithLocalEngine(details.url, details.tabId);
        }
    },
    { urls: ['<all_urls>'] }
);

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        if (tab.url.startsWith('chrome-extension://')) {
            console.log('[Tabs] Skipping extension URL:', tab.url);
            return;
        }
        
        if (tab.url.startsWith('chrome://') || tab.url.startsWith('about:')) {
            console.log('[Tabs] Skipping internal browser page:', tab.url);
            return;
        }
        
        console.log('[Tabs] Tab updated:', tab.url);
        chrome.storage.local.set({
            'currentTab': {
                url: tab.url,
                title: tab.title,
                id: tabId
            }
        });
    }
});

chrome.tabs.onActivated.addListener((activeInfo) => {
    chrome.tabs.get(activeInfo.tabId, (tab) => {
        if (tab.url) {
            if (tab.url.startsWith('chrome-extension://')) {
                console.log('[Tabs] Skipping extension URL activation:', tab.url);
                return;
            }
            
            if (tab.url.startsWith('chrome://') || tab.url.startsWith('about:')) {
                console.log('[Tabs] Skipping internal browser page activation:', tab.url);
                return;
            }
            
            console.log('[Tabs] Tab activated:', tab.url);
            chrome.storage.local.set({
                'currentTab': {
                    url: tab.url,
                    title: tab.title,
                    id: tab.id
                }
            });
        }
    });
});

function checkUrlWithLocalEngine(url, tabId) {
    if (!url || !tabId || shouldSkipDuplicateUrlBlock(url, tabId)) {
        return;
    }

    checkUrlSafety(url)
        .then((result) => {
            if (!result.safe) {
                console.warn('[Firewall] Local engine blocked URL:', url, result.reason);
                blockMaliciousPage(url, {
                    reason: result.reason || 'Blocked by local engine',
                    verdict: 'BLOCKED'
                }, tabId);
            }
        })
        .catch((error) => {
            console.warn('[Firewall] Local engine navigation check failed:', error.message);
        });
}

function checkUrlWithServer(url, tabId) {
    console.log('[Background] Checking URL with server:', url);
    
    fetchTunnelAware(`${API_BASE}/check_url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
    })
    .then(response => response.json())
    .then(result => {
        console.log('[Background] Server result:', result);
        if (result.verdict === 'BLOCKED') {
            blockMaliciousPage(url, result, tabId);
        }
    })
    .catch(e => {
        console.log('[Background] Server check failed:', e.message);
    });
}

function blockMaliciousPage(url, result, tabId) {
    const blockedUrl = chrome.runtime.getURL('blocked_page.html') + 
                      '?url=' + encodeURIComponent(url) + 
                      '&reason=' + encodeURIComponent(result.reason || result.verdict || 'Unknown threat');
    
    chrome.tabs.create({
        url: blockedUrl
    }, (newTab) => {
        if (tabId) {
            chrome.tabs.remove(tabId);
        }
    });
    
    chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icon.png',
        title: '🚫 Threat Blocked',
        message: `Blocked: ${url}` 
    });
}
