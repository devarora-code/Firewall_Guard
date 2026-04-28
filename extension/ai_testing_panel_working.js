let commands = [];
let currentPolicy = null;
const CONSOLE_ANALYSIS_CACHE_KEY = 'console_analysis_cache';
const CONSOLE_ANALYSIS_CACHE_FEATURE_VERSION = 'console-cache-v1';
const MAX_CONSOLE_ANALYSIS_CACHE_ENTRIES = 5000;

function loadCommands() {
    chrome.storage.local.get(['ai_commands'], (result) => {
        commands = Array.isArray(result.ai_commands) ? result.ai_commands : [];
        updateStorageStatus('success', `Found ${commands.length} commands`);
        updateCommandCount(commands.length);
        updateRecentCommands(commands);
    });
}

function loadRules(refreshRemote = false) {
    chrome.runtime.sendMessage({ action: 'refreshRuleSnapshots', refreshRemote }, (response) => {
        if (chrome.runtime.lastError || !response || !response.success) {
            loadRulesFromStorage();
            return;
        }

        currentPolicy = response.localPolicy || {};
        updateRulesDisplay(currentPolicy, refreshRemote ? 'Rules synced from extension' : 'Rules loaded from extension');
    });
}

function loadRulesFromStorage() {
    chrome.storage.local.get(['console_firewall_policy'], (result) => {
        currentPolicy = result.console_firewall_policy || {};
        updateRulesDisplay(currentPolicy, 'Rules loaded from local storage');
    });
}

function testStorage() {
    console.log('[AI Panel] Testing storage access...');
    loadCommands();
}

function sendRuntimeMessage(message) {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage(message, (response) => {
            if (chrome.runtime.lastError) {
                resolve({
                    success: false,
                    error: chrome.runtime.lastError.message
                });
                return;
            }

            resolve({
                success: true,
                response: response
            });
        });
    });
}

function getLocalConsoleAnalysisCacheStats() {
    return new Promise((resolve) => {
        chrome.storage.local.get([CONSOLE_ANALYSIS_CACHE_KEY], (result) => {
            const cache = result && result[CONSOLE_ANALYSIS_CACHE_KEY] && typeof result[CONSOLE_ANALYSIS_CACHE_KEY] === 'object'
                ? result[CONSOLE_ANALYSIS_CACHE_KEY]
                : {};

            resolve({
                success: true,
                featureVersion: CONSOLE_ANALYSIS_CACHE_FEATURE_VERSION,
                entryCount: Object.keys(cache).length,
                maxEntries: MAX_CONSOLE_ANALYSIS_CACHE_ENTRIES,
                source: 'storage'
            });
        });
    });
}

async function testExtension() {
    console.log('[AI Panel] Testing extension connectivity...');

    const pingResult = await sendRuntimeMessage({ action: 'ping' });
    const response = pingResult.success ? pingResult.response : null;
    const isConnected = Boolean(response && response.pong);

    updateExtensionStatus(
        isConnected ? 'success' : 'error',
        isConnected ? 'Background script responding' : 'Background script not responding'
    );

    const backgroundStatus = document.getElementById('backgroundStatus');
    if (!backgroundStatus) {
        return;
    }

    if (!isConnected) {
        backgroundStatus.className = 'status-indicator error';
        backgroundStatus.textContent = pingResult.error
            ? `Ping failed: ${pingResult.error}`
            : 'Ping failed';
        return;
    }

    const cacheStatsResult = await sendRuntimeMessage({ action: 'getConsoleAnalysisCacheStats' });
    const runtimeCacheStats = cacheStatsResult.success && cacheStatsResult.response && cacheStatsResult.response.success !== false
        ? cacheStatsResult.response
        : null;
    const cacheStats = runtimeCacheStats || await getLocalConsoleAnalysisCacheStats();

    let cacheLabel = '';
    let statusType = 'success';

    if (cacheStats) {
        const featureVersion = cacheStats.featureVersion || response.cacheFeatureVersion || 'enabled';
        const entryCount = Number(cacheStats.entryCount || 0);
        const sourceLabel = cacheStats.source === 'storage'
            ? ' | Source: storage fallback'
            : '';

        cacheLabel = `Cache feature: ${featureVersion} | Entries: ${entryCount}${sourceLabel}`;
    } else if (response.cacheFeature) {
        cacheLabel = `Cache feature: ${response.cacheFeatureVersion || 'enabled'}`;
    } else {
        statusType = 'warning';
        cacheLabel = 'Cache diagnostics unavailable from this background build; reload extension if you recently updated it';
    }

    backgroundStatus.className = `status-indicator ${statusType}`;
    backgroundStatus.textContent = response.timestamp
        ? `Last ping: ${new Date(response.timestamp).toLocaleTimeString()} | ${cacheLabel}`
        : cacheLabel;
}

function addTestCommand() {
    console.log('[AI Panel] Adding test command...');

    const testCommand = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        type: 'log',
        command: `console.log("Test command from AI Panel - ${new Date().toLocaleTimeString()}")`,
        analysis: 'RISK_LEVEL: LOW\nTHREAT_TYPE: TEST\nDESCRIPTION: Test command from AI panel\nRECOMMENDATION: Command appears safe',
        riskLevel: 'LOW',
        source: 'ai_panel',
        domain: 'extension',
        url: chrome.runtime.getURL('ai_testing_panel_working.html'),
        blocked: false,
        fallback: false
    };

    commands = [testCommand, ...commands];
    saveCommands();
    updateExtensionStatus('success', 'Test command added');
}

function clearStorage() {
    console.log('[AI Panel] Clearing storage...');
    chrome.storage.local.set({
        'ai_commands': [],
        'ai_response_history': [],
        'console_analysis_cache': {}
    }, () => {
        commands = [];
        updateStorageStatus('success', 'Storage cleared');
        updateCommandCount(0);
        updateRecentCommands([]);
    });
}

function updateStorageStatus(type, message) {
    const element = document.getElementById('storageStatus');
    element.className = `status-indicator ${type}`;
    element.textContent = message;
}

function updateExtensionStatus(type, message) {
    const element = document.getElementById('extensionStatus');
    element.className = `status-indicator ${type}`;
    element.textContent = message;
}

function updateCommandCount(count) {
    const element = document.getElementById('commandCount');
    element.textContent = `Commands: ${count}`;
    element.className = count > 0 ? 'status-indicator success' : 'status-indicator warning';
}

function savePolicy(updatedPolicy, statusMsg) {
    chrome.runtime.sendMessage({ action: 'updateConsolePolicy', policy: updatedPolicy }, (response) => {
        if (chrome.runtime.lastError || !response || !response.success) {
            const err = (chrome.runtime.lastError && chrome.runtime.lastError.message) ||
                (response && response.error) || 'Save failed';
            updateRulesDisplay(currentPolicy, 'Save failed: ' + err);
            return;
        }
        currentPolicy = response.policy || updatedPolicy;
        updateRulesDisplay(currentPolicy, statusMsg || 'Rules saved');
    });
}

function toggleRuleEnabled(ruleId) {
    if (!currentPolicy || !Array.isArray(currentPolicy.rules)) return;
    const updatedRules = currentPolicy.rules.map((r) =>
        r.id === ruleId ? { ...r, enabled: r.enabled === false ? true : false } : r
    );
    const updatedPolicy = { ...currentPolicy, rules: updatedRules };
    savePolicy(updatedPolicy, `Rule "${ruleId}" toggled`);
}

function toggleRuleBlock(ruleId) {
    if (!currentPolicy || !Array.isArray(currentPolicy.rules)) return;
    const updatedRules = currentPolicy.rules.map((r) =>
        r.id === ruleId ? { ...r, block: !r.block } : r
    );
    const updatedPolicy = { ...currentPolicy, rules: updatedRules };
    savePolicy(updatedPolicy, `Rule "${ruleId}" action toggled`);
}

function updateRulesDisplay(policy, statusMessage) {
    const rules = Array.isArray(policy && policy.rules) ? policy.rules : [];
    const activeRules = rules.filter((rule) => rule && rule.enabled !== false);
    const blockingRules = activeRules.filter((rule) => rule.block);
    const mode = policy && policy.mode ? policy.mode : 'unknown';
    const ruleVersionRange = activeRules.length
        ? `1:${activeRules.length}:b${blockingRules.length}`
        : `0:0:b${blockingRules.length}`;
    const updatedAt = policy && policy.updatedAt
        ? new Date(policy.updatedAt).toLocaleString()
        : 'Unknown';

    const statusElement = document.getElementById('rulesStatus');
    const summaryElement = document.getElementById('rulesSummary');
    const listElement = document.getElementById('rulesList');

    if (statusElement) {
        statusElement.className = `status-indicator ${activeRules.length ? 'success' : 'warning'}`;
        statusElement.textContent = statusMessage;
    }

    if (summaryElement) {
        summaryElement.className = `status-indicator ${activeRules.length ? 'info' : 'warning'}`;
        summaryElement.textContent = `Mode: ${String(mode).toUpperCase()} | Rule versions: ${ruleVersionRange} | Active rules: ${activeRules.length} | Blocking: ${blockingRules.length} | Updated: ${updatedAt}`;
    }

    if (!listElement) {
        return;
    }

    if (!rules.length) {
        listElement.innerHTML = '<div class="no-commands">No console firewall rules found.</div>';
        return;
    }

    listElement.innerHTML = rules.map((rule, index) => {
        const severity = String(rule.severity || 'unknown').toLowerCase();
        const action = rule.block ? 'block' : 'monitor';
        const enabled = rule.enabled !== false;
        const ruleVersionLabel = `${index + 1}:${rules.length}`;
        const appliesTo = Array.isArray(rule.appliesTo) && rule.appliesTo.length
            ? rule.appliesTo.join(', ')
            : 'all';

        return `
            <div class="rule-card ${action}" id="rule-card-${escapeHtml(rule.id || '')}">
                <div class="rule-header">
                    <div class="rule-title">${escapeHtml(rule.id || 'unnamed-rule')}</div>
                    <div style="color: ${getRiskColor(rule.severity)}; font-size: 10px; font-weight: bold;">
                        ${escapeHtml(rule.severity || 'UNKNOWN')}
                    </div>
                </div>
                <div class="rule-tags">
                    <span class="tag severity-${severity}">${escapeHtml(rule.severity || 'UNKNOWN')}</span>
                    <span class="tag action-${action}">${action.toUpperCase()}</span>
                    <span class="tag enabled-${enabled}">${enabled ? 'ENABLED' : 'DISABLED'}</span>
                </div>
                <div class="rule-meta">Rule version: ${escapeHtml(ruleVersionLabel)} | Applies to: ${escapeHtml(appliesTo)}</div>
                <div class="rule-reason">${escapeHtml(rule.reason || 'No reason provided')}</div>
                <div class="rule-pattern">${escapeHtml(rule.pattern || '')}</div>
                <div class="rule-actions" style="display:flex;gap:6px;margin-top:8px;">
                    <button
                        class="test-button"
                        style="padding:4px 10px;font-size:10px;margin:0;background:${enabled ? '#6c757d' : '#28a745'};"
                        data-rule-id="${escapeHtml(rule.id || '')}"
                        data-action="toggle-enabled">
                        ${enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button
                        class="test-button"
                        style="padding:4px 10px;font-size:10px;margin:0;background:${rule.block ? '#ffc107' : '#dc3545'};color:${rule.block ? '#333' : '#fff'};"
                        data-rule-id="${escapeHtml(rule.id || '')}"
                        data-action="toggle-block">
                        ${rule.block ? 'Set to Monitor' : 'Set to Block'}
                    </button>
                </div>
            </div>
        `;
    }).join('');

    // Attach button listeners after rendering
    listElement.querySelectorAll('button[data-action]').forEach((btn) => {
        btn.addEventListener('click', () => {
            const ruleId = btn.dataset.ruleId;
            const action = btn.dataset.action;
            if (action === 'toggle-enabled') toggleRuleEnabled(ruleId);
            else if (action === 'toggle-block') toggleRuleBlock(ruleId);
        });
    });
}

function updateRecentCommands(commandList) {
    const element = document.getElementById('recentCommands');

    if (commandList.length === 0) {
        element.innerHTML = '<div style="color: #666; text-align: center; padding: 20px;">No commands yet...</div>';
        return;
    }

    const html = [...commandList]
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, 10)
        .map((cmd) => `
            <div style="padding: 10px; margin: 8px 0; border: 1px solid #eee; border-radius: 8px; background: #fff; font-size: 11px;">
                <div style="display: flex; justify-content: space-between; align-items: center; gap: 10px; margin-bottom: 6px;">
                    <div style="font-weight: bold; color: #333;">${escapeHtml((cmd.type || 'unknown').toUpperCase())}</div>
                    <div style="color: ${getRiskColor(cmd.riskLevel)}; font-size: 10px; font-weight: bold;">
                        ${escapeHtml(cmd.riskLevel || 'UNKNOWN')}
                    </div>
                </div>
                <div style="color: #222; font-weight: bold; margin-bottom: 4px;">Console Command</div>
                <pre style="margin: 0 0 8px; padding: 8px; background: #f7f7f9; border-radius: 6px; color: #444; white-space: pre-wrap; word-break: break-word; font-family: Consolas, monospace;">${escapeHtml(cmd.command || '')}</pre>
                <div style="color: #1565c0; font-weight: bold; margin-bottom: 4px;">AI Response</div>
                <pre style="margin: 0 0 8px; padding: 8px; background: #eef5ff; border-radius: 6px; color: #2c3e50; white-space: pre-wrap; word-break: break-word; font-family: Consolas, monospace;">${escapeHtml(cmd.analysis || 'No AI response yet')}</pre>
                <div style="color: #999; font-size: 9px;">${escapeHtml(new Date(cmd.timestamp).toLocaleString())}</div>
                <div style="color: #777; font-size: 9px; margin-top: 2px;">Firewall rule: stored | Cache: ${cmd.cacheHit ? 'HIT' : 'MISS'}</div>
            </div>
        `)
        .join('');

    element.innerHTML = html;
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function getRiskColor(riskLevel) {
    if (riskLevel === 'HIGH' || riskLevel === 'CRITICAL') {
        return '#dc3545';
    }

    if (riskLevel === 'MEDIUM') {
        return '#ffc107';
    }

    return '#28a745';
}

function saveCommands() {
    chrome.storage.local.set({ 'ai_commands': commands }, () => {
        updateCommandCount(commands.length);
        updateRecentCommands(commands);
    });
}

chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'local' && changes.ai_commands) {
        console.log('[AI Panel] Storage changed, reloading...');
        commands = Array.isArray(changes.ai_commands.newValue) ? changes.ai_commands.newValue : [];
        updateCommandCount(commands.length);
        updateRecentCommands(commands);
    }

    if (namespace === 'local' && changes.console_firewall_policy) {
        currentPolicy = changes.console_firewall_policy.newValue || {};
        updateRulesDisplay(currentPolicy, 'Rules updated in local storage');
    }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('[AI Panel] Message received:', message);

    if (message.action === 'newAICommand' || message.action === 'commandsUpdated') {
        loadCommands();
        sendResponse({ success: true });
    }
});

document.addEventListener('DOMContentLoaded', () => {
    console.log('[AI Panel] Working version initialized');
    loadCommands();
    loadRules();
    testExtension();

    const testStorageBtn = document.getElementById('testStorageBtn');
    const testExtensionBtn = document.getElementById('testExtensionBtn');
    const addTestCommandBtn = document.getElementById('addTestCommandBtn');
    const clearStorageBtn = document.getElementById('clearStorageBtn');
    const refreshRulesBtn = document.getElementById('refreshRulesBtn');
    const syncRulesBtn = document.getElementById('syncRulesBtn');

    if (testStorageBtn) {
        testStorageBtn.addEventListener('click', testStorage);
    }

    if (testExtensionBtn) {
        testExtensionBtn.addEventListener('click', testExtension);
    }

    if (addTestCommandBtn) {
        addTestCommandBtn.addEventListener('click', addTestCommand);
    }

    if (clearStorageBtn) {
        clearStorageBtn.addEventListener('click', clearStorage);
    }

    if (refreshRulesBtn) {
        refreshRulesBtn.addEventListener('click', () => loadRules(false));
    }

    if (syncRulesBtn) {
        syncRulesBtn.addEventListener('click', () => loadRules(true));
    }
});
