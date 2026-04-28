// Clean Browser Control Panel - No Errors
let EXTENSION_ID = null;
let currentSessionId = null;
let logs = [];
let stats = {
    totalRequests: 0,
    blockedRequests: 0,
    navigationCount: 0,
    downloadCount: 0
};
let extensionPort = null;

document.addEventListener('DOMContentLoaded', () => {
    console.log('[Control Panel] Initializing clean version...');
    detectExtensionId();
    loadSessionFromStorage();
    connectToExtension();
    setupEventListeners();
    updateUI();
    
    setInterval(() => {
        checkForSessionUpdates();
    }, 3000);
});

function detectExtensionId() {
    try {
        const url = new URL(window.location.href);
        const extensionId = url.hostname.split('.')[0];
        
        if (extensionId && extensionId.length > 10) {
            EXTENSION_ID = extensionId;
            console.log('[Control Panel] Extension ID detected:', EXTENSION_ID);
        }
    } catch (error) {
        console.error('[Control Panel] Failed to detect extension ID:', error);
    }
}

function loadSessionFromStorage() {
    try {
        if (chrome && chrome.storage && chrome.storage.local) {
            chrome.storage.local.get('firewall_guard_sessions', (result) => {
                const storage = result.firewall_guard_sessions;
                
                if (storage && storage.currentSession) {
                    currentSessionId = storage.currentSession.sessionId;
                    updateSessionInfo(
                        storage.currentSession.sessionId,
                        storage.currentSession.windowId,
                        storage.currentSession.tabId
                    );
                    updateConnectionStatus(true);
                }
            });
        }
    } catch (error) {
        console.error('[Control Panel] Failed to load session:', error);
    }
}

function connectToExtension() {
    try {
        if (chrome.runtime && chrome.runtime.connect && EXTENSION_ID) {
            extensionPort = chrome.runtime.connect(EXTENSION_ID);
            
            extensionPort.onMessage.addListener((message) => {
                handleExtensionMessage(message);
            });
            
            extensionPort.onDisconnect.addListener(() => {
                updateConnectionStatus(false);
                extensionPort = null;
            });
            
            updateConnectionStatus(true);
            console.log('[Control Panel] Connected to extension');
        } else {
            console.log('[Control Panel] Extension not available, using demo mode');
            startDemoMode();
        }
    } catch (error) {
        console.error('[Control Panel] Failed to connect:', error);
        startDemoMode();
    }
}

function setupEventListeners() {
    console.log('[Control Panel] Setting up event listeners...');
    
    // URL input
    const targetUrlEl = document.getElementById('targetUrl');
    if (targetUrlEl) {
        targetUrlEl.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') navigateToUrl();
        });
    }
    
    // Element selector
    const elementSelectorEl = document.getElementById('elementSelector');
    if (elementSelectorEl) {
        elementSelectorEl.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') clickElement();
        });
    }
    
    // Script code
    const scriptCodeEl = document.getElementById('scriptCode');
    if (scriptCodeEl) {
        scriptCodeEl.addEventListener('keypress', (e) => {
            if (e.ctrlKey && e.key === 'Enter') executeScript();
        });
    }
    
    // Buttons
    const clickElementBtn = document.getElementById('clickElementBtn');
    if (clickElementBtn) {
        clickElementBtn.addEventListener('click', clickElement);
    }
    
    const executeScriptBtn = document.getElementById('executeScriptBtn');
    if (executeScriptBtn) {
        executeScriptBtn.addEventListener('click', executeScript);
    }
    
    const takeScreenshotBtn = document.getElementById('takeScreenshotBtn');
    if (takeScreenshotBtn) {
        takeScreenshotBtn.addEventListener('click', takeScreenshot);
    }
    
    const fillFormBtn = document.getElementById('fillFormBtn');
    if (fillFormBtn) {
        fillFormBtn.addEventListener('click', fillForm);
    }
    
    const stopControlBtn = document.getElementById('stopControlBtn');
    if (stopControlBtn) {
        stopControlBtn.addEventListener('click', stopControl);
    }
    
    console.log('[Control Panel] Event listeners setup complete');
}

function navigateToUrl() {
    const targetUrlEl = document.getElementById('targetUrl');
    if (!targetUrlEl) return;
    
    let url = targetUrlEl.value.trim();
    if (!url) return;
    
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
    }
    
    chrome.runtime.sendMessage({
        action: 'navigateTo',
        url: url,
        sessionId: currentSessionId
    });
    
    addLog('info', 'Navigating to URL', { url: url });
}

function clickElement() {
    const elementSelectorEl = document.getElementById('elementSelector');
    if (!elementSelectorEl) return;
    
    const selector = elementSelectorEl.value.trim();
    if (!selector) return;
    
    chrome.runtime.sendMessage({
        action: 'clickElement',
        selector: selector,
        sessionId: currentSessionId
    });
    
    addLog('info', 'Clicking element', { selector: selector });
}

function executeScript() {
    const scriptCodeEl = document.getElementById('scriptCode');
    if (!scriptCodeEl) return;
    
    const code = scriptCodeEl.value.trim();
    if (!code) return;
    
    chrome.runtime.sendMessage({
        action: 'executeScript',
        code: code,
        sessionId: currentSessionId
    });
    
    addLog('info', 'Executing script', { code: code });
}

function takeScreenshot() {
    chrome.runtime.sendMessage({
        action: 'takeScreenshot',
        sessionId: currentSessionId
    });
    
    addLog('info', 'Taking screenshot', {});
}

function fillForm() {
    const formDataEl = document.getElementById('formData');
    if (!formDataEl) return;
    
    try {
        const formData = JSON.parse(formDataEl.value);
        chrome.runtime.sendMessage({
            action: 'fillForm',
            data: formData,
            sessionId: currentSessionId
        });
        
        addLog('info', 'Filling form', { data: formData });
    } catch (error) {
        addLog('error', 'Invalid form data', { error: error.message });
    }
}

function stopControl() {
    if (currentSessionId) {
        chrome.runtime.sendMessage({
            action: 'stopAutomation',
            sessionId: currentSessionId
        });
        
        addLog('info', 'Stopping control', { sessionId: currentSessionId });
        currentSessionId = null;
        updateSessionInfo(null, null, null);
        updateBrowserStatus('Not Controlled');
    }
}

function addLog(type, message, details = {}) {
    const logEntry = {
        id: Date.now() + Math.random(),
        timestamp: new Date().toISOString(),
        type: type,
        message: message,
        details: details
    };
    
    logs.unshift(logEntry);
    
    if (logs.length > 1000) {
        logs = logs.slice(0, 1000);
    }
    
    updateLogsDisplay();
    updateLogCount();
}

function updateLogsDisplay() {
    const logsContent = document.getElementById('logsContent');
    if (!logsContent) return;
    
    logsContent.innerHTML = logs.map(log => `
        <div class="log-entry ${log.type}">
            <div class="log-time">${new Date(log.timestamp).toLocaleString()}</div>
            <div class="log-type ${log.type}">${log.type}</div>
            <div class="log-url">${log.message}</div>
        </div>
    `).join('');
    
    logsContent.scrollTop = 0;
}

function updateConnectionStatus(connected) {
    const statusIndicator = document.getElementById('connectionStatus');
    const statusText = document.getElementById('connectionText');
    
    if (statusIndicator) {
        if (connected) {
            statusIndicator.classList.add('connected');
        } else {
            statusIndicator.classList.remove('connected');
        }
    }
    
    if (statusText) {
        statusText.textContent = connected ? 'Connected' : 'Disconnected';
    }
}

function updateSessionInfo(sessionId, windowId, tabId) {
    const sessionIdEl = document.getElementById('sessionId');
    if (sessionIdEl) {
        sessionIdEl.textContent = sessionId || 'None';
    }
    
    const windowIdEl = document.getElementById('windowId');
    if (windowIdEl) {
        windowIdEl.textContent = windowId || 'None';
    }
    
    const tabIdEl = document.getElementById('tabId');
    if (tabIdEl) {
        tabIdEl.textContent = tabId || 'None';
    }
}

function updateBrowserStatus(status) {
    const browserStatusEl = document.getElementById('browserStatus');
    if (browserStatusEl) {
        browserStatusEl.textContent = status;
    }
}

function updateLogCount() {
    const logCountEl = document.getElementById('logCount');
    if (logCountEl) {
        logCountEl.textContent = logs.length;
    }
}

function updateStats() {
    const totalRequestsEl = document.getElementById('totalRequests');
    if (totalRequestsEl) {
        totalRequestsEl.textContent = stats.totalRequests;
    }
    
    const blockedRequestsEl = document.getElementById('blockedRequests');
    if (blockedRequestsEl) {
        blockedRequestsEl.textContent = stats.blockedRequests;
    }
    
    const navigationCountEl = document.getElementById('navigationCount');
    if (navigationCountEl) {
        navigationCountEl.textContent = stats.navigationCount;
    }
    
    const downloadCountEl = document.getElementById('downloadCount');
    if (downloadCountEl) {
        downloadCountEl.textContent = stats.downloadCount;
    }
}

function updateUI() {
    updateConnectionStatus(false);
    updateSessionInfo(null, null, null);
    updateBrowserStatus('Not Controlled');
    updateLogCount();
    updateStats();
}

function startDemoMode() {
    console.log('[Control Panel] Starting demo mode');
    
    setTimeout(() => {
        addLog('info', 'Demo mode started', { mode: 'simulation' });
        addLog('network', 'Request to https://google.com', { url: 'https://google.com' });
        addLog('navigation', 'Navigated to https://google.com', { url: 'https://google.com' });
        stats.totalRequests = 15;
        stats.navigationCount = 1;
        updateStats();
    }, 1000);
}

function handleExtensionMessage(message) {
    console.log('[Control Panel] Received message:', message);
    
    if (message.sessionId && !currentSessionId) {
        currentSessionId = message.sessionId;
        updateSessionInfo(message.sessionId, message.windowId, message.tabId);
        updateBrowserStatus('Controlled');
        updateConnectionStatus(true);
    }
}

function checkForSessionUpdates() {
    // Implementation for checking session updates
}

console.log('[Control Panel] Clean browser control loaded successfully');
