let EXTENSION_ID = null; // Will be detected dynamically
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
    console.log('[Control Panel] Initializing...');
    detectExtensionId();
    loadSessionFromStorage();
    connectToExtension();
    setupEventListeners();
    updateUI();
    
    setInterval(() => {
        checkForSessionUpdates();
    }, 3000); // Check every 3 seconds
    
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.action === 'sessionEnded') {
            console.log('[Control Panel] Session ended notification received:', message);
            addLog('warning', 'Session automatically ended', {
                sessionId: message.sessionId,
                reason: message.reason,
                timestamp: new Date().toISOString()
            });
            
            currentSessionId = null;
            updateSessionInfo('None', 'None', 'None');
            updateConnectionStatus('Disconnected', 'Session ended');
            updateBrowserStatus('Not Controlled');
        }
    });
});

function loadSessionFromStorage() {
    try {
        console.log('[Control Panel] Loading session from local storage...');
        
        if (chrome && chrome.storage && chrome.storage.local) {
            chrome.storage.local.get('firewall_guard_sessions', (result) => {
                const storage = result.firewall_guard_sessions;
                console.log('[Control Panel] Local storage data:', storage);
                
                if (storage && storage.currentSession) {
                    console.log('[Control Panel] Found current session in local storage:', storage.currentSession);
                    
                    currentSessionId = storage.currentSession.sessionId;
                    
                    updateSessionInfo(
                        storage.currentSession.sessionId,
                        storage.currentSession.windowId,
                        storage.currentSession.tabId
                    );
                    
                    updateConnectionStatus('Connected', 'Connected to stored session');
                    
                    console.log('[Control Panel] Session loaded from local storage successfully');
                } else {
                    console.log('[Control Panel] No current session found in local storage');
                    updateConnectionStatus('Disconnected', 'No active session found');
                }
            });
        } else {
            console.log('[Control Panel] Chrome storage not available, using fallback');
            updateConnectionStatus('Disconnected', 'Storage not available');
        }
    } catch (error) {
        console.error('[Control Panel] Failed to load session from storage:', error);
        updateConnectionStatus('Error', 'Failed to load session');
    }
}

function checkForSessionUpdates() {
    try {
        console.log('[Control Panel] Checking for session updates...');
        
        if (chrome && chrome.storage && chrome.storage.local) {
            chrome.storage.local.get('firewall_guard_sessions', (result) => {
                const storage = result.firewall_guard_sessions;
                
                if (storage && storage.currentSession) {
                    if (storage.currentSession.sessionId !== currentSessionId) {
                        console.log('[Control Panel] New session detected in storage:', storage.currentSession);
                        
                        currentSessionId = storage.currentSession.sessionId;
                        
                        updateSessionInfo(
                            storage.currentSession.sessionId,
                            storage.currentSession.windowId,
                            storage.currentSession.tabId
                        );
                        
                        updateConnectionStatus('Connected', 'Connected to stored session');
                        
                        updateBrowserStatus('Controlled');
                        
                        addLog('success', 'Session automatically detected from storage', {
                            sessionId: storage.currentSession.sessionId,
                            windowId: storage.currentSession.windowId,
                            tabId: storage.currentSession.tabId,
                            url: storage.currentSession.url,
                            timestamp: new Date().toISOString()
                        });
                    }
                }
            });
        }
        
        if (chrome.runtime && chrome.runtime.sendMessage && EXTENSION_ID) {
            chrome.runtime.sendMessage(EXTENSION_ID, { action: 'getActiveSessions' }, (response) => {
                if (chrome.runtime.lastError) {
                    console.warn('[Control Panel] Failed to get active sessions:', chrome.runtime.lastError.message);
                } else if (response && response.length > 0) {
                    const session = response[0];
                    if (session && session.sessionId && session.sessionId !== currentSessionId) {
                        console.log('[Control Panel] New session detected from extension:', session);
                        
                        currentSessionId = session.sessionId;
                        
                        updateSessionInfo(session.sessionId, session.windowId, session.tabId);
                        
                        updateConnectionStatus('Connected', 'Connected to extension session');
                        
                        updateBrowserStatus('Controlled');
                        
                        addLog('success', 'Session automatically detected from extension', {
                            sessionId: session.sessionId,
                            windowId: session.windowId,
                            tabId: session.tabId,
                            url: session.url || 'Unknown',
                            timestamp: new Date().toISOString()
                        });
                    }
                }
            });
        }
    } catch (error) {
        console.error('[Control Panel] Failed to check for session updates:', error);
    }
}

function detectExtensionId() {
    try {
        console.log('[Control Panel] Detecting extension ID...');
        
        const url = new URL(window.location.href);
        const extensionId = url.hostname.split('.')[0];
        console.log('[Control Panel] URL hostname:', url.hostname, 'Extracted ID:', extensionId);
        
        if (extensionId && extensionId.length > 10) {
            EXTENSION_ID = extensionId;
            console.log('[Control Panel] Detected extension ID from URL:', EXTENSION_ID);
        } else {
            if (chrome.runtime && chrome.runtime.id) {
                EXTENSION_ID = chrome.runtime.id;
                console.log('[Control Panel] Got extension ID from runtime:', EXTENSION_ID);
            } else {
                console.log('[Control Panel] No extension ID found, trying fallback...');
            }
        }
        
        console.log('[Control Panel] Final extension ID:', EXTENSION_ID);
    } catch (error) {
        console.error('[Control Panel] Failed to detect extension ID:', error);
    }
}

function connectToExtension() {
    try {
        console.log('[Control Panel] Attempting to connect to extension...');
        console.log('[Control Panel] Chrome runtime available:', !!chrome.runtime);
        console.log('[Control Panel] Chrome connect available:', !!(chrome.runtime && chrome.runtime.connect));
        console.log('[Control Panel] Extension ID:', EXTENSION_ID);
        
        if (chrome.runtime && chrome.runtime.connect && EXTENSION_ID) {
            console.log('[Control Panel] All conditions met, attempting connection...');
            extensionPort = chrome.runtime.connect(EXTENSION_ID);
            
            extensionPort.onMessage.addListener((message) => {
                console.log('[Control Panel] Received port message:', message);
                handleExtensionMessage(message);
            });
            
            extensionPort.onDisconnect.addListener(() => {
                console.log('[Control Panel] Port disconnected');
                updateConnectionStatus(false);
                extensionPort = null;
                console.log('[Control Panel] Disconnected from extension');
                
                setTimeout(() => {
                    if (!extensionPort) {
                        console.log('[Control Panel] Attempting to reconnect...');
                        connectToExtension();
                    }
                }, 2000);
            });
            
            updateConnectionStatus(true);
            console.log('[Control Panel] Connected to extension successfully');
            
            extensionPort.postMessage({ action: 'ping' });
            extensionPort.postMessage({ action: 'getActiveSessions' });
            
        } else {
            console.log('[Control Panel] Extension not available, using demo mode');
            console.log('[Control Panel] Missing conditions:');
            console.log('- chrome.runtime:', !!chrome.runtime);
            console.log('- chrome.runtime.connect:', !!(chrome.runtime && chrome.runtime.connect));
            console.log('- EXTENSION_ID:', !!EXTENSION_ID);
            startDemoMode();
        }
    } catch (error) {
        console.error('[Control Panel] Failed to connect to extension:', error);
        startDemoMode();
    }
    
    if (chrome.runtime && chrome.runtime.onMessage) {
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            console.log('[Control Panel] Received runtime message:', message);
            handleExtensionMessage(message);
            return false;
        });
    }
    
    setTimeout(() => {
        if (chrome.runtime && chrome.runtime.sendMessage && EXTENSION_ID) {
            console.log('[Control Panel] Requesting active sessions...');
            chrome.runtime.sendMessage(EXTENSION_ID, { action: 'getActiveSessions' }, (response) => {
                if (chrome.runtime.lastError) {
                    console.warn('[Control Panel] Failed to get active sessions:', chrome.runtime.lastError.message);
                } else if (response && response.length > 0) {
                    console.log('[Control Panel] Active sessions received:', response);
                    const session = response[0];
                    if (session && session.sessionId) {
                        console.log('[Control Panel] Auto-setting session from active sessions:', session);
                        currentSessionId = session.sessionId;
                        updateSessionInfo(session.sessionId, session.windowId, session.tabId);
                        updateBrowserStatus('Controlled');
                        updateConnectionStatus(true);
                        addLog('success', 'Session automatically detected', {
                            sessionId: session.sessionId,
                            windowId: session.windowId,
                            tabId: session.tabId,
                            url: session.url || 'Unknown',
                            autoDetected: true
                        });
                    }
                } else {
                    console.log('[Control Panel] No active sessions found, will detect on browser launch');
                    addLog('info', 'Waiting for browser launch to auto-detect session', {
                        timestamp: Date.now()
                    });
                }
            });
        }
    }, 2000); // Wait 2 seconds for connection to establish
    
    setInterval(() => {
        if (chrome.runtime && chrome.runtime.sendMessage && EXTENSION_ID && !currentSessionId) {
            console.log('[Control Panel] Periodic check for active sessions...');
            chrome.runtime.sendMessage(EXTENSION_ID, { action: 'getActiveSessions' }, (response) => {
                if (chrome.runtime.lastError) {
                    console.warn('[Control Panel] Failed to get active sessions (periodic):', chrome.runtime.lastError.message);
                } else if (response && response.length > 0) {
                    const session = response[0];
                    if (session && session.sessionId && session.sessionId !== currentSessionId) {
                        console.log('[Control Panel] Auto-detected new session:', session);
                        currentSessionId = session.sessionId;
                        updateSessionInfo(session.sessionId, session.windowId, session.tabId);
                        updateBrowserStatus('Controlled');
                        updateConnectionStatus(true);
                        addLog('success', 'New session auto-detected', {
                            sessionId: session.sessionId,
                            windowId: session.windowId,
                            tabId: session.tabId,
                            url: session.url || 'Unknown',
                            autoDetected: true
                        });
                    }
                }
            });
        }
    }, 5000); // Check every 5 seconds
}

function handleExtensionMessage(message) {
    console.log('[Control Panel] Received message:', message);
    console.log('[Control Panel] Current session ID:', currentSessionId);
    console.log('[Control Panel] Extension port status:', !!extensionPort);
    
    if (message.sessionId && !currentSessionId) {
        console.log('[Control Panel] Extracting session ID from message:', message.sessionId);
        currentSessionId = message.sessionId;
        updateSessionInfo(message.sessionId, message.windowId, message.tabId);
        updateBrowserStatus('Controlled');
        updateConnectionStatus(true);
        addLog('success', 'Session ID extracted from message', {
            sessionId: message.sessionId,
            windowId: message.windowId || message.windowId,
            tabId: message.tabId || message.tabId,
            url: message.url,
            source: message.action,
            autoDetected: true
        });
    }
    
    switch (message.action) {
        case 'pong':
            updateConnectionStatus(true);
            addLog('info', 'Extension responded to ping', { 
                sessions: message.sessions || 0,
                timestamp: message.timestamp 
            });
            break;
            
        case 'controlledBrowserReady':
            console.log('[Control Panel] Received controlledBrowserReady message!');
            console.log('[Control Panel] Session details:', {
                sessionId: message.sessionId,
                windowId: message.windowId,
                tabId: message.tabId,
                url: message.url
            });
            
            currentSessionId = message.sessionId;
            updateSessionInfo(message.sessionId, message.windowId, message.tabId);
            updateBrowserStatus('Controlled');
            addLog('info', 'Browser ready for control', {
                sessionId: message.sessionId,
                windowId: message.windowId,
                tabId: message.tabId,
                url: message.url
            });
            break;
            
        case 'controlledBrowserNavigated':
            stats.navigationCount++;
            
            if (message.sessionId && !currentSessionId) {
                console.log('[Control Panel] Extracting session ID from navigation:', message.sessionId);
                currentSessionId = message.sessionId;
                updateSessionInfo(message.sessionId, message.windowId, message.tabId);
                updateBrowserStatus('Controlled');
                updateConnectionStatus(true);
                addLog('success', 'Session ID extracted from navigation', {
                    sessionId: message.sessionId,
                    windowId: message.windowId,
                    tabId: message.tabId,
                    url: message.url,
                    autoDetected: true
                });
            }
            
            addLog('navigation', 'Page navigated', {
                url: message.url,
                sessionId: message.sessionId || currentSessionId
            });
            updateStats();
            break;
            
        case 'controlledBrowserRequest':
            stats.totalRequests++;
            
            if (message.sessionId && !currentSessionId) {
                console.log('[Control Panel] Extracting session ID from network request:', message.sessionId);
                currentSessionId = message.sessionId;
                updateSessionInfo(message.sessionId, message.windowId, message.tabId);
                updateBrowserStatus('Controlled');
                updateConnectionStatus(true);
                addLog('success', 'Session ID extracted from network request', {
                    sessionId: message.sessionId,
                    windowId: message.windowId,
                    tabId: message.tabId,
                    url: message.url,
                    autoDetected: true
                });
            }
            
            if (message.blocked) {
                stats.blockedRequests++;
                addLog('blocked', 'Request blocked', {
                    url: message.url,
                    reason: message.blockReason,
                    sessionId: message.sessionId || currentSessionId
                });
            } else {
                addLog('network', 'Network request', {
                    url: message.url,
                    sessionId: message.sessionId || currentSessionId
                });
            }
            break;
            
        case 'browserInfo':
            if (message.success) {
                updateSessionInfo(message.info.sessionId, message.info.windowId, message.info.tabId);
                updateBrowserStatus('Controlled');
                updateStatsFromInfo(message.info);
            }
            break;
            
        case 'actionResponse':
            handleActionResponse(message);
            break;
            
        case 'getActiveSessions':
            if (message.success && message.sessions && message.sessions.length > 0) {
                const session = message.sessions[0];
                currentSessionId = session.sessionId;
                updateSessionInfo(session.sessionId, session.windowId, session.tabId);
                updateBrowserStatus('Controlled');
                addLog('info', 'Active session detected', session);
            }
            break;
    }
}

function setupEventListeners() {
    const bind = (id, eventName, handler) => {
        const element = document.getElementById(id);
        if (!element) {
            return false;
        }
        element.addEventListener(eventName, handler);
        return true;
    };

    bind('targetUrl', 'keypress', (e) => {
        if (e.key === 'Enter') navigateToUrl();
    });
    
    bind('elementSelector', 'keypress', (e) => {
        if (e.key === 'Enter') clickElement();
    });
    
    bind('scriptCode', 'keypress', (e) => {
        if (e.ctrlKey && e.key === 'Enter') executeScript();
    });
    
    bind('navigateBtn', 'click', navigateToUrl);
    bind('refreshBtn', 'click', refreshPage);
    bind('goBackBtn', 'click', goBack);
    bind('goForwardBtn', 'click', goForward);
    bind('clickElementBtn', 'click', clickElement);
    bind('executeScriptBtn', 'click', executeScript);
    bind('takeScreenshotBtn', 'click', takeScreenshot);
    bind('fillFormBtn', 'click', fillForm);
    bind('stopControlBtn', 'click', stopControl);
    
    bind('refreshSessionBtn', 'click', () => {
        console.log('[Control Panel] Manual session refresh clicked');
        loadSessionFromStorage();
        checkForSessionUpdates();
        addLog('info', 'Manual session refresh triggered', {
            timestamp: new Date().toISOString()
        });
    });
    
    bind('updateRulesBtn', 'click', updateRules);
    bind('checkUpdatesBtn', 'click', checkForUpdates);
    
    bind('logFilter', 'change', filterLogs);
    bind('clearLogsBtn', 'click', clearLogs);
}

function navigateToUrl() {
    const targetUrlInput = document.getElementById('targetUrl');
    if (!targetUrlInput) {
        return;
    }

    const url = targetUrlInput.value.trim();
    if (!url) return;
    
    sendToExtension('navigateTo', {
        sessionId: currentSessionId,
        url: url
    });
    
    addLog('info', 'Navigate command sent', { url: url });
}

function refreshPage() {
    sendToExtension('executeScript', {
        sessionId: currentSessionId,
        script: 'location.reload();'
    });
    
    addLog('info', 'Refresh command sent');
}

function goBack() {
    sendToExtension('executeScript', {
        sessionId: currentSessionId,
        script: 'history.back();'
    });
    
    addLog('info', 'Back command sent');
}

function goForward() {
    sendToExtension('executeScript', {
        sessionId: currentSessionId,
        script: 'history.forward();'
    });
    
    addLog('info', 'Forward command sent');
}

function clickElement() {
    const selectorInput = document.getElementById('elementSelector');
    if (!selectorInput) {
        return;
    }

    const selector = selectorInput.value.trim();
    if (!selector) return;
    
    sendToExtension('clickElement', {
        sessionId: currentSessionId,
        selector: selector
    });
    
    addLog('info', 'Click command sent', { selector: selector });
}

function executeScript() {
    const scriptInput = document.getElementById('scriptCode');
    if (!scriptInput) {
        return;
    }

    const script = scriptInput.value;
    if (!script) return;
    
    sendToExtension('executeScript', {
        sessionId: currentSessionId,
        script: script
    });
    
    addLog('info', 'Script execution command sent', { 
        script: script.substring(0, 100) + (script.length > 100 ? '...' : '') 
    });
}

function takeScreenshot() {
    sendToExtension('takeScreenshot', {
        sessionId: currentSessionId
    });
    
    addLog('info', 'Screenshot command sent');
}

function fillForm() {
    const formDataInput = document.getElementById('formData');
    if (!formDataInput) {
        return;
    }

    const formDataText = formDataInput.value;
    if (!formDataText) return;
    
    try {
        const formData = JSON.parse(formDataText);
        
        sendToExtension('fillForm', {
            sessionId: currentSessionId,
            formData: formData
        });
        
        addLog('info', 'Form fill command sent', { formData });
    } catch (error) {
        alert('Invalid JSON in form data field');
    }
}

function stopControl() {
    if (currentSessionId) {
        sendToExtension('stopAutomation', {
            sessionId: currentSessionId
        });
        
        addLog('info', 'Stop control command sent');
        currentSessionId = null;
        updateSessionInfo(null, null, null);
        updateBrowserStatus('Not Controlled');
    }
}

function sendToExtension(action, data = {}) {
    try {
        if (extensionPort && extensionPort.postMessage) {
            extensionPort.postMessage({ action, ...data });
            console.log('[Control Panel] Sent message:', { action, ...data });
        } else if (chrome.runtime && chrome.runtime.sendMessage && EXTENSION_ID) {
            chrome.runtime.sendMessage(EXTENSION_ID, { action, ...data }, (response) => {
                if (chrome.runtime.lastError) {
                    console.warn('[Control Panel] Message error:', chrome.runtime.lastError.message);
                } else {
                    console.log('[Control Panel] Message response:', response);
                }
            });
            console.log('[Control Panel] Sent message via runtime:', { action, ...data });
        } else {
            console.warn('[Control Panel] No connection available for message:', { action, ...data });
            addLog('error', 'No connection to extension', { action, ...data });
        }
    } catch (error) {
        console.error('[Control Panel] Failed to send message:', error);
        addLog('error', 'Communication failed', { error: error.message });
    }
}

function handleActionResponse(response) {
    if (response.success) {
        addLog('success', 'Action completed successfully', response);
    } else {
        addLog('error', 'Action failed', { error: response.error });
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
    if (!logsContent) {
        return;
    }

    const filterElement = document.getElementById('logFilter');
    const filter = filterElement ? filterElement.value : 'all';
    
    const filteredLogs = filter === 'all' 
        ? logs 
        : logs.filter(log => log.type === filter);
    
    logsContent.innerHTML = filteredLogs.map(log => `
        <div class="log-entry ${log.type}">
            <div class="log-time">${new Date(log.timestamp).toLocaleString()}</div>
            <div class="log-type ${log.type}">${log.type}</div>
            <div class="log-url">${formatLogMessage(log.message, log.details)}</div>
            ${log.details.url ? `<div class="log-details">URL: ${formatUrl(log.details.url)}</div>` : ''}
            ${log.details.selector ? `<div class="log-details">Selector: ${log.details.selector}</div>` : ''}
            ${log.details.error ? `<div class="log-details">Error: ${log.details.error}</div>` : ''}
        </div>
    `).join('');
    
    logsContent.scrollTop = 0;
}

function filterLogs() {
    updateLogsDisplay();
}

function formatUrl(url) {
    if (!url) return '';
    
    try {
        const decodedUrl = decodeURIComponent(url);
        
        if (decodedUrl.length > 100) {
            return decodedUrl.substring(0, 97) + '...';
        }
        
        return decodedUrl;
    } catch (error) {
        return url.length > 100 ? url.substring(0, 97) + '...' : url;
    }
}

function formatLogMessage(message, details) {
    if (!message) return '';
    
    if (details && details.url) {
        const formattedUrl = formatUrl(details.url);
        return message.replace(details.url, formattedUrl);
    }
    
    if (message.length > 150) {
        return message.substring(0, 147) + '...';
    }
    
    return message;
}

function clearLogs() {
    if (confirm('Are you sure you want to clear all logs?')) {
        logs = [];
        stats = {
            totalRequests: 0,
            blockedRequests: 0,
            navigationCount: 0,
            downloadCount: 0
        };
        updateLogsDisplay();
        updateStats();
        updateLogCount();
    }
}

function updateConnectionStatus(connectedOrStatus, details) {
    const connected = typeof connectedOrStatus === 'boolean'
        ? connectedOrStatus
        : String(connectedOrStatus || '').toLowerCase() === 'connected';

    const statusIndicator = document.getElementById('connectionStatus');
    const statusText = document.getElementById('connectionText');
    const label = connected ? 'Connected' : 'Disconnected';
    const text = typeof details === 'string' && details.trim()
        ? details.trim()
        : label;
    
    if (statusIndicator) {
        statusIndicator.classList.toggle('connected', connected);
    }

    if (statusText) {
        statusText.textContent = text;
    }
}

function updateSessionInfo(sessionId, windowId, tabId) {
    console.log('[Control Panel] Updating session info:', { sessionId, windowId, tabId });
    
    const sessionIdElement = document.getElementById('sessionId');
    if (sessionIdElement) {
        sessionIdElement.textContent = sessionId || 'None';
    }
    
    const windowIdElement = document.getElementById('windowId');
    if (windowIdElement) {
        windowIdElement.textContent = windowId || 'None';
    }
    
    const tabIdElement = document.getElementById('tabId');
    if (tabIdElement) {
        tabIdElement.textContent = tabId || 'None';
    }
    
    if (sessionId) {
        addLog('info', 'Session information updated', {
            sessionId: sessionId,
            windowId: windowId,
            tabId: tabId,
            timestamp: new Date().toISOString()
        });
    }
}

function updateBrowserStatus(status) {
    const browserStatusElement = document.getElementById('browserStatus');
    if (browserStatusElement) {
        browserStatusElement.textContent = status;
    }
}

function updateLogCount() {
    const logCountElement = document.getElementById('logCount');
    if (logCountElement) {
        logCountElement.textContent = logs.length;
    }
}

function updateStats() {
    const totalRequestsElement = document.getElementById('totalRequests');
    const blockedRequestsElement = document.getElementById('blockedRequests');
    const navigationCountElement = document.getElementById('navigationCount');
    const downloadCountElement = document.getElementById('downloadCount');

    if (totalRequestsElement) {
        totalRequestsElement.textContent = stats.totalRequests;
    }

    if (blockedRequestsElement) {
        blockedRequestsElement.textContent = stats.blockedRequests;
    }

    if (navigationCountElement) {
        navigationCountElement.textContent = stats.navigationCount;
    }

    if (downloadCountElement) {
        downloadCountElement.textContent = stats.downloadCount;
    }
}

function updateStatsFromInfo(info) {
    if (info.logsCount !== undefined) {
        updateStats();
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
    
    setInterval(() => {
        if (Math.random() > 0.7) {
            const urls = [
                'https://www.google.com/search?q=test',
                'https://fonts.googleapis.com/css',
                'https://www.gstatic.com/images',
                'https://ajax.googleapis.com/ajax'
            ];
            
            const url = urls[Math.floor(Math.random() * urls.length)];
            const blocked = Math.random() > 0.8;
            
            if (blocked) {
                stats.blockedRequests++;
                addLog('blocked', 'Request blocked', { 
                    url: url, 
                    reason: 'Ad domain' 
                });
            } else {
                addLog('network', 'Network request', { url: url });
            }
            
            stats.totalRequests++;
            updateStats();
        }
    }, 3000);
}

function filterLogs() {
    const filterElement = document.getElementById('logFilter');
    const logsContent = document.getElementById('logsContent');
    if (!logsContent) {
        return;
    }

    const filterType = filterElement ? filterElement.value : 'all';
    const allLogEntries = logsContent.querySelectorAll('.log-entry');
    
    allLogEntries.forEach(entry => {
        if (filterType === 'all') {
            entry.style.display = 'block';
        } else {
            const logType = entry.querySelector('.log-type');
            if (logType && logType.textContent.toLowerCase() === filterType) {
                entry.style.display = 'block';
            } else {
                entry.style.display = 'none';
            }
        }
    });
}

function clearLogs() {
    logs = [];
    stats = {
        totalRequests: 0,
        blockedRequests: 0,
        navigationCount: 0,
        downloadCount: 0
    };
    updateLogsDisplay();
    updateLogCount();
    updateStats();
    addLog('info', 'Logs cleared', { timestamp: Date.now() });
}

function updateRules() {
    console.log('[Control Panel] Updating firewall rules...');
    addLog('info', 'Manual rules update triggered', { timestamp: Date.now() });
    
    sendToExtension('updateRules', {});
}

function checkForUpdates() {
    console.log('[Control Panel] Checking for firewall updates...');
    addLog('info', 'Manual update check triggered', { timestamp: Date.now() });
    
    sendToExtension('checkUpdates', {});
}

function handleDashboardResponse(response) {
    console.log('[Control Panel] Dashboard response:', response);
    
    if (response.action === 'updateRules') {
        if (response.success) {
            addLog('success', 'Firewall rules updated successfully', {
                rulesVersion: response.version || 'latest',
                timestamp: Date.now()
            });
            updateLastUpdate(response.timestamp || new Date().toISOString());
        } else {
            addLog('error', 'Failed to update firewall rules', {
                error: response.error,
                timestamp: Date.now()
            });
        }
    } else if (response.action === 'checkUpdates') {
        if (response.success) {
            addLog('info', 'Update check completed', {
                updatesAvailable: response.updatesAvailable || false,
                currentVersion: response.currentVersion || 'unknown',
                latestVersion: response.latestVersion || 'unknown',
                timestamp: Date.now()
            });
        } else {
            addLog('error', 'Failed to check for updates', {
                error: response.error,
                timestamp: Date.now()
            });
        }
    }
}

function updateLastUpdate(timestamp) {
    const lastUpdateElement = document.getElementById('lastUpdateText');
    if (lastUpdateElement) {
        if (timestamp) {
            const date = new Date(timestamp);
            lastUpdateElement.textContent = date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
        } else {
            lastUpdateElement.textContent = 'Never';
        }
    }
}

function updateEngineStatus(status) {
    const engineStatusElement = document.getElementById('engineStatusText');
    if (engineStatusElement) {
        engineStatusElement.textContent = status;
        engineStatusElement.style.color = status === 'Running' ? '#28a745' : '#dc3545';
    }
}
