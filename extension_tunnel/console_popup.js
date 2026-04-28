let allCommands = [];
let activeFilter = 'all';

document.addEventListener('DOMContentLoaded', function() {
    ensureCaptureStatusElement();
    ensureConsoleCapture(false);
    loadConsoleCommands();
    setupEventListeners();
    setupRealtimeSync();
});

function loadConsoleCommands() {
    chrome.storage.local.get(['ai_commands'], (result) => {
        allCommands = Array.isArray(result.ai_commands) ? result.ai_commands : [];
        renderCommands();
    });
}

function setupEventListeners() {
    document.getElementById('clearCommandsBtn').addEventListener('click', () => {
        chrome.storage.local.set({ 'ai_commands': [] }, () => {
            allCommands = [];
            renderCommands();
            showNotification('Console commands cleared', 'success');
        });
    });

    document.getElementById('refreshCommandsBtn').addEventListener('click', () => {
        ensureConsoleCapture(true);
        loadConsoleCommands();
        showNotification('Console commands refreshed', 'info');
    });

    document.querySelectorAll('.filter-btn').forEach((btn) => {
        btn.addEventListener('click', (event) => {
            filterCommands(event.target.dataset.filter);
        });
    });
}

function setupRealtimeSync() {
    chrome.storage.onChanged.addListener((changes, namespace) => {
        if (namespace === 'local' && changes.ai_commands) {
            allCommands = Array.isArray(changes.ai_commands.newValue) ? changes.ai_commands.newValue : [];
            renderCommands();
        }
    });

    chrome.runtime.onMessage.addListener((message) => {
        if (message.action === 'newAICommand' || message.action === 'commandsUpdated') {
            loadConsoleCommands();
        }
    });
}

function isBenignConsoleNoiseEntry(command) {
    const combined = [
        String(command && command.command ? command.command : ''),
        String(command && command.analysis ? command.analysis : ''),
        String(command && command.stackHint ? command.stackHint : ''),
        String(command && command.sourceLocation ? command.sourceLocation : '')
    ].join('\n');

    return /react-i18next::\s*useTranslation:\s*You will need to pass in an i18next instance by using initReactI18next/i.test(combined) ||
        /Legal Term Banner:\s*Fetching current user 401/i.test(combined) ||
        (/compliance\.datacamp\.com\/scripts\/terms\.js/i.test(combined) && /Fetching current user 401/i.test(combined));
}

function getVisibleCommands(commands) {
    return Array.isArray(commands)
        ? commands.filter((command) => !isBenignConsoleNoiseEntry(command))
        : [];
}

function ensureConsoleCapture(showFailureNotice) {
    updateCaptureStatus('Attaching live console capture...', 'info');

    chrome.runtime.sendMessage({ action: 'startConsoleCapture' }, (response) => {
        if (chrome.runtime.lastError) {
            updateCaptureStatus('Live capture failed to attach', 'error');
            if (showFailureNotice) {
                showNotification('Console capture could not start', 'error');
            }
            return;
        }

        if (!response || !response.success) {
            updateCaptureStatus(response?.error || 'No inspectable browser tab found', 'error');
            if (showFailureNotice) {
                showNotification(response?.error || 'No inspectable browser tab found', 'error');
            }
            return;
        }

        updateCaptureStatus(`Live capture attached to tab ${response.tabId}. Reload the site page to capture startup warnings.`, 'success');

        if (showFailureNotice) {
            showNotification('Capture attached. Reload the site page for startup warnings.', 'success');
        }
    });
}

function ensureCaptureStatusElement() {
    if (document.getElementById('captureStatus')) {
        return;
    }

    const commandsContainer = document.querySelector('.commands-container');
    if (!commandsContainer || !commandsContainer.parentNode) {
        return;
    }

    const statusElement = document.createElement('div');
    statusElement.id = 'captureStatus';
    statusElement.className = 'capture-status';
    statusElement.textContent = 'Attaching live console capture...';
    commandsContainer.parentNode.insertBefore(statusElement, commandsContainer);
}

function updateCaptureStatus(message, type) {
    const element = document.getElementById('captureStatus');
    if (!element) {
        return;
    }

    element.textContent = message;
    element.className = `capture-status ${type === 'success' ? 'success' : type === 'error' ? 'error' : ''}`.trim();
}

function renderCommands() {
    const visibleCommands = getVisibleCommands(allCommands);
    updateStatistics(visibleCommands);
    displayConsoleCommands(getFilteredCommands(visibleCommands, activeFilter));
}

function displayConsoleCommands(commands) {
    const commandsList = document.getElementById('consoleCommandsList');
    commandsList.innerHTML = '';

    if (commands.length === 0) {
        const emptyMessage = getVisibleCommands(allCommands).length === 0
            ? 'No console commands monitored yet'
            : 'No commands match the selected filter';
        commandsList.innerHTML = `<div class="no-commands">${emptyMessage}</div>`;
        return;
    }

    const sortedCommands = [...commands].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    sortedCommands.forEach((command, index) => {
        const commandElement = createCommandElement(command, index);
        commandsList.appendChild(commandElement);
    });
}

function createCommandElement(command, index) {
    const div = document.createElement('div');
    const normalizedRisk = String(command.riskLevel || '').toLowerCase();
    const riskClass = normalizedRisk ? `risk-${normalizedRisk}` : '';
    const riskIcon = getRiskIcon(command.riskLevel);
    const timeAgo = getTimeAgo(command.timestamp);
    const isBlocked = Boolean(command.blocked);

    div.className = `command-item ${riskClass}`.trim();
    div.dataset.index = String(index);

    div.innerHTML = `
        <div class="command-header">
            <span class="command-type">${escapeHtml(command.type || 'unknown')}</span>
            <span class="command-time">${timeAgo}</span>
            ${riskIcon}
        </div>
        <div class="command-content">
            <pre class="command-text">${escapeHtml(command.command || '')}</pre>
            <div class="command-source">Firewall rule stored for this response.</div>
            ${isBlocked ? `
                <div class="command-blocked">
                    Blocked by firewall: ${escapeHtml(command.blockReason || command.blockRule || 'Policy match')}
                </div>
            ` : ''}
        </div>
        ${command.analysis ? `
            <div class="command-analysis">
                <div class="analysis-header">OpenAI Analysis</div>
                <pre class="analysis-content">${escapeHtml(command.analysis)}</pre>
            </div>
        ` : ''}
    `;

    return div;
}

function getRiskIcon(riskLevel) {
    const icons = {
        LOW: 'LOW',
        MEDIUM: 'MED',
        HIGH: 'HIGH',
        CRITICAL: 'CRIT',
        UNKNOWN: '?'
    };

    if (!riskLevel) {
        return '';
    }

    return `<span class="risk-indicator" title="Risk Level: ${escapeHtml(riskLevel)}">${icons[riskLevel] || icons.UNKNOWN}</span>`;
}

function filterCommands(filter) {
    activeFilter = filter;

    document.querySelectorAll('.filter-btn').forEach((btn) => {
        btn.classList.toggle('active', btn.dataset.filter === filter);
    });

    renderCommands();
}

function getFilteredCommands(commands, filter) {
    if (filter === 'all') {
        return commands;
    }

    return commands.filter((cmd) => {
        switch (filter) {
            case 'high-risk':
                return cmd.riskLevel === 'HIGH' || cmd.riskLevel === 'CRITICAL';
            case 'medium-risk':
                return cmd.riskLevel === 'MEDIUM';
            case 'low-risk':
                return cmd.riskLevel === 'LOW';
            case 'eval':
                return cmd.source === 'eval';
            case 'console':
                return cmd.source === 'console';
            case 'script':
                return cmd.source === 'script' ||
                    cmd.source === 'runtime-error' ||
                    cmd.source === 'unhandledrejection';
            default:
                return true;
        }
    });
}

function updateStatistics(commands) {
    const stats = {
        total: commands.length,
        low: commands.filter((command) => command.riskLevel === 'LOW').length,
        medium: commands.filter((command) => command.riskLevel === 'MEDIUM').length,
        high: commands.filter((command) => command.riskLevel === 'HIGH').length,
        critical: commands.filter((command) => command.riskLevel === 'CRITICAL').length,
        unknown: commands.filter((command) => !command.riskLevel || command.riskLevel === 'UNKNOWN').length
    };

    document.getElementById('totalCommands').textContent = stats.total;
    document.getElementById('lowRiskCommands').textContent = stats.low;
    document.getElementById('mediumRiskCommands').textContent = stats.medium;
    document.getElementById('highRiskCommands').textContent = stats.high + stats.critical;
    document.getElementById('unknownRiskCommands').textContent = stats.unknown;
}

function getTimeAgo(timestamp) {
    const now = new Date();
    const past = new Date(timestamp);
    const diffMs = now - past;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) {
        return 'Just now';
    }

    if (diffMins < 60) {
        return `${diffMins}m ago`;
    }

    if (diffHours < 24) {
        return `${diffHours}h ago`;
    }

    return `${diffDays}d ago`;
}

function getOriginLabel(command) {
    if (command.originType === 'extension') {
        return 'Extension';
    }

    if (command.originType === 'page') {
        return 'Page';
    }

    if (command.captureMethod === 'debugger') {
        return 'Page';
    }

    return 'Unknown';
}

function getSourceLocation(command) {
    if (command.sourceLocation) {
        return command.sourceLocation;
    }

    if (!command.stackHint) {
        return '';
    }

    const lines = String(command.stackHint)
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean);

    for (const line of lines) {
        if (/chrome-extension:\/\//i.test(line) || /console_bridge(?:_main)?\.js/i.test(line)) {
            continue;
        }

        const parenthesizedMatch = line.match(/\(([^)]+)\)$/);
        const directMatch = line.match(/^at\s+(.+)$/);
        return (parenthesizedMatch ? parenthesizedMatch[1] : (directMatch ? directMatch[1] : line)).trim();
    }

    return '';
}

function getStackPreview(stackHint) {
    if (!stackHint) {
        return '';
    }

    const lines = String(stackHint)
        .split('\n')
        .map((line) => line.trimEnd())
        .filter(Boolean)
        .filter((line) => !/chrome-extension:\/\//i.test(line))
        .filter((line) => !/console_bridge(?:_main)?\.js/i.test(line));

    return lines.slice(0, 6).join('\n');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text == null ? '' : String(text);
    return div.innerHTML;
}

function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.remove();
    }, 3000);
}
