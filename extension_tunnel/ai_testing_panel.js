let commands = [];
let autoScroll = true;
let filterType = 'all';
let filterRisk = 'all';
let searchTerm = '';

// Load commands from storage
function loadCommands() {
    console.log('[AI Panel] Loading commands from storage...');
    chrome.storage.local.get(['ai_commands'], (result) => {
        console.log('[AI Panel] Retrieved commands:', result.ai_commands);
        commands = result.ai_commands || [];
        console.log('[AI Panel] Commands array length:', commands.length);
        updateDisplay();
    });
}

// Save commands to storage
function saveCommands() {
    chrome.storage.local.set({ 'ai_commands': commands });
}

// Update display
function updateDisplay() {
    const content = document.getElementById('commandsContent');
    
    // Apply filters
    let filteredCommands = commands.filter(cmd => {
        if (filterType !== 'all' && cmd.type !== filterType) return false;
        if (filterRisk !== 'all' && cmd.riskLevel !== filterRisk.toUpperCase()) return false;
        if (searchTerm && !cmd.command.toLowerCase().includes(searchTerm.toLowerCase())) return false;
        return true;
    });

    // Update stats
    updateStats(filteredCommands);

    // Sort by timestamp (newest first)
    filteredCommands.sort((a, b) => b.timestamp - a.timestamp);

    if (filteredCommands.length === 0) {
        content.innerHTML = `
            <div class="empty-state">
                <h3>🔍 No Commands Found</h3>
                <p>${searchTerm ? 'No commands match your search criteria' : 'AI generated commands will appear here as they are detected'}</p>
            </div>
        `;
        return;
    }

    content.innerHTML = filteredCommands.map(cmd => `
        <div class="command-entry">
            <div class="command-header">
                <div>
                    <span class="command-type ${cmd.type}">${cmd.type}</span>
                    <span class="risk-level ${cmd.riskLevel.toLowerCase()}">${cmd.riskLevel}</span>
                    <span class="command-time">${new Date(cmd.timestamp).toLocaleString()}</span>
                </div>
            </div>
            <div class="command-content">${escapeHtml(cmd.command)}</div>
            ${cmd.analysis ? `
                <div class="command-analysis">
                    <strong>AI Analysis:</strong> ${escapeHtml(cmd.analysis)}
                </div>
            ` : ''}
            <div class="command-meta">
                <span>Source: ${cmd.source || 'Unknown'}</span>
                ${cmd.domain ? `<span>Domain: ${cmd.domain}</span>` : ''}
                ${cmd.blocked ? '<span style="color: #dc3545;">⚠️ BLOCKED</span>' : ''}
            </div>
        </div>
    `).join('');

    // Auto scroll to bottom if enabled
    if (autoScroll) {
        content.scrollTop = content.scrollHeight;
    }
}

// Update statistics
function updateStats(filteredCommands) {
    document.getElementById('totalCommands').textContent = filteredCommands.length;
    document.getElementById('highRiskCommands').textContent = 
        filteredCommands.filter(cmd => cmd.riskLevel === 'HIGH' || cmd.riskLevel === 'CRITICAL').length;
    document.getElementById('blockedCommands').textContent = 
        filteredCommands.filter(cmd => cmd.blocked).length;
    document.getElementById('commandCount').textContent = `${filteredCommands.length} commands`;
    
    const lastCmd = filteredCommands[0];
    document.getElementById('lastUpdate').textContent = 
        lastCmd ? new Date(lastCmd.timestamp).toLocaleTimeString() : 'Never';
}

// Escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Event listeners
document.getElementById('refreshBtn').addEventListener('click', loadCommands);

document.getElementById('viewRulesBtn').addEventListener('click', () => {
    console.log('[AI Panel] View Rules button clicked');
    chrome.runtime.sendMessage({ action: 'openBrowserControl', tab: 'rules' });
});

document.getElementById('testBtn').addEventListener('click', () => {
    console.log('[AI Panel] Test button clicked');
    // Create a test command entry
    const testCommand = {
        id: Date.now() + Math.random(),
        timestamp: Date.now(),
        command: 'console.log("Test command from AI Panel")',
        type: 'log',
        analysis: 'RISK_LEVEL: LOW\nTHREAT_TYPE: UNKNOWN\nDESCRIPTION: Test command for debugging\nRECOMMENDATION: Command appears safe',
        riskLevel: 'LOW',
        source: 'test',
        domain: 'localhost',
        url: 'http://localhost',
        blocked: false,
        fallback: false
    };
    
    commands.push(testCommand);
    saveCommands();
    updateDisplay();
    console.log('[AI Panel] Test command added:', testCommand);
});

document.getElementById('clearBtn').addEventListener('click', () => {
    if (confirm('Are you sure you want to clear all commands?')) {
        commands = [];
        saveCommands();
        updateDisplay();
    }
});

document.getElementById('autoScrollBtn').addEventListener('click', function() {
    autoScroll = !autoScroll;
    this.textContent = `📍 Auto Scroll: ${autoScroll ? 'ON' : 'OFF'}`;
    this.style.background = autoScroll ? '#667eea' : '#6c757d';
});

document.getElementById('typeFilter').addEventListener('change', (e) => {
    filterType = e.target.value;
    updateDisplay();
});

document.getElementById('riskFilter').addEventListener('change', (e) => {
    filterRisk = e.target.value;
    updateDisplay();
});

document.getElementById('searchInput').addEventListener('input', (e) => {
    searchTerm = e.target.value;
    updateDisplay();
});

document.getElementById('exportBtn').addEventListener('click', () => {
    const dataStr = JSON.stringify(commands, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    
    const exportFileDefaultName = `ai_commands_${new Date().toISOString().split('T')[0]}.json`;
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
});

document.getElementById('exportCsvBtn').addEventListener('click', () => {
    let csv = 'Timestamp,Type,Command,Risk Level,Analysis,Source,Domain,Blocked\n';
    commands.forEach(cmd => {
        csv += `"${new Date(cmd.timestamp).toISOString()}","${cmd.type}","${cmd.command.replace(/"/g, '""')}","${cmd.riskLevel}","${(cmd.analysis || '').replace(/"/g, '""')}","${cmd.source || ''}","${cmd.domain || ''}","${cmd.blocked || false}"\n`;
    });
    
    const dataUri = 'data:text/csv;charset=utf-8,'+ encodeURIComponent(csv);
    const exportFileDefaultName = `ai_commands_${new Date().toISOString().split('T')[0]}.csv`;
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
});

// Listen for new commands from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('[AI Panel] Message received:', message);
    
    if (message.action === 'newAICommand') {
        console.log('[AI Panel] New command detected:', message.command);
        commands.push(message.command);
        saveCommands();
        updateDisplay();
        sendResponse({ success: true });
    } else if (message.action === 'commandsUpdated') {
        console.log('[AI Panel] Commands updated, refreshing...');
        loadCommands();
        sendResponse({ success: true });
    }
});

// Also listen for storage changes (in case commands are added from other sources)
chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'ai_commands') {
        console.log('[AI Panel] Storage changed, reloading commands...');
        loadCommands();
    }
});

// Initial load
loadCommands();

// Auto-refresh every 5 seconds
setInterval(loadCommands, 5000);
