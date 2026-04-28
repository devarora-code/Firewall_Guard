(function() {
    const EVENT_SOURCE = 'firewall-guard-console-bridge';
    const POLICY_UPDATE_SOURCE = 'firewall-guard-console-policy-update';
    const READY_SOURCE = 'firewall-guard-console-ready';
    const SEARCH_FETCH_REQUEST_SOURCE = 'firewall-guard-search-fetch-request';
    const SEARCH_FETCH_RESPONSE_SOURCE = 'firewall-guard-search-fetch-response';
    const SEARCH_FETCH_READY_SOURCE = 'firewall-guard-search-fetch-ready';
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
                reason: 'Sensitive data exfiltration pattern'
            },
            {
                id: 'dom-script-injection',
                appliesTo: ['eval', 'function', 'domWrite', 'htmlInsert', 'open'],
                pattern: '(?:document\\.write|insertAdjacentHTML|innerHTML|outerHTML|window\\.open).*?(?:<script|javascript:|data:text/html|onerror\\s*=|onload\\s*=)|(?:<script|javascript:|data:text/html|onerror\\s*=|onload\\s*=)',
                severity: 'HIGH',
                reason: 'DOM or script injection pattern'
            },
            {
                id: 'dangerous-storage-write',
                appliesTo: ['storage', 'eval', 'function'],
                pattern: '(?:localStorage|sessionStorage)\\.(?:setItem|removeItem|clear).*?(?:token|cookie|script|javascript:|data:text/html|onerror\\s*=|onload\\s*=)',
                severity: 'HIGH',
                reason: 'Dangerous storage manipulation pattern'
            },
            {
                id: 'dangerous-protocol-network',
                appliesTo: ['fetch', 'xhr', 'beacon', 'open', 'eval', 'function'],
                pattern: 'javascript:|data:text/html|data:application/javascript|vbscript:',
                severity: 'HIGH',
                reason: 'Dangerous protocol or payload pattern'
            }
        ]
    };

    function buildDefaultPolicy() {
        return {
            ...DEFAULT_CONSOLE_FIREWALL_POLICY,
            rules: Array.isArray(DEFAULT_CONSOLE_FIREWALL_POLICY.rules)
                ? DEFAULT_CONSOLE_FIREWALL_POLICY.rules.map((rule) => ({ ...rule }))
                : []
        };
    }

    function clonePolicy(policy) {
        try {
            return JSON.parse(JSON.stringify(policy));
        } catch (error) {
            return buildDefaultPolicy();
        }
    }

    function safeBridgeCall(callback, fallbackValue) {
        try {
            return callback();
        } catch (error) {
            if (typeof fallbackValue === 'function') {
                try {
                    return fallbackValue(error);
                } catch (fallbackError) {
                    return undefined;
                }
            }

            return fallbackValue;
        }
    }

    function safeStringify(value) {
        try {
            return JSON.stringify(value);
        } catch (error) {
            return '';
        }
    }

    function sanitizeRule(rule, fallbackRule = {}) {
        const nextRule = rule && typeof rule === 'object' ? rule : {};
        const baseRule = fallbackRule && typeof fallbackRule === 'object' ? fallbackRule : {};
        const sanitizedRule = {
            ...baseRule,
            ...nextRule,
            id: typeof nextRule.id === 'string'
                ? nextRule.id
                : String(baseRule.id || ''),
            appliesTo: Array.isArray(nextRule.appliesTo)
                ? nextRule.appliesTo.filter((entry) => typeof entry === 'string')
                : (Array.isArray(baseRule.appliesTo)
                    ? baseRule.appliesTo.filter((entry) => typeof entry === 'string')
                    : []),
            pattern: typeof nextRule.pattern === 'string'
                ? nextRule.pattern
                : (typeof baseRule.pattern === 'string' ? baseRule.pattern : ''),
            severity: typeof nextRule.severity === 'string'
                ? nextRule.severity
                : (typeof baseRule.severity === 'string' ? baseRule.severity : 'UNKNOWN'),
            reason: typeof nextRule.reason === 'string'
                ? nextRule.reason
                : (typeof baseRule.reason === 'string' ? baseRule.reason : '')
        };

        if (typeof nextRule.block === 'boolean') {
            sanitizedRule.block = nextRule.block;
        } else if (typeof baseRule.block === 'boolean') {
            sanitizedRule.block = baseRule.block;
        }

        return sanitizedRule;
    }

    function normalizePolicy(policy) {
        return safeBridgeCall(() => {
            const defaults = clonePolicy(DEFAULT_CONSOLE_FIREWALL_POLICY);
            const nextPolicy = policy && typeof policy === 'object' ? policy : {};
            const mergedRules = new Map();

            defaults.rules.forEach((rule) => {
                if (rule && rule.id) {
                    mergedRules.set(rule.id, sanitizeRule(rule));
                }
            });

            if (Array.isArray(nextPolicy.rules)) {
                nextPolicy.rules.forEach((rule) => {
                    if (!rule || typeof rule !== 'object' || !rule.id) {
                        return;
                    }

                    const defaultRule = mergedRules.get(rule.id) || {};
                    mergedRules.set(rule.id, sanitizeRule(rule, defaultRule));
                });
            }

            return {
                version: nextPolicy.version !== undefined ? nextPolicy.version : defaults.version,
                mode: typeof nextPolicy.mode === 'string' ? nextPolicy.mode : defaults.mode,
                updatedAt: typeof nextPolicy.updatedAt === 'string' ? nextPolicy.updatedAt : defaults.updatedAt,
                rules: Array.from(mergedRules.values())
            };
        }, buildDefaultPolicy());
    }

    function invokeCallback(callback, value) {
        if (typeof callback === 'function') {
            safeBridgeCall(() => callback(value), null);
        }
    }

    function ensureStoredPolicy(callback) {
        safeBridgeCall(() => {
            chrome.storage.local.get(['console_firewall_policy'], (result) => {
                const nextResult = result && typeof result === 'object' ? result : {};
                const policy = normalizePolicy(nextResult.console_firewall_policy);

                if (safeStringify(nextResult.console_firewall_policy || null) !== safeStringify(policy)) {
                    safeBridgeCall(() => {
                        chrome.storage.local.set({ 'console_firewall_policy': policy }, () => {
                            void chrome.runtime.lastError;
                            invokeCallback(callback, policy);
                        });
                    }, () => invokeCallback(callback, policy));
                    return;
                }

                invokeCallback(callback, policy);
            });
        }, () => invokeCallback(callback, normalizePolicy(null)));
    }

    function forwardToBackground(command) {
        try {
            chrome.runtime.sendMessage({
                action: 'consoleCommandCaptured',
                command: command
            }, () => {
                void chrome.runtime.lastError;
            });
        } catch (error) {
            // Ignore extension teardown errors.
        }
    }

    function postPolicyUpdate(policy) {
        safeBridgeCall(() => {
            window.postMessage({
                source: POLICY_UPDATE_SOURCE,
                policy: normalizePolicy(policy)
            }, '*');
        }, null);
    }

    function postReadySignal() {
        safeBridgeCall(() => {
            window.postMessage({
                source: READY_SOURCE
            }, '*');
        }, null);
    }

    function requestMainWorldInjection(policy) {
        safeBridgeCall(() => {
            chrome.runtime.sendMessage({ action: 'ensureMainWorldConsoleBridge' }, () => {
                void chrome.runtime.lastError;
                postReadySignal();
                postPolicyUpdate(policy);

                // Retry once shortly after injection so the main-world listener
                // definitely receives the policy on slower pages.
                setTimeout(() => {
                    safeBridgeCall(() => {
                        postReadySignal();
                        postPolicyUpdate(policy);
                    }, null);
                }, 150);
            });
        }, () => {
            postReadySignal();
            postPolicyUpdate(policy);
        });
    }

    function isSearchBridgePage() {
        return safeBridgeCall(() => {
            const host = window.location.hostname;
            const port = window.location.port;
            return (host === 'localhost' || host === '127.0.0.1') && port === '4000';
        }, false);
    }

    function postSearchFetchResponse(payload) {
        safeBridgeCall(() => {
            window.postMessage({
                source: SEARCH_FETCH_RESPONSE_SOURCE,
                ...payload
            }, '*');
        }, null);
    }

    function postSearchBridgeReady() {
        safeBridgeCall(() => {
            document.documentElement.setAttribute('data-firewall-guard-search-bridge', 'ready');
            window.postMessage({
                source: SEARCH_FETCH_READY_SOURCE
            }, '*');
        }, null);
    }

    window.addEventListener('message', (event) => {
        safeBridgeCall(() => {
            if (event.source !== window) {
                return;
            }

            if (
                isSearchBridgePage() &&
                event.data &&
                event.data.source === SEARCH_FETCH_REQUEST_SOURCE &&
                event.data.requestId
            ) {
                chrome.runtime.sendMessage({
                    action: 'searchFetchPageHtml',
                    url: event.data.url
                }, (response) => {
                    const runtimeError = chrome.runtime.lastError;

                    if (runtimeError) {
                        postSearchFetchResponse({
                            requestId: event.data.requestId,
                            success: false,
                            error: runtimeError.message || 'Extension bridge unavailable'
                        });
                        return;
                    }

                    postSearchFetchResponse({
                        requestId: event.data.requestId,
                        ...(response && typeof response === 'object'
                            ? response
                            : { success: false, error: 'No response from background service worker' })
                    });
                });
                return;
            }

            if (!event.data || event.data.source !== EVENT_SOURCE || !event.data.payload) {
                return;
            }

            forwardToBackground(event.data.payload);
        }, null);
    });

    chrome.storage.onChanged.addListener((changes, namespace) => {
        safeBridgeCall(() => {
            if (namespace === 'local' && changes.console_firewall_policy) {
                postPolicyUpdate(normalizePolicy(changes.console_firewall_policy.newValue));
            }
        }, null);
    });

    safeBridgeCall(() => {
        postReadySignal();
        if (isSearchBridgePage()) {
            postSearchBridgeReady();
        }

        ensureStoredPolicy((policy) => {
            requestMainWorldInjection(policy);
        });
    }, null);
})();
