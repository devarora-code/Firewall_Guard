(function() {
    const EVENT_SOURCE = 'firewall-guard-console-bridge';
    const POLICY_UPDATE_SOURCE = 'firewall-guard-console-policy-update';
    const READY_SOURCE = 'firewall-guard-console-ready';
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

    const rawPostMessage = window.postMessage.bind(window);

    if (window.__firewallGuardConsoleBridgeInstalled) {
        return;
    }

    window.__firewallGuardConsoleBridgeInstalled = true;

    let activePolicy = DEFAULT_CONSOLE_FIREWALL_POLICY;
    let compiledRules = [];
    let contentBridgeReady = false;
    const pendingPayloads = [];

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

    function compilePolicyRules(policy) {
        const compiled = [];

        for (const rule of Array.isArray(policy && policy.rules) ? policy.rules : []) {
            if (!rule || typeof rule !== 'object' || !rule.id || !rule.pattern) {
                continue;
            }

            try {
                compiled.push({
                    ...rule,
                    regex: new RegExp(rule.pattern, 'i')
                });
            } catch (error) {
                // Ignore malformed dynamic rules instead of breaking the bridge.
            }
        }

        return compiled;
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

    function updatePolicy(nextPolicy) {
        safeBridgeCall(() => {
            const defaults = clonePolicy(DEFAULT_CONSOLE_FIREWALL_POLICY);
            const sourcePolicy = nextPolicy && typeof nextPolicy === 'object'
                ? nextPolicy
                : {};
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

            activePolicy = {
                ...defaults,
                ...sourcePolicy,
                version: sourcePolicy.version || defaults.version,
                rules: Array.from(mergedRules.values())
            };

            compiledRules = compilePolicyRules(activePolicy);
        }, null);
    }

    function safeSerialize(value) {
        if (typeof value === 'string') {
            return value;
        }

        if (value === undefined) {
            return 'undefined';
        }

        if (value === null) {
            return 'null';
        }

        if (value instanceof Error) {
            const errorName = value.name ? `${value.name}: ` : '';
            return `${errorName}${value.message || String(value)}`;
        }

        if (typeof DOMException !== 'undefined' && value instanceof DOMException) {
            const exceptionName = value.name ? `${value.name}: ` : '';
            return `${exceptionName}${value.message || String(value)}`;
        }

        if (typeof value === 'object' &&
            typeof value.name === 'string' &&
            typeof value.message === 'string' &&
            value.name) {
            return `${value.name}: ${value.message}`;
        }

        try {
            return JSON.stringify(value);
        } catch (error) {
            return String(value);
        }
    }

    function buildCommand(args) {
        return safeBridgeCall(() => Array.from(args).map(safeSerialize).join(', '), '');
    }

    function normalizeStack(stack, skipLines = 0) {
        if (!stack) {
            return '';
        }

        const lines = String(stack)
            .split('\n')
            .map((line) => line.trimEnd())
            .filter(Boolean);

        return lines.slice(skipLines).join('\n');
    }

    function captureStack(skipLines = 2) {
        try {
            throw new Error();
        } catch (error) {
            return normalizeStack(error.stack || '', skipLines);
        }
    }

    function isConsoleLikeStack(stack) {
        return /(debugger eval code|VM\d+(?::\d+)?|eval at|at eval)/i.test(stack || '');
    }

    function buildTraceCommand(args, stack) {
        const message = args.length ? buildCommand(args) : 'console.trace()';
        return stack ? `${message}\n${stack}` : message;
    }

    function buildRuntimeErrorCommand(event) {
        const target = event && event.target && event.target !== window ? event.target : null;
        const targetName = target && target.tagName ? target.tagName.toLowerCase() : '';
        const location = [
            event && event.filename ? event.filename : '',
            event && event.lineno ? event.lineno : '',
            event && event.colno ? event.colno : ''
        ].filter(Boolean).join(':');
        const resourceLocation = target ? (target.src || target.href || '') : '';
        const message = event && event.message
            ? event.message
            : (targetName ? `Resource load failure: ${targetName}` : 'Unknown runtime error');
        const stack = event && event.error && event.error.stack
            ? normalizeStack(event.error.stack)
            : '';

        return [
            `RuntimeError: ${message}`,
            location ? `Location: ${location}` : '',
            resourceLocation ? `Resource: ${resourceLocation}` : '',
            stack
        ].filter(Boolean).join('\n');
    }

    function buildRejectionCommand(reason) {
        if (reason && typeof reason === 'object') {
            const errorName = reason.name ? `${reason.name}: ` : '';
            const errorMessage = reason.message || safeSerialize(reason);
            const stack = reason.stack ? normalizeStack(reason.stack) : '';

            return [
                `UnhandledRejection: ${errorName}${errorMessage}`,
                stack
            ].filter(Boolean).join('\n');
        }

        return `UnhandledRejection: ${safeSerialize(reason)}`;
    }

    function collectNoiseCandidates(value, candidates, depth = 0) {
        if (!candidates || depth > 2 || value === undefined || value === null) {
            return;
        }

        if (typeof value === 'string') {
            candidates.push(value);
            return;
        }

        if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
            candidates.push(String(value));
            return;
        }

        if (value instanceof Error) {
            candidates.push(safeSerialize(value));
            if (typeof value.message === 'string') {
                candidates.push(value.message);
            }
            if (typeof value.stack === 'string') {
                candidates.push(value.stack);
            }
            return;
        }

        if (typeof DOMException !== 'undefined' && value instanceof DOMException) {
            candidates.push(safeSerialize(value));
            if (typeof value.message === 'string') {
                candidates.push(value.message);
            }
            return;
        }

        if (Array.isArray(value)) {
            value.slice(0, 10).forEach((entry) => collectNoiseCandidates(entry, candidates, depth + 1));
            return;
        }

        if (typeof value === 'object') {
            if (typeof value.name === 'string' && typeof value.message === 'string') {
                candidates.push(`${value.name}: ${value.message}`);
                candidates.push(value.message);
            }

            if (typeof value.stack === 'string') {
                candidates.push(value.stack);
            }

            ['error', 'reason', 'message', 'description'].forEach((key) => {
                if (Object.prototype.hasOwnProperty.call(value, key)) {
                    collectNoiseCandidates(value[key], candidates, depth + 1);
                }
            });
        }
    }

    function matchesBenignNoisePattern(text) {
        const normalized = String(text || '');

        return /\[GSI_LOGGER\]:\s*FedCM get\(\) rejects with NetworkError: Error retrieving a token\.?/i.test(normalized) ||
            /Unable to determine state status TypeError:\s*Cannot read properties of undefined\s*\(reading ['"]nodeName['"]\)/i.test(normalized) ||
            (/Track&Report JS errors API/i.test(normalized) && /Late loading module @m\/mash/i.test(normalized)) ||
            /getItem\s*->\s*Error in getting item from indexedDB:?.*Object store\s+["'`A-Za-z0-9_ -]+\s+does not exist/i.test(normalized) ||
            /Object store\s+["'`A-Za-z0-9_ -]+\s+does not exist/i.test(normalized) ||
            /Nothing to see here,\s*move along\./i.test(normalized) ||
            /react-i18next::\s*useTranslation:\s*You will need to pass in an i18next instance by using initReactI18next/i.test(normalized) ||
            /Legal Term Banner:\s*Fetching current user 401/i.test(normalized) ||
            /\[DEPRECATED\]\s*Default export is deprecated\.\s*Instead use\s*`?import\s*\{\s*create\s*\}\s*from\s*['"]zustand['"]`?/i.test(normalized) ||
            /\[DEPRECATED\]\s*`?getStorage`?,\s*`?serialize`?\s*and\s*`?deserialize`?\s*options are deprecated\.\s*Use\s*`?storage`?\s*option instead\./i.test(normalized) ||
            /\[COMPLETION\]\s*Failed all attempts to invalidate conversation tree/i.test(normalized);
    }

    function containsBenignNoise(values = [], meta = {}) {
        const candidates = [];

        if (Array.isArray(values)) {
            values.forEach((value) => collectNoiseCandidates(value, candidates));
        } else {
            collectNoiseCandidates(values, candidates);
        }

        [
            meta.command,
            meta.serializedArgs,
            meta.stackHint,
            meta.filename
        ].forEach((value) => collectNoiseCandidates(value, candidates));

        return candidates.some((candidate) => matchesBenignNoisePattern(candidate));
    }

    function isBenignBrowserNoise(command, args = [], meta = {}) {
        return containsBenignNoise([command].concat(Array.isArray(args) ? args : []), meta);
    }

    function isBenignFrameworkNoise(command, meta = {}) {
        return containsBenignNoise([command].concat(Array.isArray(meta.rawArgs) ? meta.rawArgs : []), meta);
    }

    function shouldSuppressCapturedEvent(type, command, meta = {}) {
        const rawArgs = Array.isArray(meta.rawArgs) ? meta.rawArgs : [];

        if (isBenignBrowserNoise(command, rawArgs, meta) || isBenignFrameworkNoise(command, {
            ...meta,
            rawArgs: rawArgs
        })) {
            return true;
        }

        if (type === 'runtime-error' || type === 'unhandledrejection') {
            const combined = [
                String(command || ''),
                String(meta.stackHint || ''),
                String(meta.filename || '')
            ].join('\n');

            if (/compliance\.datacamp\.com\/scripts\/terms\.js/i.test(combined) &&
                /Fetching current user 401/i.test(combined)) {
                return true;
            }
        }

        return false;
    }

    function shouldSuppressConsoleOutput(command, args = []) {
        return shouldSuppressCapturedEvent('console', command, {
            rawArgs: Array.isArray(args) ? args : [],
            serializedArgs: Array.isArray(args)
                ? args.map((value) => safeSerialize(value)).join(', ')
                : ''
        });
    }

    function shouldMirrorConsoleOutput(method, command, args = [], meta = {}) {
        return !shouldSuppressCapturedEvent('console', command, {
            rawArgs: Array.isArray(args) ? args : [],
            serializedArgs: Array.isArray(args)
                ? args.map((value) => safeSerialize(value)).join(', ')
                : '',
            stackHint: meta.stackHint || '',
            filename: meta.filename || ''
        });
    }

    function shouldSkip(command) {
        return !command ||
            command.startsWith('[Firewall Guard]') ||
            command.startsWith('[Console Monitor]') ||
            shouldSuppressCapturedEvent('console', command);
    }

    function emit(type, command, source, extra = {}) {
        if (shouldSkip(command) && !extra.blocked) {
            return;
        }

        const payload = {
            source: EVENT_SOURCE,
            payload: {
                id: Date.now() + Math.random(),
                type: type,
                command: command,
                source: source,
                captureMethod: 'bridge',
                url: window.location.href,
                timestamp: new Date().toISOString(),
                domain: window.location.hostname,
                ...extra
            }
        };

        safeBridgeCall(() => {
            if (!contentBridgeReady) {
                pendingPayloads.push(payload);
                if (pendingPayloads.length > 200) {
                    pendingPayloads.shift();
                }
                return;
            }

            rawPostMessage(payload, '*');
        }, null);
    }

    function flushPendingPayloads() {
        safeBridgeCall(() => {
            while (pendingPayloads.length > 0) {
                rawPostMessage(pendingPayloads[0], '*');
                pendingPayloads.shift();
            }
        }, null);
    }

    function findBlockingRule(source, command, stack) {
        const enforce = isConsoleLikeStack(stack);
        if (!enforce) {
            return null;
        }

        return compiledRules.find((rule) => {
            const applies = !rule.appliesTo || rule.appliesTo.includes(source);
            return rule.block !== false && applies && rule.regex && rule.regex.test(command);
        }) || null;
    }

    function buildBlockedPayload(stack, rule) {
        return {
            blocked: true,
            blockReason: rule.reason,
            blockRule: rule.id,
            blockSeverity: rule.severity,
            stackHint: stack
        };
    }

    function createBlockedError(rule) {
        const error = new Error(`Firewall Guard blocked dangerous console activity: ${rule.reason}`);
        error.name = 'FirewallGuardBlockedError';
        error.firewallGuardBlocked = true;
        error.firewallGuardReason = rule && rule.reason ? rule.reason : '';
        error.firewallGuardRuleId = rule && rule.id ? rule.id : '';
        return error;
    }

    function isBlockedFirewallGuardError(value) {
        if (!value) {
            return false;
        }

        return value.firewallGuardBlocked === true ||
            value.name === 'FirewallGuardBlockedError' ||
            /Firewall Guard blocked dangerous console activity/i.test(String(value.message || value));
    }

    function buildBlockedResponse(rule) {
        return safeBridgeCall(() => {
            if (typeof Response !== 'function') {
                return {
                    ok: false,
                    status: 403,
                    statusText: 'Firewall Guard Blocked',
                    text: () => Promise.resolve(`Firewall Guard blocked request: ${rule.reason}`),
                    json: () => Promise.resolve({
                        error: 'firewall_guard_blocked',
                        reason: rule.reason,
                        rule: rule.id
                    })
                };
            }

            return new Response(`Firewall Guard blocked request: ${rule.reason}`, {
                status: 403,
                statusText: 'Firewall Guard Blocked',
                headers: {
                    'Content-Type': 'text/plain; charset=utf-8',
                    'X-Firewall-Guard-Blocked': '1'
                }
            });
        }, {
            ok: false,
            status: 403,
            statusText: 'Firewall Guard Blocked',
            text: () => Promise.resolve(`Firewall Guard blocked request: ${rule.reason}`),
            json: () => Promise.resolve({
                error: 'firewall_guard_blocked',
                reason: rule.reason,
                rule: rule.id
            })
        });
    }

    function buildBlockedFunction(rule) {
        const blockedFunction = function FirewallGuardBlockedFunction() {
            return undefined;
        };

        try {
            Object.defineProperty(blockedFunction, 'name', {
                configurable: true,
                value: 'FirewallGuardBlockedFunction'
            });
        } catch (error) {
            // Ignore read-only name assignment failures.
        }

        blockedFunction.firewallGuardBlocked = true;
        blockedFunction.firewallGuardReason = rule && rule.reason ? rule.reason : '';
        blockedFunction.firewallGuardRuleId = rule && rule.id ? rule.id : '';
        return blockedFunction;
    }

    function dispatchBlockedXhrEvents(xhr, rule) {
        const detail = {
            blocked: true,
            reason: rule && rule.reason ? rule.reason : '',
            ruleId: rule && rule.id ? rule.id : ''
        };

        try {
            Object.defineProperty(xhr, 'readyState', {
                configurable: true,
                value: 4
            });
        } catch (error) {
            // Ignore read-only property failures.
        }

        try {
            Object.defineProperty(xhr, 'status', {
                configurable: true,
                value: 0
            });
        } catch (error) {
            // Ignore read-only property failures.
        }

        try {
            Object.defineProperty(xhr, 'statusText', {
                configurable: true,
                value: 'Firewall Guard Blocked'
            });
        } catch (error) {
            // Ignore read-only property failures.
        }

        try {
            Object.defineProperty(xhr, 'responseText', {
                configurable: true,
                value: ''
            });
        } catch (error) {
            // Ignore read-only property failures.
        }

        setTimeout(() => {
            ['readystatechange', 'error', 'loadend'].forEach((eventName) => {
                try {
                    xhr.dispatchEvent(new Event(eventName));
                } catch (error) {
                    // Ignore dispatch failures.
                }
            });

            if (typeof xhr.onreadystatechange === 'function') {
                try {
                    xhr.onreadystatechange(new Event('readystatechange'));
                } catch (error) {
                    // Ignore handler failures.
                }
            }

            if (typeof xhr.onerror === 'function') {
                try {
                    xhr.onerror(new CustomEvent('error', { detail: detail }));
                } catch (error) {
                    // Ignore handler failures.
                }
            }

            if (typeof xhr.onloadend === 'function') {
                try {
                    xhr.onloadend(new CustomEvent('loadend', { detail: detail }));
                } catch (error) {
                    // Ignore handler failures.
                }
            }
        }, 0);
    }

    function handleBlockedAction(type, command, source, stack, rule, fallbackValue) {
        emit(type, command, source, buildBlockedPayload(stack, rule));
        return fallbackValue;
    }

    window.addEventListener('message', (event) => {
        safeBridgeCall(() => {
        if (event.source !== window || !event.data) {
            return;
        }

        if (event.data.source === READY_SOURCE) {
            contentBridgeReady = true;
            flushPendingPayloads();

            return;
        }

        if (event.data.source === POLICY_UPDATE_SOURCE && event.data.policy) {
            updatePolicy(event.data.policy);
        }
        }, null);
    });

    updatePolicy(activePolicy);

    const originalConsole = {
        log: console.log,
        warn: console.warn,
        error: console.error,
        info: console.info,
        debug: console.debug,
        trace: console.trace
    };

    function isFastPathBenignNoise(args) {
        try {
            const text = Array.from(args).map(function(a) {
                if (typeof a === 'string') { return a; }
                if (a && typeof a.message === 'string') { return a.message; }
                try { return String(a); } catch (e) { return ''; }
            }).join(' ');
            return /Object store .+ does not exist/i.test(text) ||
                /getItem.*indexedDB/i.test(text) ||
                /\[DEPRECATED\].*zustand/i.test(text) ||
                /\[DEPRECATED\].*getStorage/i.test(text) ||
                /\[COMPLETION\].*conversation tree/i.test(text) ||
                /Nothing to see here.*move along/i.test(text) ||
                /react-i18next.*useTranslation/i.test(text) ||
                /Legal Term Banner.*Fetching current user 401/i.test(text) ||
                /\[GSI_LOGGER\].*FedCM/i.test(text) ||
                /Unable to determine state status TypeError/i.test(text);
        } catch (e) {
            return false;
        }
    }

    ['log', 'warn', 'error', 'info', 'debug', 'trace'].forEach((method) => {
        console[method] = function(...args) {
            try {
                if (isFastPathBenignNoise(args)) {
                    return;
                }
            } catch (e) {
                // Ignore errors in the fast-path check and continue.
            }

            return safeBridgeCall(() => {
                if (shouldSuppressConsoleOutput('', args)) {
                    return;
                }

                if (method === 'trace') {
                    const traceStack = captureStack(2);
                    const traceCommand = buildTraceCommand(args, traceStack);
                    if (!shouldMirrorConsoleOutput(method, traceCommand, args, { stackHint: traceStack })) {
                        return;
                    }
                    originalConsole[method].apply(console, args);
                    emit('trace', traceCommand, 'console', {
                        stackHint: traceStack
                    });
                    return;
                }

                const command = buildCommand(args);
                if (!shouldMirrorConsoleOutput(method, command, args)) {
                    return;
                }

                originalConsole[method].apply(console, args);
                emit(method, command, 'console');
            }, () => {
                try {
                    if (isFastPathBenignNoise(args)) {
                        return;
                    }
                } catch (e) {
                    // Ignore errors in the fallback fast-path check.
                }
                return originalConsole[method].apply(console, args);
            });
        };
    });

    window.addEventListener('error', (event) => {
        safeBridgeCall(() => {
            if (isBlockedFirewallGuardError(event && event.error)) {
                if (event.cancelable) {
                    event.preventDefault();
                }
                event.stopImmediatePropagation();
                return;
            }

            const command = buildRuntimeErrorCommand(event);
            const stackHint = event && event.error && event.error.stack
                ? normalizeStack(event.error.stack)
                : '';
            const filename = event && event.filename ? event.filename : '';

            if (!command ||
                /Firewall Guard blocked dangerous console activity/i.test(command) ||
                shouldSuppressCapturedEvent('runtime-error', command, {
                    stackHint: stackHint,
                    filename: filename
                })) {
                return;
            }

            emit('runtime-error', command, 'runtime-error', {
                stackHint: stackHint,
                filename: filename,
                lineNumber: event && event.lineno ? event.lineno : 0,
                columnNumber: event && event.colno ? event.colno : 0
            });
        }, null);
    }, true);

    window.addEventListener('unhandledrejection', (event) => {
        safeBridgeCall(() => {
            if (isBlockedFirewallGuardError(event ? event.reason : null)) {
                if (event.cancelable) {
                    event.preventDefault();
                }
                event.stopImmediatePropagation();
                return;
            }

            const command = buildRejectionCommand(event ? event.reason : undefined);
            const stackHint = event && event.reason && event.reason.stack
                ? normalizeStack(event.reason.stack)
                : '';

            if (!command ||
                /Firewall Guard blocked dangerous console activity/i.test(command) ||
                shouldSuppressCapturedEvent('unhandledrejection', command, {
                    stackHint: stackHint
                })) {
                return;
            }

            emit('unhandledrejection', command, 'unhandledrejection', {
                stackHint: stackHint
            });
        }, null);
    }, true);

    const originalEval = window.eval;
    window.eval = function(code) {
        const command = `eval(${safeSerialize(code)})`;
        const stack = captureStack();
        const consoleInvocation = isConsoleLikeStack(stack);
        const rule = findBlockingRule('eval', command, stack);

        if (rule) {
            return handleBlockedAction('eval', command, 'eval', stack, rule, undefined);
        }

        if (consoleInvocation) {
            emit('eval', command, 'eval');
        }
        return originalEval.call(this, code);
    };

    const OriginalFunction = window.Function;
    const WrappedFunction = function(...args) {
        const command = `Function(${buildCommand(args)})`;
        const stack = captureStack();
        const consoleInvocation = isConsoleLikeStack(stack);
        const rule = findBlockingRule('function', command, stack);

        if (rule) {
            return handleBlockedAction('function', command, 'function', stack, rule, buildBlockedFunction(rule));
        }

        if (consoleInvocation) {
            emit('function', command, 'function');
        }
        return OriginalFunction.apply(this, args);
    };

    WrappedFunction.prototype = OriginalFunction.prototype;
    window.Function = WrappedFunction;

    const originalWrite = document.write.bind(document);
    document.write = function(...args) {
        const command = `document.write(${buildCommand(args)})`;
        const stack = captureStack();
        const rule = findBlockingRule('domWrite', command, stack);

        if (rule) {
            return handleBlockedAction('domWrite', command, 'domWrite', stack, rule, undefined);
        }

        if (isConsoleLikeStack(stack)) {
            emit('domWrite', command, 'domWrite');
        }

        return originalWrite(...args);
    };

    const originalWriteln = document.writeln ? document.writeln.bind(document) : null;
    if (originalWriteln) {
        document.writeln = function(...args) {
            const command = `document.writeln(${buildCommand(args)})`;
            const stack = captureStack();
            const rule = findBlockingRule('domWrite', command, stack);

            if (rule) {
                return handleBlockedAction('domWrite', command, 'domWrite', stack, rule, undefined);
            }

            if (isConsoleLikeStack(stack)) {
                emit('domWrite', command, 'domWrite');
            }

            return originalWriteln(...args);
        };
    }

    if (window.Element && Element.prototype.insertAdjacentHTML) {
        const originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
        Element.prototype.insertAdjacentHTML = function(position, text) {
            const command = `insertAdjacentHTML(${safeSerialize(position)}, ${safeSerialize(text)})`;
            const stack = captureStack();
            const rule = findBlockingRule('htmlInsert', command, stack);

            if (rule) {
                return handleBlockedAction('htmlInsert', command, 'htmlInsert', stack, rule, undefined);
            }

            if (isConsoleLikeStack(stack)) {
                emit('htmlInsert', command, 'htmlInsert');
            }

            return originalInsertAdjacentHTML.call(this, position, text);
        };
    }

    const originalFetch = window.fetch ? window.fetch.bind(window) : null;
    if (originalFetch) {
        window.fetch = function(input, init) {
            const url = typeof input === 'string'
                ? input
                : (input && input.url ? input.url : safeSerialize(input));
            const body = init && init.body !== undefined ? `, ${safeSerialize(init.body)}` : '';
            const command = `fetch(${safeSerialize(url)}${body})`;
            const stack = captureStack();
            const rule = findBlockingRule('fetch', command, stack);

            if (rule) {
                return Promise.resolve(handleBlockedAction('fetch', command, 'fetch', stack, rule, buildBlockedResponse(rule)));
            }

            if (isConsoleLikeStack(stack)) {
                emit('fetch', command, 'fetch');
            }

            return originalFetch(input, init);
        };
    }

    if (navigator.sendBeacon) {
        const originalSendBeacon = navigator.sendBeacon.bind(navigator);
        navigator.sendBeacon = function(url, data) {
            const command = `sendBeacon(${safeSerialize(url)}, ${safeSerialize(data)})`;
            const stack = captureStack();
            const rule = findBlockingRule('beacon', command, stack);

            if (rule) {
                emit('beacon', command, 'beacon', buildBlockedPayload(stack, rule));
                return false;
            }

            if (isConsoleLikeStack(stack)) {
                emit('beacon', command, 'beacon');
            }

            return originalSendBeacon(url, data);
        };
    }

    const xhrMetaKey = '__firewallGuardXhrMeta';
    const originalXHROpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
        this[xhrMetaKey] = { method: method, url: url };
        return originalXHROpen.apply(this, arguments);
    };

    const originalXHRSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(body) {
        const meta = this[xhrMetaKey] || {};
        const command = `XMLHttpRequest(${safeSerialize(meta.method || 'GET')}, ${safeSerialize(meta.url || '')}, ${safeSerialize(body)})`;
        const stack = captureStack();
        const rule = findBlockingRule('xhr', command, stack);

        if (rule) {
            dispatchBlockedXhrEvents(this, rule);
            return handleBlockedAction('xhr', command, 'xhr', stack, rule, undefined);
        }

        if (isConsoleLikeStack(stack)) {
            emit('xhr', command, 'xhr');
        }

        return originalXHRSend.apply(this, arguments);
    };

    const originalWindowPostMessage = rawPostMessage;
    window.postMessage = function(message, targetOrigin, transfer) {
        if (message && (message.source === EVENT_SOURCE || message.source === POLICY_UPDATE_SOURCE)) {
            return originalWindowPostMessage.apply(window, arguments);
        }

        const command = `postMessage(${buildCommand(arguments)})`;
        const stack = captureStack();
        const rule = findBlockingRule('postMessage', command, stack);

        if (rule) {
            return handleBlockedAction('postMessage', command, 'postMessage', stack, rule, undefined);
        }

        if (isConsoleLikeStack(stack)) {
            emit('postMessage', command, 'postMessage');
        }

        return originalWindowPostMessage.apply(window, arguments);
    };

    const originalWindowOpen = window.open ? window.open.bind(window) : null;
    if (originalWindowOpen) {
        window.open = function(url, target, features) {
            const command = `window.open(${safeSerialize(url)}, ${safeSerialize(target)}, ${safeSerialize(features)})`;
            const stack = captureStack();
            const rule = findBlockingRule('open', command, stack);

            if (rule) {
                emit('open', command, 'open', buildBlockedPayload(stack, rule));
                return null;
            }

            if (isConsoleLikeStack(stack)) {
                emit('open', command, 'open');
            }

            return originalWindowOpen(url, target, features);
        };
    }

    if (window.Storage && Storage.prototype) {
        ['setItem', 'removeItem', 'clear'].forEach((methodName) => {
            const originalMethod = Storage.prototype[methodName];
            if (!originalMethod) {
                return;
            }

            Storage.prototype[methodName] = function(...args) {
                const storageType = this === window.sessionStorage ? 'sessionStorage' : 'localStorage';
                const command = `${storageType}.${methodName}(${buildCommand(args)})`;
                const stack = captureStack();
                const rule = findBlockingRule('storage', command, stack);

                if (rule) {
                    return handleBlockedAction('storage', command, 'storage', stack, rule, undefined);
                }

                if (isConsoleLikeStack(stack)) {
                    emit('storage', command, 'storage');
                }

                return originalMethod.apply(this, args);
            };
        });
    }
})();
