(function () {
    const e = React.createElement;
    const useState = React.useState;
    const useRef = React.useRef;
    const useEffect = React.useEffect;
    const useDeferredValue = React.useDeferredValue || ((value) => value);
    const startTransition = React.startTransition || ((callback) => callback());

    const MAX_PAGE_LINKS = 30;
    const MAX_CONTENT_CHARS = 12000;
    const MAX_PREVIEW_HTML_CHARS = 300000;
    const SEARCH_FETCH_REQUEST_SOURCE = "firewall-guard-search-fetch-request";
    const SEARCH_FETCH_RESPONSE_SOURCE = "firewall-guard-search-fetch-response";
    const SEARCH_FETCH_READY_SOURCE = "firewall-guard-search-fetch-ready";
    const EXTENSION_BRIDGE_FETCH_TIMEOUT_MS = 12000;
    const DEFAULT_CLIENT_CONTENT_POLICY = Object.freeze({
        version: 1,
        updated_at: "",
        blocked_content_patterns: [
            {
                id: "captcha-challenge",
                pattern: "captcha",
                reason: "Challenge page content should be blocked from search results.",
                enabled: true
            },
            {
                id: "access-denied",
                pattern: "access denied",
                reason: "Access denied pages should be blocked from search content.",
                enabled: true
            },
            {
                id: "forbidden-403",
                pattern: "403 forbidden",
                reason: "Forbidden content should be blocked from search content.",
                enabled: true
            }
        ],
        delayed_content_patterns: [
            {
                id: "just-a-moment",
                pattern: "just a moment",
                reason: "Interstitial challenge pages should incur a small verification delay.",
                enabled: true,
                delay_ms: 2000
            },
            {
                id: "checking-your-browser",
                pattern: "checking your browser",
                reason: "Browser verification pages should incur a small verification delay.",
                enabled: true,
                delay_ms: 2000
            },
            {
                id: "please-wait",
                pattern: "please wait",
                reason: "Wait screens should incur a small verification delay.",
                enabled: true,
                delay_ms: 1500
            }
        ]
    });

    function looksLikeUrl(value) {
        const trimmed = String(value || "").trim();
        if (!trimmed || /\s/.test(trimmed)) return false;
        return /^https?:\/\//i.test(trimmed) || trimmed.includes(".");
    }

    function normalizeUrl(rawUrl) {
        const candidate = String(rawUrl || "").trim();
        if (!candidate) {
            throw new Error("Enter a website URL to open.");
        }
        const parsed = new URL(/^https?:\/\//i.test(candidate) ? candidate : `https://${candidate}`);
        if (!/^https?:$/i.test(parsed.protocol)) {
            throw new Error("Only http:// and https:// URLs are supported.");
        }
        return parsed.toString();
    }

    function compactText(text) {
        return String(text || "")
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter(Boolean)
            .join("\n")
            .slice(0, MAX_CONTENT_CHARS);
    }

    function extractLinksFromDocument(doc, baseUrl) {
        const links = [];
        const seen = new Set();
        const anchors = doc.querySelectorAll("a[href]");

        for (const anchor of anchors) {
            if (links.length >= MAX_PAGE_LINKS) break;

            const rawHref = anchor.getAttribute("href") || "";
            if (!rawHref || rawHref.startsWith("javascript:")) continue;

            let absoluteUrl = "";
            try {
                absoluteUrl = new URL(rawHref, baseUrl).toString();
            } catch (error) {
                continue;
            }

            if (!/^https?:\/\//i.test(absoluteUrl)) continue;
            if (seen.has(absoluteUrl)) continue;
            seen.add(absoluteUrl);

            const text = (anchor.innerText || anchor.textContent || "").trim() || absoluteUrl;
            links.push({
                url: absoluteUrl,
                text: text,
                blocked: false
            });
        }

        return links;
    }

    function sanitizeDocumentForPreview(doc, baseUrl) {
        doc.querySelectorAll(
            "script,style,noscript,img,picture,source,video,audio,canvas,iframe,frame,object,embed,link,meta,base,form,input,textarea,select,option,button"
        ).forEach((node) => node.remove());

        for (const node of doc.querySelectorAll("*")) {
            for (const attribute of Array.from(node.attributes || [])) {
                const name = String(attribute.name || "").toLowerCase();
                if (
                    name.startsWith("on") ||
                    name === "srcset" ||
                    name === "integrity" ||
                    name === "nonce"
                ) {
                    node.removeAttribute(attribute.name);
                }
            }

            if (node.tagName && node.tagName.toLowerCase() === "a") {
                const rawHref = node.getAttribute("href") || "";

                try {
                    const absoluteUrl = new URL(rawHref, baseUrl).toString();
                    if (/^https?:\/\//i.test(absoluteUrl)) {
                        node.setAttribute("href", absoluteUrl);
                    } else {
                        node.removeAttribute("href");
                    }
                } catch (error) {
                    node.removeAttribute("href");
                }

                node.removeAttribute("target");
                node.setAttribute("rel", "noopener noreferrer");
            }
        }
    }

    function buildPageData(html, baseUrl) {
        const parser = new DOMParser();
        const doc = parser.parseFromString(String(html || ""), "text/html");
        sanitizeDocumentForPreview(doc, baseUrl);

        const body = doc.body || doc.createElement("body");
        const pageText = compactText(body.innerText || body.textContent || "");
        const previewHtml = String(body.innerHTML || "").slice(0, MAX_PREVIEW_HTML_CHARS);
        const links = extractLinksFromDocument(doc, baseUrl);

        return {
            text: pageText,
            previewHtml: previewHtml,
            links: links
        };
    }

    async function fetchPageFromServer(url, signal) {
        const response = await fetch(`/fetch?url=${encodeURIComponent(url)}`, {
            signal: signal,
            headers: {
                "Accept": "application/json"
            }
        });

        let data = {};
        try {
            data = await response.json();
        } catch (error) {
            throw new Error(`Server returned an invalid response for ${url}.`);
        }

        return {
            ...data,
            ok: response.ok,
            httpStatus: response.status,
            finalUrl: data.url || url,
            fetchMode: data.fetch_mode || "server"
        };
    }

    function buildServerPageData(page, baseUrl) {
        const htmlData = page && page.html ? buildPageData(page.html, baseUrl) : { text: "", previewHtml: "", links: [] };
        const serverLinks = Array.isArray(page && page.links) ? page.links : [];

        return {
            text: compactText((page && page.content) || htmlData.text || "") || "No readable text found.",
            previewHtml: htmlData.previewHtml,
            links: serverLinks.length ? serverLinks : htmlData.links
        };
    }

    function buildServerFetchMessage(url, error) {
        return [
            "Server-side page loading failed.",
            `URL: ${url}`,
            "",
            `Reason: ${error && error.message ? error.message : "The server could not load this page."}`,
            "",
            "This search page now uses the Firewall Guard server on port 4000 for page loading.",
            "Try the URL again or restart the local search server if the problem continues."
        ].join("\n");
    }

    function normalizePolicyRule(rule, delayRule) {
        const source = rule && typeof rule === "object" ? rule : {};
        const pattern = String(source.pattern || "").trim();
        if (!pattern) {
            return null;
        }

        const normalized = {
            id: String(source.id || pattern).trim(),
            pattern: pattern,
            reason: String(
                source.reason ||
                    (delayRule
                        ? "Search content delay match."
                        : "Search content block match.")
            ).trim(),
            enabled: source.enabled !== false
        };

        if (delayRule) {
            const delayMs = Number(source.delay_ms || source.delayMs || 0);
            normalized.delay_ms = Number.isFinite(delayMs) && delayMs > 0 ? Math.floor(delayMs) : 0;
        }

        return normalized;
    }

    function normalizeContentPolicy(policy) {
        const source = policy && typeof policy === "object" ? policy : {};
        const blocked = Array.isArray(source.blocked_content_patterns)
            ? source.blocked_content_patterns
            : DEFAULT_CLIENT_CONTENT_POLICY.blocked_content_patterns;
        const delayed = Array.isArray(source.delayed_content_patterns)
            ? source.delayed_content_patterns
            : DEFAULT_CLIENT_CONTENT_POLICY.delayed_content_patterns;

        return {
            version: Number(source.version || DEFAULT_CLIENT_CONTENT_POLICY.version) || DEFAULT_CLIENT_CONTENT_POLICY.version,
            updated_at: String(source.updated_at || ""),
            blocked_content_patterns: blocked
                .map((rule) => normalizePolicyRule(rule, false))
                .filter(Boolean),
            delayed_content_patterns: delayed
                .map((rule) => normalizePolicyRule(rule, true))
                .filter(Boolean)
        };
    }

    function contentPatternMatches(text, pattern) {
        const candidate = String(pattern || "").trim();
        if (!candidate) {
            return false;
        }

        const sourceText = String(text || "");
        if (/^regex:/i.test(candidate)) {
            try {
                return new RegExp(candidate.slice(6).trim(), "i").test(sourceText);
            } catch (error) {
                return false;
            }
        }

        return sourceText.toLowerCase().includes(candidate.toLowerCase());
    }

    function evaluateClientContentPolicy(policy, url, pageData, loadedPage) {
        const normalizedPolicy = normalizeContentPolicy(policy || DEFAULT_CLIENT_CONTENT_POLICY);
        const combinedText = [
            pageData && pageData.text ? pageData.text : "",
            loadedPage && loadedPage.content ? loadedPage.content : ""
        ]
            .filter(Boolean)
            .join("\n");

        const summary = {
            url: String(url || ""),
            blocked: false,
            block_rule: "",
            block_pattern: "",
            block_reason: "",
            delay_ms: 0,
            delay_rule: "",
            delay_pattern: "",
            delay_reason: "",
            policy_version: normalizedPolicy.version,
            content_length: combinedText.length
        };

        if (!combinedText.trim()) {
            return summary;
        }

        for (const rule of normalizedPolicy.blocked_content_patterns) {
            if (!rule.enabled) continue;
            if (!contentPatternMatches(combinedText, rule.pattern)) continue;
            summary.blocked = true;
            summary.block_rule = rule.id;
            summary.block_pattern = rule.pattern;
            summary.block_reason = rule.reason;
            return summary;
        }

        let bestDelayRule = null;
        for (const rule of normalizedPolicy.delayed_content_patterns) {
            if (!rule.enabled) continue;
            if (!contentPatternMatches(combinedText, rule.pattern)) continue;
            if (!bestDelayRule || Number(rule.delay_ms || 0) >= Number(bestDelayRule.delay_ms || 0)) {
                bestDelayRule = rule;
            }
        }

        if (bestDelayRule) {
            summary.delay_ms = Number(bestDelayRule.delay_ms || 0);
            summary.delay_rule = bestDelayRule.id;
            summary.delay_pattern = bestDelayRule.pattern;
            summary.delay_reason = bestDelayRule.reason;
        }

        return summary;
    }

    async function fetchContentPolicy(signal) {
        const response = await fetch("/api/content-policy", {
            signal: signal,
            headers: {
                "Accept": "application/json"
            }
        });
        const data = await response.json();
        if (!response.ok || data.success === false) {
            throw new Error((data && data.error) || "Failed to load content policy.");
        }
        return normalizeContentPolicy(data.policy || DEFAULT_CLIENT_CONTENT_POLICY);
    }

    function waitForDelay(delayMs, signal) {
        const duration = Number(delayMs || 0);
        if (!Number.isFinite(duration) || duration <= 0) {
            return Promise.resolve();
        }

        return new Promise((resolve, reject) => {
            let timeoutId = null;

            function cleanup() {
                if (timeoutId !== null) {
                    clearTimeout(timeoutId);
                    timeoutId = null;
                }
                if (signal) {
                    signal.removeEventListener("abort", handleAbort);
                }
            }

            function handleAbort() {
                cleanup();
                reject(createAbortError());
            }

            if (signal && signal.aborted) {
                reject(createAbortError());
                return;
            }

            if (signal) {
                signal.addEventListener("abort", handleAbort, { once: true });
            }

            timeoutId = window.setTimeout(() => {
                cleanup();
                resolve();
            }, duration);
        });
    }

    function createAbortError() {
        const error = new Error("Request aborted.");
        error.name = "AbortError";
        return error;
    }

    function isSearchBridgeReady() {
        try {
            return document.documentElement.getAttribute("data-firewall-guard-search-bridge") === "ready";
        } catch (error) {
            return false;
        }
    }

    function prefersExtensionBridge(url) {
        try {
            const hostname = new URL(url).hostname.toLowerCase();
            return (
                hostname === "notion.site" ||
                hostname.endsWith(".notion.site") ||
                hostname === "notion.so" ||
                hostname.endsWith(".notion.so")
            );
        } catch (error) {
            return false;
        }
    }

    function looksLikeServerFallback(text) {
        const lowered = String(text || "").toLowerCase();
        return (
            lowered.includes("text-only output is not available for this page.") ||
            lowered.includes("this site likely blocks lightweight scraping") ||
            lowered.includes("reason:")
        );
    }

    function shouldTryExtensionBridge(url, page, pageData) {
        if (!isSearchBridgeReady() || !url || (page && page.blocked)) {
            return false;
        }

        if (page && page.fetchMode === "bridge") {
            return false;
        }

        if (prefersExtensionBridge(url) && (!page || page.fetchMode !== "browser")) {
            return true;
        }

        return looksLikeServerFallback(pageData && pageData.text);
    }

    async function fetchPageFromExtensionBridge(url, signal) {
        if (!isSearchBridgeReady()) {
            throw new Error("Firewall Guard extension bridge is not ready.");
        }

        return new Promise((resolve, reject) => {
            const requestId = `search-fetch-${Date.now()}-${Math.random().toString(16).slice(2)}`;
            let settled = false;
            let timeoutId = null;

            function cleanup() {
                if (timeoutId !== null) {
                    clearTimeout(timeoutId);
                    timeoutId = null;
                }
                window.removeEventListener("message", handleMessage);
                if (signal) {
                    signal.removeEventListener("abort", handleAbort);
                }
            }

            function finishWithError(error) {
                if (settled) return;
                settled = true;
                cleanup();
                reject(error);
            }

            function finishWithSuccess(value) {
                if (settled) return;
                settled = true;
                cleanup();
                resolve(value);
            }

            function handleAbort() {
                finishWithError(createAbortError());
            }

            function handleMessage(event) {
                if (event.source !== window) return;
                if (!event.data || event.data.source !== SEARCH_FETCH_RESPONSE_SOURCE) return;
                if (event.data.requestId !== requestId) return;

                if (event.data.success === false) {
                    finishWithError(new Error(event.data.error || "Extension bridge failed."));
                    return;
                }

                finishWithSuccess({
                    ok: true,
                    fetchMode: "bridge",
                    finalUrl: event.data.url || url,
                    html: event.data.html || "",
                    contentType: event.data.contentType || ""
                });
            }

            if (signal && signal.aborted) {
                finishWithError(createAbortError());
                return;
            }

            window.addEventListener("message", handleMessage);
            if (signal) {
                signal.addEventListener("abort", handleAbort, { once: true });
            }

            timeoutId = window.setTimeout(() => {
                finishWithError(new Error("Firewall Guard extension bridge timed out."));
            }, EXTENSION_BRIDGE_FETCH_TIMEOUT_MS);

            window.postMessage(
                {
                    source: SEARCH_FETCH_REQUEST_SOURCE,
                    requestId: requestId,
                    url: url
                },
                "*"
            );
        });
    }

    function ResultButton(props) {
        const item = props.item || {};
        const className = props.current ? "result-button current" : "result-button";

        return e(
            "button",
            {
                type: "button",
                className: className,
                disabled: Boolean(item.blocked),
                onClick: props.onSelect
            },
            e("span", { className: "result-title" }, item.text || item.url || "Open"),
            item.url ? e("span", { className: "result-url" }, item.url) : null
        );
    }

    function Section(props) {
        return e(
            "section",
            { className: "section" },
            e("h3", null, props.title),
            props.children
        );
    }

    function EmptyState(props) {
        return e("div", { className: "empty" }, props.message);
    }

    function SearchApp() {
        const [query, setQuery] = useState("");
        const [hint, setHint] = useState("Type to search. The server on port 4000 handles search results and page loading.");
        const [status, setStatus] = useState("Ready.");
        const [results, setResults] = useState([]);
        const [selected, setSelected] = useState(null);
        const [pageLinks, setPageLinks] = useState([]);
        const [content, setContent] = useState("");
        const [previewHtml, setPreviewHtml] = useState("");
        const [contentMeta, setContentMeta] = useState("Open a URL or click a search result to load page content from the server.");
        const searchControllerRef = useRef(null);
        const loadControllerRef = useRef(null);
        const contentPolicyRef = useRef(normalizeContentPolicy(DEFAULT_CLIENT_CONTENT_POLICY));
        const contentPolicyLoadedRef = useRef(false);
        const deferredPreviewHtml = useDeferredValue(previewHtml);

        useEffect(() => {
            const controller = new AbortController();

            fetchContentPolicy(controller.signal)
                .then((policy) => {
                    contentPolicyRef.current = policy;
                    contentPolicyLoadedRef.current = true;
                })
                .catch(() => {
                    contentPolicyRef.current = normalizeContentPolicy(DEFAULT_CLIENT_CONTENT_POLICY);
                });

            return () => controller.abort();
        }, []);

        async function ensureContentPolicy(signal) {
            if (contentPolicyLoadedRef.current) {
                return contentPolicyRef.current;
            }

            try {
                const policy = await fetchContentPolicy(signal);
                contentPolicyRef.current = policy;
                contentPolicyLoadedRef.current = true;
                return policy;
            } catch (error) {
                contentPolicyRef.current = normalizeContentPolicy(DEFAULT_CLIENT_CONTENT_POLICY);
                return contentPolicyRef.current;
            }
        }

        async function runSearch() {
            const trimmed = query.trim();
            if (!trimmed) {
                setHint("Enter something to search.");
                setStatus("Enter something to search.");
                return;
            }

            if (looksLikeUrl(trimmed)) {
                await loadPage(trimmed, trimmed);
                return;
            }

            if (searchControllerRef.current) {
                searchControllerRef.current.abort();
            }
            const controller = new AbortController();
            searchControllerRef.current = controller;

            setStatus(`Searching for "${trimmed}"...`);
            setHint("Searching...");
            setSelected(null);
            setResults([]);
            setPageLinks([]);
            setContent("");
            setPreviewHtml("");
            setContentMeta("Searching...");

            try {
                const response = await fetch(`/search?q=${encodeURIComponent(trimmed)}`, {
                    signal: controller.signal
                });
                const data = await response.json();
                if (!response.ok || data.success === false) {
                    throw new Error(data.error || "Search failed");
                }

                setResults(Array.isArray(data.results) ? data.results : []);
                setHint(`Found ${data.count || 0} result(s). Click a result button to load page content.`);
                setStatus(`Found ${data.count || 0} result(s) from ${data.source || "search"}.`);
                setContentMeta("Search complete. Click a result to load page content from the server.");
            } catch (error) {
                if (error.name === "AbortError") return;
                setHint("Search failed.");
                setStatus(`Search failed: ${error.message}`);
                setContentMeta("Search failed.");
                setResults([]);
            } finally {
                if (searchControllerRef.current === controller) {
                    searchControllerRef.current = null;
                }
            }
        }

        async function loadPage(url, textLabel) {
            let normalizedUrl = "";
            try {
                normalizedUrl = normalizeUrl(url);
            } catch (error) {
                setStatus(error.message);
                setContent(error.message);
                setContentMeta("Page load failed.");
                setPageLinks([]);
                return;
            }

            if (loadControllerRef.current) {
                loadControllerRef.current.abort();
            }
            const controller = new AbortController();
            loadControllerRef.current = controller;

            const selectedItem = {
                url: normalizedUrl,
                text: textLabel || normalizedUrl,
                blocked: false
            };

            setSelected(selectedItem);
            setResults([selectedItem]);
            setPageLinks([]);
            setPreviewHtml("");
            setContent("Loading...");
            setContentMeta("Loading page content from the Firewall Guard server...");
            setStatus(`Loading ${normalizedUrl}...`);

            try {
                let loadedPage = await fetchPageFromServer(normalizedUrl, controller.signal);
                let pageData = buildServerPageData(loadedPage, loadedPage.finalUrl || normalizedUrl);

                if (shouldTryExtensionBridge(normalizedUrl, loadedPage, pageData)) {
                    try {
                        const bridgePage = await fetchPageFromExtensionBridge(normalizedUrl, controller.signal);
                        const bridgePageData = buildPageData(bridgePage.html, bridgePage.finalUrl || normalizedUrl);

                        if (bridgePageData.previewHtml || bridgePageData.text || bridgePageData.links.length) {
                            loadedPage = {
                                ...loadedPage,
                                ...bridgePage,
                                blocked: false
                            };
                            pageData = {
                                text: bridgePageData.text || pageData.text || "No readable text found.",
                                previewHtml: bridgePageData.previewHtml,
                                links: bridgePageData.links.length ? bridgePageData.links : pageData.links
                            };
                        }
                    } catch (bridgeError) {
                        if (bridgeError && bridgeError.name === "AbortError") {
                            throw bridgeError;
                        }
                    }
                }

                const activeContentPolicy = await ensureContentPolicy(controller.signal);
                const clientContentPolicy = evaluateClientContentPolicy(
                    activeContentPolicy,
                    loadedPage.finalUrl || normalizedUrl,
                    pageData,
                    loadedPage
                );

                if (clientContentPolicy.delay_ms > 0) {
                    setContentMeta(
                        `Firewall Guard search frontend is delaying this page for ${clientContentPolicy.delay_ms} ms because of ${clientContentPolicy.delay_rule || clientContentPolicy.delay_pattern}.`
                    );
                    setStatus(`Delaying ${loadedPage.finalUrl || normalizedUrl}...`);
                    await waitForDelay(clientContentPolicy.delay_ms, controller.signal);
                }

                const currentItem = {
                    url: loadedPage.finalUrl || normalizedUrl,
                    text: textLabel || loadedPage.finalUrl || normalizedUrl,
                    blocked: Boolean(loadedPage.blocked || clientContentPolicy.blocked)
                };

                setSelected(currentItem);
                if (loadedPage.blocked) {
                    startTransition(() => {
                        setResults([currentItem]);
                        setPageLinks(pageData.links);
                        setPreviewHtml(pageData.previewHtml);
                        setContent(pageData.text || "No readable text found.");
                    });
                    setContentMeta(
                        loadedPage.policy && loadedPage.policy.block_pattern
                            ? `Blocked by Firewall Guard search policy: ${loadedPage.policy.block_pattern}`
                            : "Blocked by Firewall Guard search policy."
                    );
                    setStatus(`Blocked ${currentItem.url}.`);
                } else if (clientContentPolicy.blocked) {
                    startTransition(() => {
                        setResults([currentItem]);
                        setPageLinks([]);
                        setPreviewHtml("");
                        setContent(
                            `Blocked by frontend content policy: ${
                                clientContentPolicy.block_reason || clientContentPolicy.block_pattern || "content policy"
                            }`
                        );
                    });
                    setContentMeta(
                        clientContentPolicy.block_rule
                            ? `Blocked by Firewall Guard search frontend policy: ${clientContentPolicy.block_rule}`
                            : "Blocked by Firewall Guard search frontend policy."
                    );
                    setStatus(`Blocked ${currentItem.url} in the search frontend.`);
                } else {
                    startTransition(() => {
                        setResults([currentItem]);
                        setPageLinks(pageData.links);
                        setPreviewHtml(pageData.previewHtml);
                        setContent(pageData.text || "No readable text found.");
                    });
                    setContentMeta(
                        loadedPage.fetchMode === "bridge"
                            ? "Loaded through the Firewall Guard extension bridge on port 4000."
                            : loadedPage.fetchMode === "browser"
                            ? "Loaded by Firewall Guard server browser render on port 4000."
                            : loadedPage.fetchMode === "requests"
                              ? "Loaded by Firewall Guard server fetch on port 4000."
                              : loadedPage.fetchMode === "fallback"
                                ? "Loaded by Firewall Guard fallback output on port 4000."
                              : "Loaded by Firewall Guard server on port 4000."
                    );
                    setStatus(
                        clientContentPolicy.delay_ms > 0
                            ? `Loaded ${currentItem.url} after a frontend content delay of ${clientContentPolicy.delay_ms} ms.`
                            : `Loaded ${currentItem.url}.`
                    );
                }
            } catch (error) {
                if (error.name === "AbortError") return;
                try {
                    const bridgePage = await fetchPageFromExtensionBridge(normalizedUrl, controller.signal);
                    const bridgePageData = buildPageData(bridgePage.html, bridgePage.finalUrl || normalizedUrl);
                    const activeContentPolicy = await ensureContentPolicy(controller.signal);
                    const clientContentPolicy = evaluateClientContentPolicy(
                        activeContentPolicy,
                        bridgePage.finalUrl || normalizedUrl,
                        bridgePageData,
                        bridgePage
                    );

                    if (clientContentPolicy.delay_ms > 0) {
                        setContentMeta(
                            `Firewall Guard search frontend is delaying this page for ${clientContentPolicy.delay_ms} ms because of ${clientContentPolicy.delay_rule || clientContentPolicy.delay_pattern}.`
                        );
                        setStatus(`Delaying ${bridgePage.finalUrl || normalizedUrl}...`);
                        await waitForDelay(clientContentPolicy.delay_ms, controller.signal);
                    }

                    const currentItem = {
                        url: bridgePage.finalUrl || normalizedUrl,
                        text: textLabel || bridgePage.finalUrl || normalizedUrl,
                        blocked: Boolean(clientContentPolicy.blocked)
                    };

                    setSelected(currentItem);
                    if (clientContentPolicy.blocked) {
                        startTransition(() => {
                            setResults([currentItem]);
                            setPageLinks([]);
                            setPreviewHtml("");
                            setContent(
                                `Blocked by frontend content policy: ${
                                    clientContentPolicy.block_reason || clientContentPolicy.block_pattern || "content policy"
                                }`
                            );
                        });
                        setContentMeta(
                            clientContentPolicy.block_rule
                                ? `Blocked by Firewall Guard search frontend policy: ${clientContentPolicy.block_rule}`
                                : "Blocked by Firewall Guard search frontend policy."
                        );
                        setStatus(`Blocked ${currentItem.url} in the search frontend.`);
                    } else {
                        startTransition(() => {
                            setResults([currentItem]);
                            setPageLinks(bridgePageData.links);
                            setPreviewHtml(bridgePageData.previewHtml);
                            setContent(bridgePageData.text || "No readable text found.");
                        });
                        setContentMeta("Loaded through the Firewall Guard extension bridge on port 4000.");
                        setStatus(
                            clientContentPolicy.delay_ms > 0
                                ? `Loaded ${currentItem.url} after a frontend content delay of ${clientContentPolicy.delay_ms} ms.`
                                : `Loaded ${currentItem.url}.`
                        );
                    }
                } catch (bridgeError) {
                    if (bridgeError && bridgeError.name === "AbortError") return;
                    setPreviewHtml("");
                    setContent(buildServerFetchMessage(normalizedUrl, bridgeError || error));
                    setPageLinks([]);
                    setContentMeta("Server-side page load failed.");
                    setStatus(`Page load failed: ${(bridgeError || error).message}`);
                }
            } finally {
                if (loadControllerRef.current === controller) {
                    loadControllerRef.current = null;
                }
            }
        }

        function onQueryKeyDown(event) {
            if (event.key !== "Enter") return;
            event.preventDefault();
            void runSearch();
        }

        function onPreviewClick(event) {
            const target = event.target;
            if (!target || !target.closest) return;

            const anchor = target.closest("a[href]");
            if (!anchor) return;

            event.preventDefault();
            const href = anchor.getAttribute("href") || "";
            const label = (anchor.innerText || anchor.textContent || "").trim() || href;
            if (!href) return;
            void loadPage(href, label);
        }

        return e(
            "div",
            { className: "page" },
            e("h1", null, "Firewall Guard Search Engine"),
            e(
                "section",
                { className: "section" },
                e(
                    "div",
                    { className: "toolbar" },
                    e("input", {
                        type: "text",
                        value: query,
                        placeholder: "Search for keywords or enter a URL like example.com",
                        onChange: (event) => setQuery(event.target.value),
                        onKeyDown: onQueryKeyDown
                    }),
                    e("button", { type: "button", onClick: () => void runSearch() }, "Search"),
                    e("button", { type: "button", onClick: () => void loadPage(query, query) }, "Open URL")
                ),
                e("div", { className: "meta", style: { marginTop: "10px" } }, hint),
                e("div", { className: "status" }, status)
            ),
            e(
                Section,
                { title: "Search Results" },
                e(
                    "div",
                    { className: "button-grid" },
                    results.length
                        ? results.map((item) =>
                              e(ResultButton, {
                                  key: item.url,
                                  item: item,
                                  current: Boolean(selected && selected.url === item.url),
                                  onSelect: () => void loadPage(item.url, item.text)
                              })
                          )
                        : e(EmptyState, { message: "Search results will appear here." })
                )
            ),
            e(
                Section,
                { title: "Page Links / Buttons" },
                e(
                    "div",
                    { className: "button-grid" },
                    pageLinks.length
                        ? pageLinks.map((item) =>
                              e(ResultButton, {
                                  key: item.url,
                                  item: item,
                                  current: false,
                                  onSelect: () => void loadPage(item.url, item.text)
                              })
                          )
                        : e(EmptyState, { message: "Open a result to list page links." })
                )
            ),
            e(
                Section,
                { title: "Page Content" },
                e("div", { className: "meta" }, contentMeta),
                deferredPreviewHtml
                    ? e(
                          "div",
                          { className: "content-preview" },
                          e("div", {
                              className: "preview-canvas",
                              onClick: onPreviewClick,
                              dangerouslySetInnerHTML: { __html: deferredPreviewHtml }
                          })
                      )
                    : null,
                deferredPreviewHtml && content
                    ? e(
                          "details",
                          { className: "text-details" },
                          e("summary", null, "Show text extract"),
                          e("div", { className: "content plain text-content" }, content)
                      )
                    : null,
                !deferredPreviewHtml
                    ? e("div", { className: "content plain" }, content || "Content will appear here.")
                    : null
            )
        );
    }

    ReactDOM.createRoot(document.getElementById("root")).render(e(SearchApp));
})();
