"""
CHROME EXTENSION SERVER
Dedicated API server for Chrome extension communication
Handles extension-specific requests, session management, and real-time updates
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from datetime import datetime
import json
import os
import re
import uuid
from pathlib import Path
import threading
import time
from urllib.parse import quote_plus, urlparse

app = Flask(__name__)
CORS(app)

BACKEND_API_BASE = os.getenv('FIREWALL_BACKEND_API_BASE', 'http://localhost:5000/api').rstrip('/')
SERVER_HOST = os.getenv('FIREWALL_EXTENSION_SERVER_HOST', 'localhost')
SERVER_PORT = int(os.getenv('FIREWALL_EXTENSION_SERVER_PORT', '6000'))

class ExtensionSessionManager:
    def __init__(self):
        self.sessions_file = Path('extension_sessions.json')
        self.sessions = self.load_sessions()
        self.active_connections = {}
        
    def load_sessions(self):
        """Load extension sessions from file"""
        default = {
            "active_sessions": {},
            "session_history": [],
            "last_updated": datetime.now().isoformat(),
            "version": "1.0"
        }
        
        if self.sessions_file.exists():
            try:
                return json.loads(self.sessions_file.read_text())
            except Exception as e:
                print(f"[Extension Server] Failed to load sessions: {e}")
                self.save_sessions(default)
                return default
        else:
            self.save_sessions(default)
            return default
    
    def save_sessions(self, data=None):
        """Save sessions to file"""
        if data is None:
            data = self.sessions
        data['last_updated'] = datetime.now().isoformat()
        self.sessions_file.write_text(json.dumps(data, indent=2))
    
    def create_session(self, session_data):
        """Create new extension session"""
        session_id = str(uuid.uuid4())
        session = {
            "session_id": session_id,
            "created_at": datetime.now().isoformat(),
            "status": "active",
            "extension_version": "2.0.0",
            "browser_info": session_data.get("browser_info", {}),
            "tab_info": session_data.get("tab_info", {}),
            "window_info": session_data.get("window_info", {}),
            "last_activity": datetime.now().isoformat(),
            "requests_count": 0,
            "blocked_requests": 0,
            "allowed_requests": 0
        }
        
        self.sessions['active_sessions'][session_id] = session
        self.save_sessions()
        return session_id, session
    
    def update_session(self, session_id, updates):
        """Update existing session"""
        if session_id in self.sessions['active_sessions']:
            self.sessions['active_sessions'][session_id].update(updates)
            self.sessions['active_sessions'][session_id]['last_activity'] = datetime.now().isoformat()
            self.save_sessions()
            return True
        return False
    
    def end_session(self, session_id, reason="manual"):
        """End a session and move to history"""
        if session_id in self.sessions['active_sessions']:
            session = self.sessions['active_sessions'][session_id]
            session['status'] = 'ended'
            session['ended_at'] = datetime.now().isoformat()
            session['end_reason'] = reason
            
            # Move to history
            self.sessions['session_history'].append(session)
            del self.sessions['active_sessions'][session_id]
            
            # Keep only last 50 sessions in history
            if len(self.sessions['session_history']) > 50:
                self.sessions['session_history'] = self.sessions['session_history'][-50:]
            
            self.save_sessions()
            return True
        return False
    
    def get_session(self, session_id):
        """Get session by ID"""
        return self.sessions['active_sessions'].get(session_id)
    
    def get_all_sessions(self):
        """Get all active sessions"""
        return self.sessions['active_sessions']
    
    def cleanup_expired_sessions(self):
        """Clean up sessions older than 24 hours"""
        now = datetime.now()
        expired_sessions = []
        
        for session_id, session in self.sessions['active_sessions'].items():
            created_at = datetime.fromisoformat(session['created_at'])
            if (now - created_at).total_seconds() > 24 * 3600:  # 24 hours
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.end_session(session_id, "expired")
        
        return len(expired_sessions)

class ExtensionRequestLogger:
    def __init__(self):
        self.log_file = Path('extension_requests.log')
        self.requests = []
        
    def log_request(self, session_id, request_data):
        """Log extension request"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "session_id": session_id,
            "url": request_data.get("url", ""),
            "action": request_data.get("action", ""),
            "decision": request_data.get("decision", ""),
            "risk_level": request_data.get("risk_level", "unknown"),
            "processing_time": request_data.get("processing_time", 0)
        }
        
        self.requests.append(log_entry)
        
        # Keep only last 1000 requests in memory
        if len(self.requests) > 1000:
            self.requests = self.requests[-1000:]
        
        # Append to file
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        return log_entry
    
    def get_recent_requests(self, limit=100):
        """Get recent requests"""
        return self.requests[-limit:]


class LocalBrowserRunner:
    """Runs local headless browser tasks for page extraction and lightweight search."""

    MEDIA_EXTENSION_PATTERN = re.compile(
        r"\.(?:png|jpe?g|gif|webp|svg|ico|bmp|avif|mp4|webm|ogg|ogv|mov|m4v|m3u8|mpd|ts)(?:[\?#].*)?$",
        re.IGNORECASE
    )
    URL_HOST_PATTERN = re.compile(
        r"^(?:localhost|[\w-]+(?:\.[\w-]+)+|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$",
        re.IGNORECASE
    )
    SEARCH_ENGINE_TEMPLATE = "https://search.brave.com/search?q={query}"
    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/136.0.0.0 Safari/537.36"
    )
    BOILERPLATE_TEXT_PATTERN = re.compile(
        r"\b(?:cookie|privacy|terms|sign in|log in|all rights reserved|javascript|skip to|menu)\b",
        re.IGNORECASE
    )

    def __init__(self):
        self.lock = threading.Lock()
        self.state = {
            "running": False,
            "last_run_id": None,
            "last_started_at": None,
            "last_completed_at": None,
            "last_error": None,
            "last_result": None
        }
        self._sync_playwright = None
        self._playwright_error = None
        self._detect_playwright()

    def _detect_playwright(self):
        try:
            from playwright.sync_api import sync_playwright
            self._sync_playwright = sync_playwright
            self._playwright_error = None
        except Exception as error:
            self._sync_playwright = None
            self._playwright_error = str(error)

    @property
    def available(self):
        return self._sync_playwright is not None

    def status(self):
        with self.lock:
            return {
                "running": self.state["running"],
                "last_run_id": self.state["last_run_id"],
                "last_started_at": self.state["last_started_at"],
                "last_completed_at": self.state["last_completed_at"],
                "last_error": self.state["last_error"],
                "last_result": self.state["last_result"],
                "playwright_available": self.available,
                "playwright_error": self._playwright_error
            }

    def _compact_text(self, value):
        return " ".join((value or "").split())

    def _normalize_target_url(self, value):
        raw_value = (value or "").strip()
        if not raw_value:
            raise ValueError("Enter a target URL or search query.")

        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_value):
            raw_value = f"https://{raw_value}"

        parsed = urlparse(raw_value)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only http:// or https:// URLs are supported.")

        if not parsed.netloc:
            raise ValueError("Target URL must include a valid host.")

        return raw_value

    def _looks_like_url(self, value):
        raw_value = (value or "").strip()
        if not raw_value or re.search(r"\s", raw_value):
            return False

        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_value):
            return True

        parsed = urlparse(f"https://{raw_value}")
        host = parsed.netloc.split("@")[-1]
        return bool(host and self.URL_HOST_PATTERN.match(host))

    def _resolve_target(self, value):
        raw_value = (value or "").strip()
        if not raw_value:
            raise ValueError("Enter a target URL or search query.")

        if self._looks_like_url(raw_value):
            normalized_url = self._normalize_target_url(raw_value)
            return {
                "mode": "browse",
                "input": raw_value,
                "target_url": normalized_url,
                "query": None
            }

        return {
            "mode": "search",
            "input": raw_value,
            "target_url": self._build_search_url(raw_value),
            "query": raw_value
        }

    def _build_search_url(self, query):
        return self.SEARCH_ENGINE_TEMPLATE.format(query=quote_plus((query or "").strip()))

    def _is_transient_page_context_error(self, error):
        message = str(error or "")
        return (
            "Execution context was destroyed" in message or
            "Cannot find context with specified id" in message or
            "Most likely the page has been closed" in message
        )

    def _wait_for_page_settle(self, page, timeout_seconds):
        timeout_ms = max(1000, min(timeout_seconds * 1000, 8000))

        for state in ("domcontentloaded", "load"):
            try:
                page.wait_for_load_state(state, timeout=timeout_ms)
            except Exception:
                continue

        page.wait_for_timeout(750)

    def _install_image_dom_blocker(self, context):
        context.add_init_script("""
            (() => {
                const SELECTOR = 'img, picture, source[srcset], source[src], image';

                function removeImageLikeNodes(root) {
                    if (!root) {
                        return;
                    }

                    if (root.nodeType === Node.ELEMENT_NODE) {
                        if (root.matches && root.matches(SELECTOR)) {
                            root.remove();
                            return;
                        }

                        if (root.querySelectorAll) {
                            root.querySelectorAll(SELECTOR).forEach((node) => node.remove());
                        }
                    }
                }

                function scrubAttributes(element) {
                    if (!element || !element.removeAttribute) {
                        return;
                    }

                    ['src', 'srcset', 'sizes', 'poster'].forEach((attribute) => {
                        if (element.hasAttribute(attribute)) {
                            element.removeAttribute(attribute);
                        }
                    });
                }

                const originalSetAttribute = Element.prototype.setAttribute;
                Element.prototype.setAttribute = function(name, value) {
                    const attributeName = String(name || '').toLowerCase();
                    if (
                        this &&
                        this.matches &&
                        this.matches('img, source, picture, video') &&
                        ['src', 'srcset', 'sizes', 'poster'].includes(attributeName)
                    ) {
                        scrubAttributes(this);
                        return;
                    }

                    return originalSetAttribute.call(this, name, value);
                };

                removeImageLikeNodes(document.documentElement);

                const observer = new MutationObserver((mutations) => {
                    mutations.forEach((mutation) => {
                        if (mutation.type === 'attributes' && mutation.target) {
                            if (mutation.target.matches && mutation.target.matches('img, source, picture, video')) {
                                scrubAttributes(mutation.target);
                                if (mutation.target.matches('img, picture, source[srcset], source[src], image')) {
                                    mutation.target.remove();
                                }
                            }
                        }

                        mutation.addedNodes.forEach((node) => {
                            removeImageLikeNodes(node);
                        });
                    });
                });

                observer.observe(document.documentElement || document, {
                    childList: true,
                    subtree: true,
                    attributes: true,
                    attributeFilter: ['src', 'srcset', 'sizes', 'poster']
                });

                window.__firewallGuardRemoveImages = () => removeImageLikeNodes(document.documentElement);
            })();
        """)

    def _remove_images_from_dom(self, page):
        return page.evaluate("""
            () => {
                const removeImageLikeNodes = window.__firewallGuardRemoveImages;
                if (typeof removeImageLikeNodes === 'function') {
                    removeImageLikeNodes();
                } else {
                    document.querySelectorAll('img, picture, source[srcset], source[src], image').forEach((node) => node.remove());
                }

                return document.querySelectorAll('img').length;
            }
        """)

    def _navigate_page(self, page, target_url, timeout_seconds):
        response = page.goto(target_url, wait_until="domcontentloaded")
        self._wait_for_page_settle(page, timeout_seconds)
        return response

    def _collect_page_snapshot(self, page, requested_url, response, timeout_seconds, should_remove_images):
        if should_remove_images:
            self._read_page_with_retry(
                page,
                lambda: self._remove_images_from_dom(page),
                0,
                timeout_seconds
            )

        title = self._read_page_with_retry(
            page,
            lambda: page.title() or "Untitled",
            "Untitled",
            timeout_seconds
        )
        final_url = self._read_page_with_retry(
            page,
            lambda: page.url,
            requested_url,
            timeout_seconds
        )
        text_content = self._read_page_with_retry(
            page,
            lambda: page.evaluate(
                "() => (document.body && document.body.innerText) ? document.body.innerText : ''"
            ) or "",
            "",
            timeout_seconds
        )
        normalized_text = self._compact_text(text_content)
        image_count = self._read_page_with_retry(
            page,
            lambda: page.locator("img").count(),
            0,
            timeout_seconds
        )
        link_count = self._read_page_with_retry(
            page,
            lambda: page.locator("a[href]").count(),
            0,
            timeout_seconds
        )
        response_status = response.status if response else None
        content_type = response.headers.get("content-type", "") if response else ""

        return {
            "requested_url": requested_url,
            "final_url": final_url,
            "title": title,
            "response_status": response_status,
            "content_type": content_type,
            "text_content": text_content,
            "normalized_text": normalized_text,
            "text_length": len(normalized_text),
            "text_preview": normalized_text[:1200],
            "image_count": image_count,
            "link_count": link_count
        }

    def _extract_search_results(self, page, timeout_seconds):
        return self._read_page_with_retry(
            page,
            lambda: page.evaluate("""
                () => {
                    function cleanText(value) {
                        return String(value || '').replace(/\\s+/g, ' ').trim();
                    }

                    function normalizeResultUrl(rawValue) {
                        if (!rawValue) {
                            return '';
                        }

                        try {
                            const url = new URL(rawValue, window.location.href);
                            const redirectTarget = url.searchParams.get('uddg');
                            if (redirectTarget) {
                                return redirectTarget;
                            }

                            if (url.protocol === 'http:' || url.protocol === 'https:') {
                                return url.href;
                            }
                        } catch (error) {
                            return '';
                        }

                        return '';
                    }

                    const braveNodes = Array.from(document.querySelectorAll('div.snippet[data-type="web"]'));
                    if (braveNodes.length) {
                        return braveNodes.slice(0, 5).map((node, index) => {
                            const anchor = node.querySelector('a[href]');
                            const lines = String(node.innerText || '')
                                .split('\\n')
                                .map((line) => cleanText(line))
                                .filter(Boolean);
                            const title = cleanText(lines[2] || (anchor ? anchor.textContent : ''));
                            const snippet = cleanText(lines.slice(3).join(' '));

                            return {
                                position: index + 1,
                                title,
                                url: normalizeResultUrl(anchor ? (anchor.getAttribute('href') || anchor.href) : ''),
                                snippet
                            };
                        }).filter((entry) => entry.title || entry.url || entry.snippet);
                    }

                    const duckDuckGoNodes = Array.from(document.querySelectorAll('.result'));
                    return duckDuckGoNodes.slice(0, 5).map((node, index) => {
                        const anchor = node.querySelector('a.result__a, h2 a, a[href]');
                        const title = cleanText(anchor ? anchor.textContent : '');
                        const url = normalizeResultUrl(anchor ? (anchor.getAttribute('href') || anchor.href) : '');
                        const snippet = cleanText(
                            (node.querySelector('.result__snippet') || node.querySelector('.result__body') || node.querySelector('p'))?.textContent || ''
                        );

                        return {
                            position: index + 1,
                            title,
                            url,
                            snippet
                        };
                    }).filter((entry) => entry.title || entry.url || entry.snippet);
                }
            """),
            [],
            timeout_seconds
        )

    def _extract_answer_candidate(self, text, page_title=""):
        candidates = []
        normalized_title = self._compact_text(page_title).lower()
        for raw_line in re.split(r"[\r\n]+", text or ""):
            line = self._compact_text(raw_line)
            if len(line) < 50 or len(line) > 260:
                continue
            if self.BOILERPLATE_TEXT_PATTERN.search(line):
                continue
            if line.count("|") > 2:
                continue
            lowered_line = line.lower()
            if normalized_title and (
                lowered_line == normalized_title or
                (normalized_title in lowered_line and len(line) <= len(page_title) + 20)
            ):
                continue
            candidates.append(line)

        if candidates:
            return candidates[0]

        normalized_text = self._compact_text(text)
        if not normalized_text:
            return ""

        if len(normalized_text) <= 260:
            return normalized_text

        truncated = normalized_text[:260].rsplit(" ", 1)[0].strip()
        return truncated or normalized_text[:260]

    def _build_search_response(self, query, search_results, landing_snapshot, search_snapshot):
        active_snapshot = landing_snapshot or search_snapshot
        primary_result = search_results[0] if search_results else {}

        answer = ""
        if landing_snapshot:
            answer = self._extract_answer_candidate(
                landing_snapshot.get("text_content", ""),
                landing_snapshot.get("title", "")
            )

        primary_snippet = self._compact_text(primary_result.get("snippet", ""))
        if answer and primary_snippet and len(answer) < 80 and not re.search(r"[.!?]", answer):
            answer = primary_snippet

        if not answer:
            answer = primary_snippet

        if not answer and active_snapshot:
            answer = self._extract_answer_candidate(
                active_snapshot.get("text_content", ""),
                active_snapshot.get("title", "")
            )

        if not answer:
            answer = f"Headless search completed for '{query}', but no concise answer could be extracted."

        preview_lines = [answer]
        source_lines = []
        for result in search_results[:3]:
            title = self._compact_text(result.get("title", ""))
            snippet = self._compact_text(result.get("snippet", ""))
            if title and snippet and snippet.lower() not in title.lower():
                source_lines.append(f"{title} - {snippet}")
            elif title:
                source_lines.append(title)
            elif snippet:
                source_lines.append(snippet)

        if source_lines:
            preview_lines.append("")
            preview_lines.append("Top results:")
            for index, line in enumerate(source_lines, start=1):
                preview_lines.append(f"{index}. {line}")

        preview_text = "\n".join(preview_lines).strip()
        return {
            "answer": answer,
            "preview_text": preview_text[:1200],
            "source_url": (landing_snapshot or {}).get("final_url") or primary_result.get("url", ""),
            "source_title": (landing_snapshot or {}).get("title") or primary_result.get("title", "")
        }

    def _run_search_task(self, page, query, timeout_seconds, should_remove_images):
        search_url = self._build_search_url(query)
        search_response = self._navigate_page(page, search_url, timeout_seconds)
        search_snapshot = self._collect_page_snapshot(
            page,
            search_url,
            search_response,
            timeout_seconds,
            should_remove_images
        )
        search_results = self._extract_search_results(page, timeout_seconds)
        selected_result = next((item for item in search_results if item.get("url")), None)

        landing_snapshot = None
        landing_error = None
        if selected_result and selected_result.get("url"):
            try:
                landing_response = self._navigate_page(page, selected_result["url"], timeout_seconds)
                landing_snapshot = self._collect_page_snapshot(
                    page,
                    selected_result["url"],
                    landing_response,
                    timeout_seconds,
                    should_remove_images
                )
            except Exception as error:
                landing_error = str(error)

        active_snapshot = landing_snapshot or search_snapshot
        search_response_data = self._build_search_response(query, search_results, landing_snapshot, search_snapshot)

        return {
            "mode": "search",
            "input": query,
            "query": query,
            "target_url": search_url,
            "final_url": active_snapshot["final_url"],
            "title": active_snapshot["title"],
            "response_status": active_snapshot["response_status"],
            "content_type": active_snapshot["content_type"],
            "text_length": active_snapshot["text_length"],
            "text_preview": search_response_data["preview_text"],
            "image_count": active_snapshot["image_count"],
            "link_count": active_snapshot["link_count"],
            "answer": search_response_data["answer"],
            "source_title": search_response_data["source_title"],
            "source_url": search_response_data["source_url"],
            "search_result_count": len(search_results),
            "search_results": search_results,
            "selected_result": selected_result,
            "search_page_url": search_url,
            "landing_error": landing_error
        }

    def _read_page_with_retry(self, page, reader, fallback, timeout_seconds, retries=4):
        for attempt in range(retries):
            try:
                return reader()
            except Exception as error:
                if not self._is_transient_page_context_error(error):
                    raise

                if attempt == retries - 1:
                    return fallback

                self._wait_for_page_settle(page, timeout_seconds)

        return fallback

    def run(self, payload):
        request_payload = payload if isinstance(payload, dict) else {}
        run_id = uuid.uuid4().hex[:12]

        with self.lock:
            if self.state["running"]:
                return {
                    "success": False,
                    "error": "Local browser runner is busy with another job."
                }, 409
            self.state["running"] = True
            self.state["last_run_id"] = run_id
            self.state["last_started_at"] = datetime.now().isoformat()

        try:
            if not self.available:
                raise RuntimeError(
                    "Playwright is not installed. Run: pip install playwright && python -m playwright install chromium"
                )

            target = self._resolve_target(
                request_payload.get("url") or request_payload.get("target") or request_payload.get("query")
            )
            headless = bool(request_payload.get("headless", True))
            lightweight_mode = bool(request_payload.get("lightweightMode", True))
            text_only_mode = bool(request_payload.get("textOnlyMode", False))
            allow_images = bool(request_payload.get("allowImages", True))
            timeout_seconds = int(request_payload.get("timeoutSeconds", 20))
            timeout_seconds = max(5, min(timeout_seconds, 90))

            start_time = time.time()
            with self._sync_playwright() as playwright:
                launch_args = [
                    "--disable-background-networking",
                    "--disable-sync",
                    "--disable-default-apps",
                    "--disable-component-update",
                    "--no-first-run"
                ]
                if lightweight_mode:
                    launch_args.extend([
                        "--disable-gpu",
                        "--disable-renderer-backgrounding",
                        "--disable-dev-shm-usage"
                    ])

                browser = playwright.chromium.launch(
                    headless=headless,
                    args=launch_args
                )

                context = browser.new_context(
                    ignore_https_errors=True,
                    user_agent=self.DEFAULT_USER_AGENT,
                    locale="en-US",
                    viewport={"width": 1366, "height": 900}
                )

                blocked_resource_types = set()
                if lightweight_mode:
                    blocked_resource_types.add("font")
                if text_only_mode:
                    blocked_resource_types.update(["stylesheet", "media", "image"])
                if not allow_images:
                    blocked_resource_types.add("image")

                should_remove_images = text_only_mode or not allow_images
                if should_remove_images:
                    self._install_image_dom_blocker(context)

                blocked_request_count = 0

                if blocked_resource_types:
                    def route_handler(route):
                        nonlocal blocked_request_count
                        request_url = route.request.url or ""
                        resource_type = route.request.resource_type
                        should_block = resource_type in blocked_resource_types

                        if not should_block and text_only_mode and self.MEDIA_EXTENSION_PATTERN.search(request_url):
                            should_block = True

                        if not should_block and not allow_images and self.MEDIA_EXTENSION_PATTERN.search(request_url):
                            if resource_type in ("image", "media", "other"):
                                should_block = True

                        if should_block:
                            blocked_request_count += 1
                            route.abort()
                        else:
                            route.continue_()

                    context.route("**/*", route_handler)

                page = context.new_page()
                page.set_default_timeout(timeout_seconds * 1000)
                if target["mode"] == "search":
                    result = self._run_search_task(
                        page,
                        target["query"],
                        timeout_seconds,
                        should_remove_images
                    )
                else:
                    response = self._navigate_page(page, target["target_url"], timeout_seconds)
                    snapshot = self._collect_page_snapshot(
                        page,
                        target["target_url"],
                        response,
                        timeout_seconds,
                        should_remove_images
                    )
                    result = {
                        "mode": "browse",
                        "input": target["input"],
                        "query": None,
                        "answer": "",
                        "target_url": target["target_url"],
                        "final_url": snapshot["final_url"],
                        "title": snapshot["title"],
                        "response_status": snapshot["response_status"],
                        "content_type": snapshot["content_type"],
                        "text_length": snapshot["text_length"],
                        "text_preview": snapshot["text_preview"],
                        "image_count": snapshot["image_count"],
                        "link_count": snapshot["link_count"]
                    }

                context.close()
                browser.close()

            elapsed_ms = int((time.time() - start_time) * 1000)
            result = {
                **result,
                "run_id": run_id,
                "blocked_request_count": blocked_request_count,
                "blocked_resource_types": sorted(blocked_resource_types),
                "elapsed_ms": elapsed_ms,
                "options": {
                    "headless": headless,
                    "lightweightMode": lightweight_mode,
                    "textOnlyMode": text_only_mode,
                    "allowImages": allow_images,
                    "timeoutSeconds": timeout_seconds
                },
                "timestamp": datetime.now().isoformat()
            }

            with self.lock:
                self.state["last_completed_at"] = datetime.now().isoformat()
                self.state["last_error"] = None
                self.state["last_result"] = result

            return {
                "success": True,
                "result": result
            }, 200

        except ValueError as error:
            message = str(error)
            with self.lock:
                self.state["last_completed_at"] = datetime.now().isoformat()
                self.state["last_error"] = message
                self.state["last_result"] = None
            return {
                "success": False,
                "run_id": run_id,
                "error": message
            }, 400
        except RuntimeError as error:
            message = str(error)
            with self.lock:
                self.state["last_completed_at"] = datetime.now().isoformat()
                self.state["last_error"] = message
                self.state["last_result"] = None
            return {
                "success": False,
                "run_id": run_id,
                "error": message
            }, 503
        except Exception as error:
            message = f"Local browser run failed: {error}"
            with self.lock:
                self.state["last_completed_at"] = datetime.now().isoformat()
                self.state["last_error"] = message
                self.state["last_result"] = None
            return {
                "success": False,
                "run_id": run_id,
                "error": message
            }, 500
        finally:
            with self.lock:
                self.state["running"] = False

# Initialize managers
session_manager = ExtensionSessionManager()
request_logger = ExtensionRequestLogger()
local_browser_runner = LocalBrowserRunner()

# Start cleanup thread
def cleanup_worker():
    while True:
        time.sleep(300)  # Run every 5 minutes
        cleaned = session_manager.cleanup_expired_sessions()
        if cleaned > 0:
            print(f"[Extension Server] Cleaned up {cleaned} expired sessions")

cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
cleanup_thread.start()

@app.route('/')
def dashboard():
    """Extension server dashboard"""
    return render_template('extension_dashboard.html')

@app.route('/api/status')
def api_status():
    """Extension server status"""
    return jsonify({
        "server": "extension_server",
        "status": "running",
        "version": "1.0.0",
        "active_sessions": len(session_manager.get_all_sessions()),
        "total_requests": len(request_logger.requests),
        "uptime": "running",
        "timestamp": datetime.now().isoformat()
    })


@app.route('/api/local-browser/status', methods=['GET'])
def api_local_browser_status():
    """Get local headless browser runner status."""
    return jsonify({
        "success": True,
        "runner": local_browser_runner.status(),
        "timestamp": datetime.now().isoformat()
    })


@app.route('/api/local-browser/run', methods=['POST'])
def api_local_browser_run():
    """Run a local headless browser extraction job."""
    payload = request.json or {}
    response, status_code = local_browser_runner.run(payload)
    response["timestamp"] = datetime.now().isoformat()
    return jsonify(response), status_code

@app.route('/api/session/create', methods=['POST'])
def api_create_session():
    """Create new extension session"""
    try:
        data = request.json or {}
        session_id, session = session_manager.create_session(data)
        
        return jsonify({
            "success": True,
            "session_id": session_id,
            "session": session,
            "message": "Extension session created successfully"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/session/<session_id>', methods=['GET'])
def api_get_session(session_id):
    """Get session details"""
    session = session_manager.get_session(session_id)
    if session:
        return jsonify({
            "success": True,
            "session": session
        })
    else:
        return jsonify({
            "success": False,
            "error": "Session not found"
        }), 404

@app.route('/api/session/<session_id>/update', methods=['POST'])
def api_update_session(session_id):
    """Update session"""
    try:
        data = request.json or {}
        if session_manager.update_session(session_id, data):
            return jsonify({
                "success": True,
                "message": "Session updated successfully"
            })
        else:
            return jsonify({
                "success": False,
                "error": "Session not found"
            }), 404
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/session/<session_id>/end', methods=['POST'])
def api_end_session(session_id):
    """End session"""
    try:
        data = request.json or {}
        reason = data.get('reason', 'manual')
        
        if session_manager.end_session(session_id, reason):
            return jsonify({
                "success": True,
                "message": f"Session ended: {reason}"
            })
        else:
            return jsonify({
                "success": False,
                "error": "Session not found"
            }), 404
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/sessions', methods=['GET'])
def api_get_all_sessions():
    """Get all active sessions"""
    sessions = session_manager.get_all_sessions()
    return jsonify({
        "success": True,
        "sessions": sessions,
        "count": len(sessions)
    })

@app.route('/api/request/log', methods=['POST'])
def api_log_request():
    """Log extension request"""
    try:
        data = request.json or {}
        session_id = data.get('session_id')
        
        if not session_id:
            return jsonify({
                "success": False,
                "error": "Session ID required"
            }), 400
        
        log_entry = request_logger.log_request(session_id, data)
        
        # Update session statistics
        session = session_manager.get_session(session_id)
        if session:
            updates = {
                "requests_count": session.get("requests_count", 0) + 1,
                "last_activity": datetime.now().isoformat()
            }
            
            if data.get('decision') == 'blocked':
                updates["blocked_requests"] = session.get("blocked_requests", 0) + 1
            elif data.get('decision') == 'allowed':
                updates["allowed_requests"] = session.get("allowed_requests", 0) + 1
            
            session_manager.update_session(session_id, updates)
        
        return jsonify({
            "success": True,
            "log_entry": log_entry
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/requests/recent', methods=['GET'])
def api_get_recent_requests():
    """Get recent requests"""
    limit = request.args.get('limit', 100, type=int)
    requests = request_logger.get_recent_requests(limit)
    
    return jsonify({
        "success": True,
        "requests": requests,
        "count": len(requests)
    })

@app.route('/api/sync/rules', methods=['GET'])
def api_sync_rules():
    """Sync rules from main backend"""
    try:
        # Try to get rules from main backend
        import requests
        response = requests.get(f'{BACKEND_API_BASE}/rules/current', timeout=5)
        
        if response.status_code == 200:
            rules = response.json()
            return jsonify({
                "success": True,
                "rules": rules,
                "source": "backend",
                "timestamp": datetime.now().isoformat()
            })
        else:
            raise Exception("Backend not responding")
            
    except Exception as e:
        # Fallback to default rules
        default_rules = {
            "blocked_domains": [
                "malicious.com", "evil.net", "badware.io", "malwarehost.xyz",
                "phishing-site.io", "fake-bank.com", "amazon-verify.xyz"
            ],
            "whitelisted_domains": [
                "google.com", "github.com", "stackoverflow.com", "youtube.com"
            ],
            "dangerous_extensions": [".exe", ".dll", ".bat", ".scr"],
            "version": 1,
            "last_updated": datetime.now().isoformat()
        }
        
        return jsonify({
            "success": True,
            "rules": default_rules,
            "source": "fallback",
            "timestamp": datetime.now().isoformat(),
            "warning": f"Using fallback rules: {str(e)}"
        })

@app.route('/api/health', methods=['GET'])
def api_health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "session_manager": "running",
            "request_logger": "running",
            "cleanup_worker": "running"
        }
    })

if __name__ == '__main__':
    print("="*80)
    print("CHROME EXTENSION SERVER STARTED")
    print("="*80)
    print(f"Server running on: http://{SERVER_HOST}:{SERVER_PORT}")
    print(f"Dashboard: http://{SERVER_HOST}:{SERVER_PORT}/")
    print(f"API: http://{SERVER_HOST}:{SERVER_PORT}/api/")
    print(f"Rule sync target: {BACKEND_API_BASE}")
    print()
    print("Available endpoints:")
    print("  GET  /api/status")
    print("  POST /api/session/create")
    print("  GET  /api/sessions")
    print("  POST /api/request/log")
    print("  GET  /api/requests/recent")
    print("  GET  /api/sync/rules")
    print("  GET  /api/local-browser/status")
    print("  POST /api/local-browser/run")
    print("  GET  /api/health")
    print()
    
    app.run(debug=False, host=SERVER_HOST, port=SERVER_PORT)
