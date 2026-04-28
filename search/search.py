import atexit
import argparse
import importlib.util
import json
import re
import sys
import time
import urllib3
from datetime import datetime
from pathlib import Path
from threading import Lock, Thread
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from ddgs import DDGS
from flask import Flask, jsonify, render_template, request

try:
    from playwright.sync_api import sync_playwright
except Exception:
    sync_playwright = None

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
BACKEND_DIR = ROOT_DIR / "backend"
SEARCH_RUNTIME_DIR = BACKEND_DIR / "search_runtime"
DATA_LIFECYCLE_MODULE_PATH = BACKEND_DIR / "data_lifecycle.py"
INDEXED_URLS_FILE = SEARCH_RUNTIME_DIR / "indexed_urls.txt"
SEARCH_STATE_FILE = SEARCH_RUNTIME_DIR / "search_state.json"
RULE_EXPORT_FILE = SEARCH_RUNTIME_DIR / "extracted_rules.txt"
SERVER_STDOUT_LOG_FILE = SEARCH_RUNTIME_DIR / "search_server.out.log"
SERVER_STDERR_LOG_FILE = SEARCH_RUNTIME_DIR / "search_server.err.log"
LEGACY_INDEXED_URLS_FILE = BASE_DIR / "indexed_urls.txt"
LEGACY_SEARCH_STATE_FILE = BASE_DIR / "search_state.json"
LEGACY_RULE_EXPORT_FILE = BASE_DIR / "extracted_rules.txt"
LEGACY_SERVER_STDOUT_LOG_FILE = BASE_DIR / "search_server.out.log"
LEGACY_SERVER_STDERR_LOG_FILE = BASE_DIR / "search_server.err.log"
DEFAULT_SEARCH_PORT = 4000
DEFAULT_ADMIN_PORT = 3800
LOCAL_ADMIN_HOST = "localhost"
MAX_SEARCH_RESULTS = 25
MAX_FETCH_LINKS = 30
LOCAL_SEARCH_FALLBACK_RESULTS = 25
MAX_INDEX_PREVIEW = 25
DEFAULT_DELAY_MS = 2000
MAX_DELAY_MS = 300000
BROWSER_NAVIGATION_TIMEOUT_MS = 15000
BROWSER_NETWORK_IDLE_TIMEOUT_MS = 1500
BROWSER_SETTLE_DELAY_MS = 1500
REQUEST_CONNECT_TIMEOUT_SECONDS = 2
REQUEST_READ_TIMEOUT_SECONDS = 4
MAX_FETCH_BYTES = 262144
MAX_CONTENT_CHARS = 12000
MAX_FETCH_HTML_CHARS = 300000
MIN_REQUESTS_CONTENT_CHARS_FOR_SUCCESS = 400
BROWSER_RENDER_HOSTS = {
    "notion.site",
    "www.notion.site",
    "notion.so",
    "www.notion.so"
}
TEXT_ONLY_FALLBACK_HOSTS = {
    "youtube.com",
    "www.youtube.com",
    "m.youtube.com",
    "music.youtube.com",
    "tv.youtube.com",
    "instagram.com",
    "www.instagram.com"
}
AUTO_RULE_SOURCE_FILES = [
    ROOT_DIR / "firewall_rules.json",
    ROOT_DIR / "local_engine" / "firewall_rules.json",
    ROOT_DIR / "backend" / "rules_database.json",
    ROOT_DIR / "backend" / "console_firewall_policy.json"
]
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/136.0.0.0 Safari/537.36"
)
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
LOCAL_REMOTE_ADDRESSES = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}
DEFAULT_STATE = {
    "blocked_patterns": [],
    "delayed_patterns": [],
    "last_updated": None,
    "last_rule_extract": None
}
LOCAL_BACKUP_ALLOWED = False
search_app = Flask("firewall_guard_search", root_path=str(BASE_DIR), template_folder="templates")
admin_app = Flask("firewall_guard_admin", root_path=str(BASE_DIR), template_folder="templates")
ALL_APPS = (search_app, admin_app)

storage_lock = Lock()
_logging_configured = False
current_admin_port = DEFAULT_ADMIN_PORT
_state_cache = {"mtime_ns": None, "data": None}
_indexed_urls_cache = {"mtime_ns": None, "urls": None}
requests_session = requests.Session()
_data_lifecycle_helpers = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def now_iso():
    return datetime.now().isoformat()


def admin_base_url(port=None):
    return f"http://{LOCAL_ADMIN_HOST}:{port or current_admin_port}"


class TeeStream:
    def __init__(self, original_stream, log_path):
        self.original_stream = original_stream
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.file_handle = self.log_path.open("a", encoding="utf-8", buffering=1)
        atexit.register(self.close)

    @property
    def encoding(self):
        return getattr(self.original_stream, "encoding", "utf-8")

    def write(self, data):
        if isinstance(data, bytes):
            text = data.decode("utf-8", errors="replace")
        else:
            text = data if isinstance(data, str) else str(data)
        try:
            self.original_stream.write(text)
        except Exception:
            pass
        try:
            if self.file_handle and not self.file_handle.closed:
                self.file_handle.write(text)
        except Exception:
            pass
        return len(text)

    def flush(self):
        try:
            self.original_stream.flush()
        except Exception:
            pass
        try:
            if self.file_handle and not self.file_handle.closed:
                self.file_handle.flush()
        except Exception:
            pass

    def isatty(self):
        return bool(getattr(self.original_stream, "isatty", lambda: False)())

    def close(self):
        try:
            if self.file_handle and not self.file_handle.closed:
                self.file_handle.flush()
                self.file_handle.close()
        except Exception:
            pass
        finally:
            self.file_handle = None


def configure_process_logs():
    global _logging_configured

    if _logging_configured:
        return

    sys.stdout = TeeStream(sys.stdout, SERVER_STDOUT_LOG_FILE)
    sys.stderr = TeeStream(sys.stderr, SERVER_STDERR_LOG_FILE)
    _logging_configured = True


def load_data_lifecycle_helpers():
    global _data_lifecycle_helpers

    if _data_lifecycle_helpers is not None:
        return _data_lifecycle_helpers

    spec = importlib.util.spec_from_file_location(
        "firewall_guard_data_lifecycle",
        str(DATA_LIFECYCLE_MODULE_PATH)
    )
    if not spec or not spec.loader:
        raise ImportError(f"Unable to load data lifecycle helpers from {DATA_LIFECYCLE_MODULE_PATH}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _data_lifecycle_helpers = module
    return module


def evaluate_content_policy(url, page):
    summary = {
        "url": str(url or ""),
        "blocked": False,
        "block_rule": "",
        "block_pattern": "",
        "block_reason": "",
        "delay_ms": 0,
        "delay_rule": "",
        "delay_pattern": "",
        "delay_reason": "",
        "policy_version": None,
        "content_length": 0
    }

    content_parts = [str((page or {}).get("content") or "")]
    html = str((page or {}).get("html") or "")
    if html:
        content_parts.append(html[:MAX_FETCH_HTML_CHARS])
    combined_content = "\n".join(part for part in content_parts if part)
    summary["content_length"] = len(combined_content)

    if not combined_content.strip():
        return summary

    try:
        helpers = load_data_lifecycle_helpers()
        evaluator = getattr(helpers, "evaluate_search_content_policy", None)
        if callable(evaluator):
            return evaluator(combined_content, url=url)
    except Exception as error:
        log_error(f"Data lifecycle content policy evaluation failed for {url}: {error}")

    return summary


def migrate_legacy_runtime_files():
    SEARCH_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    runtime_files = (
        (LEGACY_INDEXED_URLS_FILE, INDEXED_URLS_FILE),
        (LEGACY_SEARCH_STATE_FILE, SEARCH_STATE_FILE),
        (LEGACY_RULE_EXPORT_FILE, RULE_EXPORT_FILE),
        (LEGACY_SERVER_STDOUT_LOG_FILE, SERVER_STDOUT_LOG_FILE),
        (LEGACY_SERVER_STDERR_LOG_FILE, SERVER_STDERR_LOG_FILE),
    )

    for legacy_path, target_path in runtime_files:
        if target_path.exists() or not legacy_path.exists():
            continue

        try:
            legacy_path.replace(target_path)
            print(f"[Search] {now_iso()} Moved runtime file {legacy_path} -> {target_path}")
        except Exception as error:
            try:
                if legacy_path.suffix.lower() in {".txt", ".json", ".log"}:
                    target_path.write_text(
                        legacy_path.read_text(encoding="utf-8", errors="ignore"),
                        encoding="utf-8"
                    )
                else:
                    target_path.write_bytes(legacy_path.read_bytes())
                legacy_path.unlink()
                print(f"[Search] {now_iso()} Copied runtime file {legacy_path} -> {target_path}")
            except Exception as copy_error:
                print(
                    f"[Search][Error] {now_iso()} Failed to move runtime file "
                    f"{legacy_path} -> {target_path}: {copy_error or error}",
                    file=sys.stderr
                )


def log_info(message):
    print(f"[Search] {now_iso()} {message}")


def log_error(message):
    print(f"[Search][Error] {now_iso()} {message}", file=sys.stderr)


def read_text(path):
    return Path(path).read_text(encoding="utf-8", errors="ignore")


def write_text(path, content):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def dedupe_strings(values):
    items = []
    seen = set()
    for value in values or []:
        text = str(value or "").strip()
        key = text.lower()
        if not text or key in seen:
            continue
        seen.add(key)
        items.append(text)
    return items


def normalize_url(raw_url):
    candidate = (raw_url or "").strip()
    if not candidate:
        raise ValueError("No URL provided")

    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are supported")
    if not parsed.netloc:
        raise ValueError("URL must include a valid host")
    return parsed.geturl()


def normalize_request_host(host_value):
    host = str(host_value or "").strip().lower()
    if not host:
        return ""
    if host.startswith("["):
        return host.split("]", 1)[0].strip("[]")
    return host.split(":", 1)[0]


def is_local_request():
    host = normalize_request_host(request.host)
    remote_addr = str(request.remote_addr or "").strip().lower()
    return host in LOCAL_HOSTS and remote_addr in LOCAL_REMOTE_ADDRESSES


def local_only_response():
    message = f"Firewall Guard admin page is available only through {admin_base_url()}/."
    wants_json = (
        request.path.startswith("/api/")
        or request.path in {"/search", "/fetch", "/health"}
        or "application/json" in str(request.headers.get("Accept") or "").lower()
    )
    if wants_json:
        return jsonify({"success": False, "error": message}), 403
    return message, 403, {"Content-Type": "text/plain; charset=utf-8"}


def extract_hostname(raw_url):
    try:
        return (urlparse(normalize_url(raw_url)).hostname or "").lower()
    except Exception:
        return ""


def domain_matches(hostname, rule_domain):
    host = str(hostname or "").strip(".").lower()
    rule = str(rule_domain or "").strip(".").lower()
    return bool(host and rule) and (host == rule or host.endswith(f".{rule}"))


def dedupe_links(links):
    unique = []
    seen = set()
    for link in links or []:
        try:
            url = normalize_url((link or {}).get("url", ""))
        except Exception:
            continue
        key = url.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append({"url": url, "text": (link or {}).get("text", "").strip() or url})
    return unique


def normalize_state(state):
    source = state if isinstance(state, dict) else {}
    delayed = []
    seen_delay = set()
    for item in source.get("delayed_patterns", []):
        rule = item if isinstance(item, dict) else {"pattern": item, "delay_ms": DEFAULT_DELAY_MS}
        pattern = str(rule.get("pattern") or "").strip()
        if not pattern or pattern.lower() in seen_delay:
            continue
        seen_delay.add(pattern.lower())
        try:
            delay_ms = int(rule.get("delay_ms", DEFAULT_DELAY_MS))
        except (TypeError, ValueError):
            delay_ms = DEFAULT_DELAY_MS
        delayed.append({"pattern": pattern, "delay_ms": max(0, min(delay_ms, MAX_DELAY_MS))})

    last_extract = source.get("last_rule_extract")
    if not isinstance(last_extract, dict):
        last_extract = None

    return {
        "blocked_patterns": dedupe_strings(source.get("blocked_patterns", [])),
        "delayed_patterns": delayed,
        "last_updated": str(source.get("last_updated") or now_iso()),
        "last_rule_extract": last_extract
    }


def clone_state(state):
    current = normalize_state(state)
    return {
        "blocked_patterns": list(current.get("blocked_patterns", [])),
        "delayed_patterns": [dict(item) for item in current.get("delayed_patterns", [])],
        "last_updated": current.get("last_updated"),
        "last_rule_extract": dict(current["last_rule_extract"]) if isinstance(current.get("last_rule_extract"), dict) else None
    }


def load_state():
    with storage_lock:
        if not SEARCH_STATE_FILE.exists():
            state = normalize_state(DEFAULT_STATE)
            write_text(SEARCH_STATE_FILE, json.dumps(state, indent=2))
            _state_cache["mtime_ns"] = SEARCH_STATE_FILE.stat().st_mtime_ns
            _state_cache["data"] = state
            return clone_state(state)

        try:
            current_mtime_ns = SEARCH_STATE_FILE.stat().st_mtime_ns
        except OSError:
            current_mtime_ns = None

        if _state_cache["data"] is not None and _state_cache["mtime_ns"] == current_mtime_ns:
            return clone_state(_state_cache["data"])

        try:
            state = normalize_state(json.loads(read_text(SEARCH_STATE_FILE)))
        except Exception:
            state = normalize_state(DEFAULT_STATE)
            write_text(SEARCH_STATE_FILE, json.dumps(state, indent=2))
            current_mtime_ns = SEARCH_STATE_FILE.stat().st_mtime_ns

        _state_cache["mtime_ns"] = current_mtime_ns
        _state_cache["data"] = state
        return clone_state(state)


def save_state(state):
    with storage_lock:
        normalized = normalize_state(state)
        write_text(SEARCH_STATE_FILE, json.dumps(normalized, indent=2))
        _state_cache["mtime_ns"] = SEARCH_STATE_FILE.stat().st_mtime_ns
        _state_cache["data"] = normalized
        return clone_state(normalized)


def load_indexed_urls():
    with storage_lock:
        if not INDEXED_URLS_FILE.exists():
            write_text(INDEXED_URLS_FILE, "")
            _indexed_urls_cache["mtime_ns"] = INDEXED_URLS_FILE.stat().st_mtime_ns
            _indexed_urls_cache["urls"] = []
            return []

        try:
            current_mtime_ns = INDEXED_URLS_FILE.stat().st_mtime_ns
        except OSError:
            current_mtime_ns = None

        if _indexed_urls_cache["urls"] is not None and _indexed_urls_cache["mtime_ns"] == current_mtime_ns:
            return list(_indexed_urls_cache["urls"])

        urls = []
        seen = set()
        for line in read_text(INDEXED_URLS_FILE).splitlines():
            item = line.strip()
            key = item.lower()
            if not item or key in seen:
                continue
            seen.add(key)
            urls.append(item)
        _indexed_urls_cache["mtime_ns"] = current_mtime_ns
        _indexed_urls_cache["urls"] = list(urls)
        return urls


def append_indexed_urls(urls):
    valid = []
    for value in urls or []:
        try:
            valid.append(normalize_url(value))
        except Exception:
            continue

    with storage_lock:
        if not INDEXED_URLS_FILE.exists():
            write_text(INDEXED_URLS_FILE, "")
            current = []
        else:
            current = []
            seen_current = set()
            for line in read_text(INDEXED_URLS_FILE).splitlines():
                item = line.strip()
                if not item or item.lower() in seen_current:
                    continue
                seen_current.add(item.lower())
                current.append(item)
        seen = {item.lower() for item in current}
        added = 0
        for item in valid:
            if item.lower() in seen:
                continue
            seen.add(item.lower())
            current.append(item)
            added += 1
        write_text(INDEXED_URLS_FILE, ("\n".join(current) + "\n") if current else "")
        _indexed_urls_cache["mtime_ns"] = INDEXED_URLS_FILE.stat().st_mtime_ns
        _indexed_urls_cache["urls"] = list(current)
        return {"added": added, "count": len(current), "file": str(INDEXED_URLS_FILE)}


def wildcard_to_regex(pattern):
    return "^" + "".join(".*" if char == "*" else re.escape(char) for char in pattern) + "$"


def match_url_pattern(url, pattern):
    target = str(url or "").strip().lower()
    candidate = str(pattern or "").strip()
    lowered = candidate.lower()
    host = extract_hostname(url)

    if not target or not candidate:
        return False
    if lowered.startswith("regex:"):
        try:
            return re.search(candidate.split(":", 1)[1].strip(), target, re.IGNORECASE) is not None
        except re.error:
            return False
    if lowered.startswith("domain:") or lowered.startswith("host:"):
        return domain_matches(host, candidate.split(":", 1)[1].strip())
    if lowered.startswith("url:"):
        expected = candidate.split(":", 1)[1].strip().lower()
        return target == expected or target.startswith(expected)
    if "*" in candidate:
        regex = wildcard_to_regex(lowered)
        return bool(re.match(regex, target) or re.match(regex, host))
    if "://" in candidate:
        return target == lowered or target.startswith(lowered)
    if "/" in candidate:
        return lowered in target
    return domain_matches(host, lowered) or lowered in target


def evaluate_url_policy(url, state=None):
    current_state = state or load_state()
    for pattern in current_state.get("blocked_patterns", []):
        if match_url_pattern(url, pattern):
            return {"blocked": True, "block_pattern": pattern, "delay_ms": 0, "delay_pattern": ""}

    delay_ms = 0
    delay_pattern = ""
    for rule in current_state.get("delayed_patterns", []):
        if match_url_pattern(url, rule.get("pattern")) and int(rule.get("delay_ms", 0)) >= delay_ms:
            delay_ms = int(rule.get("delay_ms", 0))
            delay_pattern = str(rule.get("pattern") or "")

    return {"blocked": False, "block_pattern": "", "delay_ms": delay_ms, "delay_pattern": delay_pattern}


def annotate_links(links, state=None):
    current_state = state or load_state()
    annotated = []
    for link in dedupe_links(links):
        policy = evaluate_url_policy(link["url"], current_state)
        annotated.append({
            "url": link["url"],
            "text": link["text"],
            "hostname": extract_hostname(link["url"]),
            "blocked": policy["blocked"],
            "block_pattern": policy["block_pattern"],
            "delay_ms": policy["delay_ms"],
            "delay_pattern": policy["delay_pattern"]
        })
    return annotated


def search_local_index(query, limit=LOCAL_SEARCH_FALLBACK_RESULTS, state=None):
    terms = [part for part in re.split(r"\s+", str(query or "").strip().lower()) if part]
    if not terms:
        return []

    matches = []
    for url in reversed(load_indexed_urls()):
        target = url.lower()
        score = 0
        for term in terms:
            if term in target:
                score += 2 if target.startswith("http") and term in extract_hostname(url) else 1
        if score:
            matches.append({"url": url, "text": url, "score": score})

    matches.sort(key=lambda item: (-item["score"], item["url"]))
    links = [{"url": item["url"], "text": item["text"]} for item in matches[:limit]]
    return annotate_links(links, state)


def build_text_only_fallback(url, reason):
    hostname = extract_hostname(url) or "unknown-host"
    lines = [
        "Text-only output is not available for this page.",
        f"URL: {url}",
        f"Host: {hostname}",
        "",
        f"Reason: {reason}",
        "",
        "This site likely blocks lightweight scraping or depends heavily on dynamic scripts.",
        "Try another result such as Wikipedia, docs, blogs, or static pages."
    ]
    return {
        "content": "\n".join(lines),
        "html": "",
        "links": [],
        "fetch_mode": "fallback",
        "url": url
    }


def update_block_pattern(pattern, remove=False):
    state = load_state()
    target = str(pattern or "").strip()
    if not target:
        raise ValueError("Enter a URL pattern.")
    blocked = state.get("blocked_patterns", [])
    if remove:
        blocked = [item for item in blocked if item.lower() != target.lower()]
    elif target.lower() not in {item.lower() for item in blocked}:
        blocked.append(target)
    state["blocked_patterns"] = dedupe_strings(blocked)
    state["last_updated"] = now_iso()
    return save_state(state)


def update_delay_pattern(pattern, delay_ms=None, remove=False):
    state = load_state()
    target = str(pattern or "").strip()
    if not target:
        raise ValueError("Enter a URL pattern.")
    delayed = []
    replaced = False
    if not remove:
        try:
            delay_ms = int(delay_ms)
        except (TypeError, ValueError):
            delay_ms = DEFAULT_DELAY_MS
        delay_ms = max(0, min(delay_ms, MAX_DELAY_MS))

    for rule in state.get("delayed_patterns", []):
        if str(rule.get("pattern") or "").lower() == target.lower():
            if remove:
                continue
            delayed.append({"pattern": target, "delay_ms": delay_ms})
            replaced = True
            continue
        delayed.append(rule)

    if not remove and not replaced:
        delayed.append({"pattern": target, "delay_ms": delay_ms})

    state["delayed_patterns"] = delayed
    state["last_updated"] = now_iso()
    return save_state(state)


def fetch_page_with_browser(url):
    if sync_playwright is None:
        raise RuntimeError("Playwright is not installed")

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            args=["--disable-gpu", "--disable-dev-shm-usage", "--no-first-run"]
        )
        context = browser.new_context(
            ignore_https_errors=True,
            user_agent=BROWSER_USER_AGENT,
            viewport={"width": 1366, "height": 900}
        )
        page = context.new_page()
        page.set_default_timeout(BROWSER_NAVIGATION_TIMEOUT_MS)
        try:
            page.goto(url, wait_until="commit")
            try:
                page.wait_for_load_state("domcontentloaded", timeout=BROWSER_NETWORK_IDLE_TIMEOUT_MS)
            except Exception:
                pass
            try:
                page.wait_for_load_state("networkidle", timeout=BROWSER_NETWORK_IDLE_TIMEOUT_MS)
            except Exception:
                pass
            page.wait_for_timeout(BROWSER_SETTLE_DELAY_MS)
            html = page.content() or ""
            text = page.evaluate("() => document.body ? (document.body.innerText || '') : ''") or ""
            links = page.evaluate(
                """
                () => Array.from(document.querySelectorAll('a[href]')).map((anchor) => {
                    const rawHref = anchor.getAttribute('href') || anchor.href || '';
                    const text = (anchor.innerText || anchor.textContent || '').trim();
                    try {
                        const normalized = new URL(rawHref, window.location.href);
                        if (!['http:', 'https:'].includes(normalized.protocol)) return null;
                        return { url: normalized.href, text: text || normalized.href };
                    } catch (error) {
                        return null;
                    }
                }).filter(Boolean)
                """
            ) or []
        finally:
            context.close()
            browser.close()

    return {
        "content": text[:MAX_CONTENT_CHARS],
        "html": html[:MAX_FETCH_HTML_CHARS],
        "links": dedupe_links(links)[:MAX_FETCH_LINKS]
    }


def fetch_page_with_requests(url):
    response = requests_session.get(
        url,
        headers={
            "User-Agent": BROWSER_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9"
        },
        timeout=(REQUEST_CONNECT_TIMEOUT_SECONDS, REQUEST_READ_TIMEOUT_SECONDS),
        verify=False,
        allow_redirects=True,
        stream=True
    )
    response.raise_for_status()

    chunks = []
    total_bytes = 0
    for chunk in response.iter_content(chunk_size=16384, decode_unicode=False):
        if not chunk:
            continue
        chunks.append(chunk)
        total_bytes += len(chunk)
        if total_bytes >= MAX_FETCH_BYTES:
            break

    raw_html = b"".join(chunks)
    encoding = response.encoding or response.apparent_encoding or "utf-8"
    html = raw_html.decode(encoding, errors="ignore")
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["img", "script", "style", "noscript"]):
        tag.decompose()
    links = []
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"]
        if href.startswith("/"):
            href = urljoin(url, href)
        if href.startswith("http") and "javascript" not in href:
            links.append({"url": href, "text": anchor.get_text(strip=True) or href})
        if len(links) >= MAX_FETCH_LINKS * 3:
            break

    text = soup.get_text(separator="\n")
    compact_lines = [line.strip() for line in text.splitlines() if line.strip()]
    compact_text = "\n".join(compact_lines)
    return {
        "content": compact_text[:MAX_CONTENT_CHARS],
        "html": html[:MAX_FETCH_HTML_CHARS],
        "links": dedupe_links(links)[:MAX_FETCH_LINKS]
    }


def hostname_matches_any_rule(hostname, patterns):
    return any(domain_matches(hostname, pattern) for pattern in patterns or [])


def should_retry_fetch_with_browser(url, page):
    hostname = extract_hostname(url)
    if hostname_matches_any_rule(hostname, BROWSER_RENDER_HOSTS):
        return True

    page_content = str((page or {}).get("content") or "").strip()
    page_links = (page or {}).get("links") or []
    page_html = str((page or {}).get("html") or "")

    if len(page_content) < MIN_REQUESTS_CONTENT_CHARS_FOR_SUCCESS:
        return True

    if not page_links and len(page_content) < MIN_REQUESTS_CONTENT_CHARS_FOR_SUCCESS * 2:
        return True

    title_match = re.search(r"<title[^>]*>(.*?)</title>", page_html, re.IGNORECASE | re.DOTALL)
    page_title = re.sub(r"\s+", " ", title_match.group(1)).strip().lower() if title_match else ""
    if page_title in {"notion", "just a moment...", "access denied"}:
        return True

    lowered_content = page_content.lower()
    if "enable javascript" in lowered_content and len(page_content) < 1500:
        return True

    return False


def fetch_page_for_search(url):
    hostname = extract_hostname(url)
    if hostname in TEXT_ONLY_FALLBACK_HOSTS:
        page = build_text_only_fallback(
            url,
            f"{hostname} is handled in fallback mode for faster text-only output."
        )
        return page, page.get("fetch_mode", "fallback")

    requests_page = None
    requests_error = None

    try:
        requests_page = fetch_page_with_requests(url)
        if not should_retry_fetch_with_browser(url, requests_page):
            return requests_page, "requests"
    except Exception as error:
        requests_error = error
        log_error(f"Requests fetch failed for {url}: {error}")

    if sync_playwright is not None:
        try:
            browser_page = fetch_page_with_browser(url)
            return browser_page, "browser"
        except Exception as error:
            log_error(f"Browser fetch failed for {url}: {error}")

    if requests_page is not None:
        return requests_page, "requests"

    fallback = build_text_only_fallback(url, str(requests_error or "Unable to load page"))
    return fallback, fallback.get("fetch_mode", "fallback")


def balanced_block(text, start, open_char, close_char):
    if start < 0 or start >= len(text) or text[start] != open_char:
        return ""
    depth = 0
    quote = None
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ("'", '"', "`"):
            quote = char
        elif char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    return ""


def keyed_block(text, key, open_char, close_char):
    match = re.search(rf"(?:['\"]?{re.escape(key)}['\"]?)\s*:\s*", text, re.IGNORECASE)
    if not match:
        return ""
    start = text.find(open_char, match.end())
    return balanced_block(text, start, open_char, close_char) if start >= 0 else ""


def string_literals(text):
    return [
        first if first is not None else second
        for first, second in re.findall(r'"((?:\\.|[^"\\])*)"|\'((?:\\.|[^\'\\])*)\'', text or "", re.DOTALL)
    ]


def object_blocks(array_text):
    blocks = []
    index = 0
    quote = None
    escaped = False
    while index < len(array_text):
        char = array_text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"', "`"):
            quote = char
            index += 1
            continue
        if char == "{":
            block = balanced_block(array_text, index, "{", "}")
            if not block:
                break
            blocks.append(block)
            index += len(block)
            continue
        index += 1
    return blocks


def field_string(block, key):
    match = re.search(rf"(?:['\"]?{re.escape(key)}['\"]?)\s*:\s*(['\"])(.*?)\1", block, re.IGNORECASE | re.DOTALL)
    return (match.group(2) or "").strip() if match else ""


def field_bool(block, key):
    match = re.search(rf"(?:['\"]?{re.escape(key)}['\"]?)\s*:\s*(true|false)", block, re.IGNORECASE)
    return None if not match else match.group(1).lower() == "true"


def field_array(block, key):
    return dedupe_strings(string_literals(keyed_block(block, key, "[", "]")))


def parse_policy_rules(text):
    rules_block = keyed_block(text, "rules", "[", "]")
    parsed = []
    for index, block in enumerate(object_blocks(rules_block), start=1):
        item = {
            "id": field_string(block, "id") or f"rule-{index}",
            "applies_to": field_array(block, "appliesTo"),
            "pattern": field_string(block, "pattern"),
            "severity": field_string(block, "severity"),
            "block": field_bool(block, "block"),
            "reason": field_string(block, "reason")
        }
        if any([item["id"], item["applies_to"], item["pattern"], item["severity"], item["block"] is not None, item["reason"]]):
            parsed.append(item)
    return parsed


def collection_values(text, key):
    return dedupe_strings(string_literals(keyed_block(text, key, "[", "]")))


def extract_rule_data(source_text):
    return {
        "grouped": {
            "blocked_domains": collection_values(source_text, "blocked_domains"),
            "whitelisted_domains": collection_values(source_text, "whitelisted_domains"),
            "dangerous_extensions": collection_values(source_text, "dangerous_extensions"),
            "suspicious_patterns": collection_values(source_text, "suspicious_patterns")
        },
        "policy_rules": parse_policy_rules(source_text)
    }


def format_rule_report(source_label, grouped, policy_rules):
    total = sum(len(values) for values in grouped.values()) + len(policy_rules)
    lines = [
        "Firewall Guard Rule Extraction",
        f"Extracted at: {now_iso()}",
        f"Source: {source_label}",
        f"Total extracted entries: {total}",
        f"Policy rules: {len(policy_rules)}",
        ""
    ]
    for key in ("blocked_domains", "whitelisted_domains", "dangerous_extensions", "suspicious_patterns"):
        values = grouped.get(key, [])
        if not values:
            continue
        lines.append(f"[{key}]")
        lines.extend(values)
        lines.append("")
    if policy_rules:
        lines.append("[policy_rules]")
        for index, rule in enumerate(policy_rules, start=1):
            lines.append(f"Rule {index}")
            lines.append(f"id: {rule.get('id') or ''}")
            lines.append("applies_to: " + ", ".join(rule.get("applies_to", [])))
            lines.append(f"pattern: {rule.get('pattern') or ''}")
            lines.append(f"severity: {rule.get('severity') or ''}")
            lines.append(
                f"block: {str(rule.get('block')).lower()}" if rule.get("block") is not None else "block: "
            )
            lines.append(f"reason: {rule.get('reason') or ''}")
            lines.append("")
    if total == 0:
        lines.append("No rules were found in the supplied text.")
    return "\n".join(lines).strip() + "\n", total


def resolve_input_path(value):
    candidate = Path(str(value or "").strip())
    if not str(candidate):
        raise ValueError("Provide an input file path.")
    if candidate.is_absolute():
        return candidate
    cwd_candidate = Path.cwd() / candidate
    return cwd_candidate if cwd_candidate.exists() else BASE_DIR / candidate


def resolve_output_path(value):
    candidate = Path(str(value or "").strip())
    if not str(candidate):
        return RULE_EXPORT_FILE
    return candidate if candidate.is_absolute() else SEARCH_RUNTIME_DIR / candidate


def build_auto_rule_report(source_summaries):
    generated_at = now_iso()
    total_sources = len(source_summaries)
    total_entries = sum(item["total_extracted"] for item in source_summaries)
    total_policy_rules = sum(len(item["policy_rules"]) for item in source_summaries)
    lines = [
        "Firewall Guard Automatic Rule Report",
        f"Generated at: {generated_at}",
        f"Sources scanned: {total_sources}",
        f"Total extracted entries: {total_entries}",
        f"Total policy rules: {total_policy_rules}",
        ""
    ]

    if not source_summaries:
        lines.append("No rule sources were found.")
        return "\n".join(lines).strip() + "\n", 0, 0

    for item in source_summaries:
        lines.append("=" * 80)
        lines.append(f"Source File: {item['source_label']}")
        lines.append("")
        section_report, _ = format_rule_report(item["source_label"], item["grouped"], item["policy_rules"])
        lines.append(section_report.rstrip())
        lines.append("")

    return "\n".join(lines).strip() + "\n", total_entries, total_policy_rules


def extract_rules_to_file(source_text, source_label, output_path=None):
    extracted = extract_rule_data(source_text)
    grouped = extracted["grouped"]
    policy_rules = extracted["policy_rules"]
    report, total = format_rule_report(source_label, grouped, policy_rules)
    target = resolve_output_path(output_path)
    write_text(target, report)

    state = load_state()
    state["last_rule_extract"] = {
        "timestamp": now_iso(),
        "output_file": str(target),
        "source_label": str(source_label),
        "total_extracted": total,
        "policy_rule_count": len(policy_rules)
    }
    state["last_updated"] = now_iso()
    save_state(state)
    log_info(f"Generated rule export from {source_label} -> {target}")

    return {
        "timestamp": state["last_rule_extract"]["timestamp"],
        "output_file": str(target),
        "source_label": str(source_label),
        "total_extracted": total,
        "policy_rule_count": len(policy_rules),
        "group_counts": {key: len(values) for key, values in grouped.items()},
        "preview": report[:4000]
    }


def collect_existing_rule_sources():
    return [path for path in AUTO_RULE_SOURCE_FILES if path.exists()]


def should_refresh_auto_rules(target_path, source_paths):
    target = Path(target_path)
    if not target.exists():
        return True

    target_mtime = target.stat().st_mtime
    return any(path.stat().st_mtime > target_mtime for path in source_paths)


def generate_automatic_rules_file(force=False):
    source_paths = collect_existing_rule_sources()
    if not force and not should_refresh_auto_rules(RULE_EXPORT_FILE, source_paths):
        return load_state().get("last_rule_extract")

    summaries = []
    for source_path in source_paths:
        extracted = extract_rule_data(read_text(source_path))
        summaries.append({
            "source_label": str(source_path),
            "grouped": extracted["grouped"],
            "policy_rules": extracted["policy_rules"],
            "total_extracted": sum(len(values) for values in extracted["grouped"].values()) + len(extracted["policy_rules"])
        })

    report, total_entries, total_policy_rules = build_auto_rule_report(summaries)
    write_text(RULE_EXPORT_FILE, report)

    state = load_state()
    state["last_rule_extract"] = {
        "timestamp": now_iso(),
        "output_file": str(RULE_EXPORT_FILE),
        "source_label": "automatic",
        "source_files": [str(path) for path in source_paths],
        "total_extracted": total_entries,
        "policy_rule_count": total_policy_rules
    }
    state["last_updated"] = now_iso()
    save_state(state)
    log_info(f"Auto-generated rules file from {len(source_paths)} source file(s)")
    return state["last_rule_extract"]


def build_state_payload():
    generate_automatic_rules_file()
    state = load_state()
    indexed_urls = load_indexed_urls()
    return {
        "indexed_url_count": len(indexed_urls),
        "indexed_urls_file": str(INDEXED_URLS_FILE),
        "indexed_urls_preview": list(reversed(indexed_urls[-MAX_INDEX_PREVIEW:])),
        "blocked_patterns": state.get("blocked_patterns", []),
        "delayed_patterns": state.get("delayed_patterns", []),
        "policy_file": str(SEARCH_STATE_FILE),
        "last_rule_extract": state.get("last_rule_extract"),
        "default_rule_export_file": str(RULE_EXPORT_FILE),
        "local_backup_allowed": LOCAL_BACKUP_ALLOWED,
        "timestamp": now_iso()
    }


def build_health_payload():
    state = load_state()
    indexed_urls = load_indexed_urls()
    return {
        "status": "ok",
        "service": "search_engine",
        "timestamp": now_iso(),
        "base_url": request.host_url.rstrip("/"),
        "indexed_url_count": len(indexed_urls),
        "blocked_patterns": len(state.get("blocked_patterns", [])),
        "delayed_patterns": len(state.get("delayed_patterns", []))
    }


def load_content_policy():
    try:
        helpers = load_data_lifecycle_helpers()
        loader = getattr(helpers, "load_search_content_policy", None)
        if callable(loader):
            return loader()
    except Exception as error:
        log_error(f"Unable to load search content policy: {error}")
    return {
        "version": 0,
        "updated_at": now_iso(),
        "blocked_content_patterns": [],
        "delayed_content_patterns": []
    }


def initialize_generated_files():
    load_state()
    load_indexed_urls()
    generate_automatic_rules_file(force=True)
    try:
        helpers = load_data_lifecycle_helpers()
        initializer = getattr(helpers, "load_search_content_policy", None)
        if callable(initializer):
            initializer()
    except Exception as error:
        log_error(f"Unable to initialize search content policy: {error}")


def make_before_request_handler(local_only=False):
    def before_request_logging():
        request._search_started_at = time.time()
        if local_only and not is_local_request():
            log_error(
                f"Rejected non-local request for {request.path} "
                f"(host={request.host}, remote={request.remote_addr})"
            )
            return local_only_response()

    return before_request_logging


def after_request_logging(response):
    started_at = getattr(request, "_search_started_at", time.time())
    duration_ms = int((time.time() - started_at) * 1000)
    log_info(f"{request.method} {request.path} -> {response.status_code} in {duration_ms}ms")
    return response


def search_home():
    return render_template("search_index.html", admin_base=admin_base_url())


def admin_home():
    return render_template("index.html")


def health():
    return jsonify(build_health_payload())


def api_state():
    return jsonify(build_state_payload())


def api_indexed_urls():
    urls = load_indexed_urls()
    return jsonify({"count": len(urls), "file": str(INDEXED_URLS_FILE), "urls": urls})


def api_content_policy():
    policy = load_content_policy()
    return jsonify({
        "success": True,
        "policy": policy,
        "timestamp": now_iso()
    })


def api_add_block():
    data = request.get_json(silent=True) or {}
    try:
        state = update_block_pattern(data.get("pattern"))
        log_info(f"Added blocked pattern: {data.get('pattern')}")
        return jsonify({"success": True, "blocked_patterns": state["blocked_patterns"]})
    except Exception as error:
        log_error(f"Failed to add blocked pattern: {error}")
        return jsonify({"success": False, "error": str(error)}), 400


def api_remove_block():
    data = request.get_json(silent=True) or {}
    try:
        state = update_block_pattern(data.get("pattern"), remove=True)
        log_info(f"Removed blocked pattern: {data.get('pattern')}")
        return jsonify({"success": True, "blocked_patterns": state["blocked_patterns"]})
    except Exception as error:
        log_error(f"Failed to remove blocked pattern: {error}")
        return jsonify({"success": False, "error": str(error)}), 400


def api_add_delay():
    data = request.get_json(silent=True) or {}
    try:
        state = update_delay_pattern(data.get("pattern"), data.get("delay_ms"))
        log_info(f"Added delayed pattern: {data.get('pattern')} ({data.get('delay_ms')}ms)")
        return jsonify({"success": True, "delayed_patterns": state["delayed_patterns"]})
    except Exception as error:
        log_error(f"Failed to add delayed pattern: {error}")
        return jsonify({"success": False, "error": str(error)}), 400


def api_remove_delay():
    data = request.get_json(silent=True) or {}
    try:
        state = update_delay_pattern(data.get("pattern"), remove=True)
        log_info(f"Removed delayed pattern: {data.get('pattern')}")
        return jsonify({"success": True, "delayed_patterns": state["delayed_patterns"]})
    except Exception as error:
        log_error(f"Failed to remove delayed pattern: {error}")
        return jsonify({"success": False, "error": str(error)}), 400


def api_extract_rules():
    data = request.get_json(silent=True) or {}
    source_path = str(data.get("source_path") or "").strip()
    source_text = str(data.get("source_text") or "")
    output_file = data.get("output_file")

    try:
        if source_path:
            resolved = resolve_input_path(source_path)
            if not resolved.exists():
                raise FileNotFoundError(f"Source file not found: {resolved}")
            summary = extract_rules_to_file(read_text(resolved), str(resolved), output_file)
        elif source_text.strip():
            summary = extract_rules_to_file(source_text, "pasted-text", output_file)
        else:
            raise ValueError("Paste text or provide a file path before extracting rules.")

        log_info(f"Manual rule extraction completed: {summary['output_file']}")
        return jsonify({"success": True, **summary})
    except Exception as error:
        log_error(f"Manual rule extraction failed: {error}")
        return jsonify({"success": False, "error": str(error)}), 400


def download_indexed_urls():
    log_info("Blocked local backup request for indexed URLs")
    return jsonify({
        "success": False,
        "error": "Local backup is disabled."
    }), 403


def download_extracted_rules():
    log_info("Blocked local backup request for extracted rules")
    return jsonify({
        "success": False,
        "error": "Local backup is disabled."
    }), 403


def search_api():
    query = (request.args.get("q") or "").strip()
    results = []
    if not query:
        return jsonify({"query": "", "count": 0, "indexed": append_indexed_urls([]), "results": []})

    source = "ddgs"
    try:
        with DDGS() as ddgs:
            for result in ddgs.text(query, max_results=MAX_SEARCH_RESULTS):
                href = result.get("href") or result.get("url")
                if href:
                    results.append({"url": href, "text": str(result.get("title") or href).strip()})
    except Exception as error:
        log_error(f"Search error for query '{query}': {error}")

    deduped = dedupe_links(results)[:MAX_SEARCH_RESULTS]
    if not deduped:
        source = "local-index"
        deduped = [
            {"url": item["url"], "text": item["text"]}
            for item in search_local_index(query, state=load_state())
        ]

    indexed = append_indexed_urls([item["url"] for item in deduped])
    log_info(
        f"Search query '{query}' returned {len(deduped)} result(s) from {source}; "
        f"indexed count is {indexed['count']}"
    )
    return jsonify({
        "query": query,
        "count": len(deduped),
        "indexed": indexed,
        "source": source,
        "results": annotate_links(deduped)
    })


def fetch_page():
    current_state = load_state()
    try:
        url = normalize_url(request.args.get("url"))
        policy = evaluate_url_policy(url, current_state)
        indexed = append_indexed_urls([url])

        if policy["blocked"]:
            log_info(f"Blocked fetch for {url} by pattern {policy['block_pattern']}")
            return jsonify({
                "url": url,
                "content": f"Blocked by search policy: {policy['block_pattern']}",
                "html": "",
                "links": [],
                "blocked": True,
                "policy": policy,
                "indexed": indexed
            }), 403

        if policy["delay_ms"] > 0:
            time.sleep(policy["delay_ms"] / 1000)

        page, fetch_mode = fetch_page_for_search(url)
        content_policy = evaluate_content_policy(url, page)
        total_delay_ms = int(policy["delay_ms"])

        indexed = append_indexed_urls([url, *[item["url"] for item in page["links"]]])
        log_info(f"Fetched {url} using {fetch_mode}; discovered {len(page['links'])} link(s)")
        return jsonify({
            "url": url,
            "content": page["content"],
            "html": page.get("html", ""),
            "links": annotate_links(page["links"], current_state),
            "blocked": False,
            "policy": policy,
            "content_policy": content_policy,
            "indexed": indexed,
            "delay_applied_ms": total_delay_ms,
            "fetch_mode": fetch_mode
        })
    except Exception as error:
        url = request.args.get("url") or ""
        log_error(f"Fetch error: {error}")
        fallback = build_text_only_fallback(url, str(error))
        return jsonify({
            "url": fallback["url"],
            "content": fallback["content"],
            "html": fallback.get("html", ""),
            "links": fallback["links"],
            "blocked": False,
            "policy": {"blocked": False, "block_pattern": "", "delay_ms": 0, "delay_pattern": ""},
            "content_policy": evaluate_content_policy(url, fallback),
            "indexed": append_indexed_urls([]),
            "fetch_mode": fallback["fetch_mode"],
            "delay_applied_ms": 0
        })


search_app.before_request(make_before_request_handler(local_only=True))
admin_app.before_request(make_before_request_handler(local_only=True))
search_app.after_request(after_request_logging)
admin_app.after_request(after_request_logging)

search_app.add_url_rule("/", view_func=search_home)
admin_app.add_url_rule("/", view_func=admin_home)
search_app.add_url_rule("/health", view_func=health)

for current_app in ALL_APPS:
    current_app.add_url_rule("/search", view_func=search_api)
    current_app.add_url_rule("/fetch", view_func=fetch_page)
    current_app.add_url_rule("/api/content-policy", view_func=api_content_policy)

for current_app in (admin_app,):
    current_app.add_url_rule("/api/state", view_func=api_state)
    current_app.add_url_rule("/api/indexed-urls", view_func=api_indexed_urls)
    current_app.add_url_rule("/api/policy/block", view_func=api_add_block, methods=["POST"])
    current_app.add_url_rule("/api/policy/block/remove", view_func=api_remove_block, methods=["POST"])
    current_app.add_url_rule("/api/policy/delay", view_func=api_add_delay, methods=["POST"])
    current_app.add_url_rule("/api/policy/delay/remove", view_func=api_remove_delay, methods=["POST"])
    current_app.add_url_rule("/api/extract-rules", view_func=api_extract_rules, methods=["POST"])
    current_app.add_url_rule("/download/indexed-urls", view_func=download_indexed_urls)
    current_app.add_url_rule("/download/extracted-rules", view_func=download_extracted_rules)


def parse_args():
    parser = argparse.ArgumentParser(description="Firewall Guard local search engine")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", default=DEFAULT_SEARCH_PORT, type=int)
    parser.add_argument("--admin-port", default=DEFAULT_ADMIN_PORT, type=int)
    parser.add_argument("--debug", action="store_true", help="Run the Flask server in debug mode")
    parser.add_argument("--extract-rules", dest="extract_rules", metavar="INPUT_FILE")
    parser.add_argument("--output", help="Optional output path for --extract-rules")
    return parser.parse_args()


def prepare_search_runtime():
    migrate_legacy_runtime_files()
    configure_process_logs()
    initialize_generated_files()


def run_search_backend(host="localhost", port=DEFAULT_SEARCH_PORT, debug=False):
    prepare_search_runtime()
    log_info(f"Starting search backend (user-only, no admin panel) on http://{host}:{port}")
    search_app.run(debug=debug, host=host, port=port, use_reloader=False)


def run_admin_server(port, debug=False):
    log_info(f"Starting admin page on {admin_base_url(port)}")
    admin_app.run(debug=debug, host=LOCAL_ADMIN_HOST, port=port, use_reloader=False)


def main():
    global current_admin_port

    args = parse_args()
    prepare_search_runtime()
    current_admin_port = args.admin_port

    if args.extract_rules:
        source_path = resolve_input_path(args.extract_rules)
        if not source_path.exists():
            raise FileNotFoundError(f"Input file not found: {source_path}")
        summary = extract_rules_to_file(read_text(source_path), str(source_path), args.output)
        print(f"Extracted {summary['total_extracted']} entries to {summary['output_file']}")
        return

    admin_thread = Thread(target=run_admin_server, args=(args.admin_port, args.debug), daemon=True)
    admin_thread.start()
    log_info(f"Starting search engine on http://{args.host}:{args.port}")
    search_app.run(debug=args.debug, host=args.host, port=args.port, use_reloader=False)


if __name__ == "__main__":
    main()
