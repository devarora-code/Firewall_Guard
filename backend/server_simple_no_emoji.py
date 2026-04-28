from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from werkzeug.serving import WSGIRequestHandler
import requests
import json
from datetime import datetime
import os
from pathlib import Path
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app, methods=['GET', 'POST'], 
     allow_headers=['Content-Type', 'Authorization', 'X-Requested-With'],
     origins=['*'])

saved_links = [
    {'id': '1768469843317', 'name': 'https://pixeldrain.dev/u/yLf8pggV', 'url': 'https://pixeldrain.dev/u/yLf8pggV'}
]
recent_streams = []
global_tunnel_base = "https://cdkvj82q-5000.inc1.devtunnels.ms"

RULES_FILE = Path(__file__).with_name('rules_database.json')
CONSOLE_POLICY_FILE = Path(__file__).with_name('console_firewall_policy.json')
DEFAULT_RULES = {
    'version': 1,
    'last_updated': datetime.now().isoformat(),
    'blocked_domains': [
        'malicious.com',
        'evil.net',
        'badware.io',
        'malwarehost.xyz',
        'exploitkit.ru',
        'malwarepack.tk',
        'virusden.ml',
        'trojan-host.ga',
        'phishing-site.io',
        'fake-bank.com',
        'amazon-verify.xyz',
        'paypal-confirm.tk',
        'apple-id-verify.ml',
        'microsoft-verify.ga',
        'google-signin.cf',
        'botnet-c2.ru',
        'c2-command.tk',
        'zombie-controller.ml',
        'ransomware-pay.xyz',
        'decrypt-payment.tk',
        'ransom-portal.ml',
        'exploit-kit.ru',
        'drive-by-download.tk',
        'malvertising.ml',
        'tech-support-scam.xyz',
        'fake-support.tk',
        'virus-warning.ml',
        'adware-host.xyz',
        'spyware-download.tk',
        'malware.ml'
    ],
    'whitelisted_domains': [
        'google.com',
        'github.com',
        'github.io',
        'stackoverflow.com',
        'youtube.com',
        'wikipedia.org',
        'reddit.com'
    ],
    'dangerous_extensions': [
        '.exe',
        '.msi',
        '.dll',
        '.bat',
        '.cmd',
        '.scr',
        '.pif',
        '.vbs',
        '.js'
    ],
    'suspicious_patterns': [
        'suspicious_tld',
        'excessive_hyphens',
        'long_domain'
    ]
}
DEFAULT_CONSOLE_FIREWALL_POLICY = {
    'version': 2,
    'mode': 'block',
    'updatedAt': '2026-03-18T00:00:00.000Z',
    'rules': [
        {
            'id': 'dynamic-code-eval',
            'appliesTo': ['eval', 'function'],
            'pattern': r'(?:^|[^a-z])eval\s*\(|(?:^|[^a-z])Function\s*\(|new\s+Function\s*\(',
            'severity': 'HIGH',
            'block': False,
            'enabled': True,
            'reason': 'Dynamic code execution from console or eval-like context'
        },
        {
            'id': 'cookie-storage-exfiltration',
            'appliesTo': ['fetch', 'xhr', 'beacon', 'postMessage', 'eval', 'function'],
            'pattern': r'(?:document\.cookie|localStorage|sessionStorage|authorization|bearer|token).*?(?:fetch|XMLHttpRequest|sendBeacon|postMessage)|(?:fetch|XMLHttpRequest|sendBeacon|postMessage).*?(?:document\.cookie|localStorage|sessionStorage|authorization|bearer|token)',
            'severity': 'CRITICAL',
            'block': True,
            'enabled': True,
            'reason': 'Sensitive data exfiltration pattern'
        },
        {
            'id': 'dom-script-injection',
            'appliesTo': ['eval', 'function', 'domWrite', 'htmlInsert', 'open'],
            'pattern': r'(?:document\.write|insertAdjacentHTML|innerHTML|outerHTML|window\.open).*?(?:<script|javascript:|data:text/html|onerror\s*=|onload\s*=)|(?:<script|javascript:|data:text/html|onerror\s*=|onload\s*=)',
            'severity': 'HIGH',
            'block': True,
            'enabled': True,
            'reason': 'DOM or script injection pattern'
        },
        {
            'id': 'dangerous-storage-write',
            'appliesTo': ['storage', 'eval', 'function'],
            'pattern': r'(?:localStorage|sessionStorage)\.(?:setItem|removeItem|clear).*?(?:token|cookie|script|javascript:|data:text/html|onerror\s*=|onload\s*=)',
            'severity': 'HIGH',
            'block': True,
            'enabled': True,
            'reason': 'Dangerous storage manipulation pattern'
        },
        {
            'id': 'dangerous-protocol-network',
            'appliesTo': ['fetch', 'xhr', 'beacon', 'open', 'eval', 'function'],
            'pattern': r'javascript:|data:text/html|data:application/javascript|vbscript:',
            'severity': 'HIGH',
            'block': True,
            'enabled': True,
            'reason': 'Dangerous protocol or payload pattern'
        }
    ]
}

def is_debug_enabled():
    return os.getenv('FIREWALL_DEBUG', '0').strip().lower() in {'1', 'true', 'yes', 'on'}

def get_advanced_backend_port():
    return os.getenv('FIREWALL_ADVANCED_PORT', '3100').strip() or '3100'

def parse_version(value, fallback=1):
    try:
        if isinstance(value, bool):
            return fallback
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str) and value.strip():
            return int(float(value.strip()))
    except (TypeError, ValueError):
        return fallback
    return fallback

def normalize_rule_list(values, *, extensions=False):
    if not isinstance(values, list):
        return []

    normalized = []
    seen = set()

    for value in values:
        item = str(value).strip().lower()
        if not item:
            continue
        if extensions and not item.startswith('.'):
            item = f'.{item.lstrip(".")}'
        if item in seen:
            continue
        seen.add(item)
        normalized.append(item)

    return normalized

def normalize_rules(raw_rules, *, source_path=None):
    source = raw_rules if isinstance(raw_rules, dict) else {}
    source_stat = source_path.stat() if source_path and source_path.exists() else None
    last_updated = source.get('last_updated')

    if not last_updated and source_stat:
        last_updated = datetime.fromtimestamp(source_stat.st_mtime).isoformat()
    if not last_updated:
        last_updated = datetime.now().isoformat()

    declared_version = parse_version(source.get('version'), DEFAULT_RULES['version'])
    effective_version = declared_version
    if source_stat:
        effective_version = max(effective_version, int(source_stat.st_mtime))

    return {
        'version': effective_version,
        'declared_version': declared_version,
        'last_updated': last_updated,
        'blocked_domains': normalize_rule_list(
            source.get('blocked_domains', DEFAULT_RULES['blocked_domains'])
        ) or list(DEFAULT_RULES['blocked_domains']),
        'whitelisted_domains': normalize_rule_list(
            source.get('whitelisted_domains', DEFAULT_RULES['whitelisted_domains'])
        ) or list(DEFAULT_RULES['whitelisted_domains']),
        'dangerous_extensions': normalize_rule_list(
            source.get('dangerous_extensions', DEFAULT_RULES['dangerous_extensions']),
            extensions=True
        ) or list(DEFAULT_RULES['dangerous_extensions']),
        'suspicious_patterns': normalize_rule_list(
            source.get('suspicious_patterns', DEFAULT_RULES['suspicious_patterns'])
        ) or list(DEFAULT_RULES['suspicious_patterns'])
    }

def save_rules_database(rules):
    normalized = normalize_rules(rules)
    RULES_FILE.write_text(json.dumps(normalized, indent=2), encoding='utf-8')
    return normalize_rules(normalized, source_path=RULES_FILE)

def load_rules_database():
    if RULES_FILE.exists():
        try:
            raw_rules = json.loads(RULES_FILE.read_text(encoding='utf-8'))
            return normalize_rules(raw_rules, source_path=RULES_FILE)
        except Exception as error:
            print(f"[Rules] Failed to load rules database: {error}")

    return save_rules_database(DEFAULT_RULES)

def clone_json(data):
    return json.loads(json.dumps(data))

def normalize_console_rule(rule, default_rule=None):
    source = rule if isinstance(rule, dict) else {}
    fallback = default_rule if isinstance(default_rule, dict) else {}
    merged = {**fallback, **source}
    rule_id = str(merged.get('id', '')).strip()

    if not rule_id:
        return None

    applies_to = merged.get('appliesTo', [])
    if not isinstance(applies_to, list):
        applies_to = []

    normalized_applies_to = []
    seen_actions = set()
    for value in applies_to:
        item = str(value).strip()
        if not item:
            continue
        normalized_key = item.lower()
        if normalized_key in seen_actions:
            continue
        seen_actions.add(normalized_key)
        normalized_applies_to.append(item)

    pattern = str(merged.get('pattern', '')).strip()
    if not pattern:
        return None

    severity = str(merged.get('severity') or fallback.get('severity') or 'HIGH').upper()
    if severity not in {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
        severity = 'HIGH'

    normalized_rule = {
        **fallback,
        **source,
        'id': rule_id,
        'appliesTo': normalized_applies_to,
        'pattern': pattern,
        'severity': severity,
        'block': bool(merged.get('block', fallback.get('block', False))),
        'enabled': merged.get('enabled', True) is not False,
        'learned': bool(merged.get('learned', fallback.get('learned', False))),
        'reason': str(merged.get('reason') or fallback.get('reason') or 'Console firewall rule').strip()
    }

    if merged.get('updatedAt'):
        normalized_rule['updatedAt'] = str(merged.get('updatedAt'))

    if 'hitCount' in merged:
        try:
            normalized_rule['hitCount'] = max(0, int(merged.get('hitCount', 0)))
        except (TypeError, ValueError):
            pass

    return normalized_rule

def normalize_console_policy(raw_policy, *, source_path=None):
    defaults = clone_json(DEFAULT_CONSOLE_FIREWALL_POLICY)
    source = raw_policy if isinstance(raw_policy, dict) else {}
    source_stat = source_path.stat() if source_path and source_path.exists() else None
    merged_rules = {}
    ordered_rule_ids = []

    for default_rule in defaults.get('rules', []):
        normalized_default = normalize_console_rule(default_rule, default_rule)
        if not normalized_default:
            continue
        merged_rules[normalized_default['id']] = normalized_default
        ordered_rule_ids.append(normalized_default['id'])

    if isinstance(source.get('rules'), list):
        for rule in source.get('rules', []):
            if not isinstance(rule, dict):
                continue
            rule_id = str(rule.get('id', '')).strip()
            normalized_rule = normalize_console_rule(rule, merged_rules.get(rule_id, {}))
            if not normalized_rule:
                continue
            if rule_id not in merged_rules:
                ordered_rule_ids.append(rule_id)
            merged_rules[rule_id] = normalized_rule

    updated_at = source.get('updatedAt')
    if not updated_at and source_stat:
        updated_at = datetime.fromtimestamp(source_stat.st_mtime).isoformat()
    if not updated_at:
        updated_at = datetime.now().isoformat()

    version = parse_version(source.get('version'), defaults.get('version', 1))
    if source_stat:
        version = max(version, int(source_stat.st_mtime))

    mode = str(source.get('mode') or defaults.get('mode') or 'block').strip().lower()
    if mode not in {'block', 'monitor'}:
        mode = 'block'

    return {
        **defaults,
        **{key: value for key, value in source.items() if key != 'rules'},
        'version': version,
        'mode': mode,
        'updatedAt': updated_at,
        'rules': [merged_rules[rule_id] for rule_id in ordered_rule_ids if rule_id in merged_rules]
    }

def save_console_policy(policy):
    normalized = normalize_console_policy(policy)
    CONSOLE_POLICY_FILE.write_text(json.dumps(normalized, indent=2), encoding='utf-8')
    return normalize_console_policy(normalized, source_path=CONSOLE_POLICY_FILE)

def load_console_policy():
    if CONSOLE_POLICY_FILE.exists():
        try:
            raw_policy = json.loads(CONSOLE_POLICY_FILE.read_text(encoding='utf-8'))
            return normalize_console_policy(raw_policy, source_path=CONSOLE_POLICY_FILE)
        except Exception as error:
            print(f"[Console Policy] Failed to load console policy: {error}")

    return save_console_policy(DEFAULT_CONSOLE_FIREWALL_POLICY)

def extract_hostname(value):
    candidate = str(value or '').strip()
    if not candidate:
        return ''

    parsed = urlparse(candidate if '://' in candidate else f'http://{candidate}')
    return (parsed.hostname or '').lower()

def domain_matches(hostname, rule_domain):
    host = str(hostname or '').strip('.').lower()
    rule = str(rule_domain or '').strip('.').lower()
    return bool(host and rule) and (host == rule or host.endswith(f'.{rule}'))

def match_domain(hostname, domains):
    for domain in domains:
        if domain_matches(hostname, domain):
            return domain
    return ''

def is_suspicious_domain(hostname, patterns):
    enabled = set(patterns or [])

    if 'suspicious_tld' in enabled and any(
        hostname.endswith(tld) for tld in ['.ml', '.tk', '.ga', '.cf', '.xyz', '.top', '.club']
    ):
        return True
    if 'long_domain' in enabled and len(hostname) > 50:
        return True
    if 'excessive_hyphens' in enabled and hostname.count('-') > 3:
        return True

    return False

class QuietTLSMismatchRequestHandler(WSGIRequestHandler):
    @staticmethod
    def looks_like_tls_handshake(value):
        return isinstance(value, str) and value.startswith('\x16\x03')

    def log_error(self, format, *args):
        message = format % args if args else format
        if 'Bad request version' in message and self.looks_like_tls_handshake(getattr(self, 'requestline', '')):
            return
        super().log_error(format, *args)

    def log_request(self, code='-', size='-'):
        if str(code).startswith('400') and self.looks_like_tls_handshake(getattr(self, 'requestline', '')):
            return
        super().log_request(code, size)

@app.route('/', methods=['GET'])
def index():
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Firewall Guard Backend</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 32px; line-height: 1.5; color: #1f2937; }
        h1 { margin-bottom: 8px; }
        code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }
        ul { padding-left: 20px; }
    </style>
</head>
<body>
    <h1>Firewall Guard Backend</h1>
    <p>The backend is running. Open one of the API endpoints below to test it.</p>
    <ul>
        <li><code>/api/status</code></li>
        <li><code>/api/rules</code></li>
        <li><code>/api/get_links</code></li>
    </ul>
</body>
</html>"""

@app.route('/favicon.ico', methods=['GET'])
def favicon():
    return ('', 204)

@app.route('/api/status', methods=['GET'])
def get_status():
    rules = load_rules_database()
    console_policy = load_console_policy()
    return jsonify({
        'success': True,
        'status': 'running',
        'server': 'Firewall Guard Backend',
        'version': '2.1.0',
        'rules_version': rules['version'],
        'rules_last_updated': rules['last_updated'],
        'console_policy_version': console_policy['version'],
        'console_policy_updated_at': console_policy['updatedAt'],
        'rules_summary': {
            'blocked_domains': len(rules.get('blocked_domains', [])),
            'whitelisted_domains': len(rules.get('whitelisted_domains', [])),
            'dangerous_extensions': len(rules.get('dangerous_extensions', []))
        },
        'console_policy_summary': {
            'rules': len(console_policy.get('rules', [])),
            'mode': console_policy.get('mode', 'block')
        },
        'timestamp': datetime.now().isoformat(),
        'endpoints': [
            '/api/status',
            '/api/check_url',
            '/api/save_link',
            '/api/get_links',
            '/api/stream',
            '/api/rules',
            '/api/rules/current',
            '/api/rules/update',
            '/api/console-policy',
            '/api/console-policy/current',
            '/api/ai/analyze',
            '/api/check_updates'
        ]
    })

@app.route('/api/check_updates', methods=['GET'])
def check_updates():
    return jsonify({
        'success': True,
        'currentVersion': '2.1.0',
        'latestVersion': '2.1.0',
        'updatesAvailable': False,
        'timestamp': datetime.now().isoformat(),
        'message': 'No updates available'
    })

@app.route('/api/rules/check-update', methods=['POST'])
def rules_check_update():
    payload = request.get_json(silent=True) or {}
    rules = load_rules_database()
    client_version = parse_version(payload.get('version'), 0)
    server_version = parse_version(rules.get('version'), 1)
    update_available = server_version > client_version

    return jsonify({
        'success': True,
        'client_version': client_version,
        'server_version': server_version,
        'currentVersion': client_version,
        'latestVersion': server_version,
        'update_available': update_available,
        'updatesAvailable': update_available,
        'timestamp': datetime.now().isoformat(),
        'message': 'New firewall rules are available' if update_available else 'Rules are up to date',
        'rulesUpdated': update_available
    })

@app.route('/api/check_url', methods=['POST'])
def check_url():
    data = request.get_json(silent=True) or {}
    url = data.get('url', '')
    hostname = extract_hostname(url)
    rules = load_rules_database()

    if not hostname:
        return jsonify({
            'safe': False,
            'verdict': 'BLOCKED',
            'reason': 'Invalid URL',
            'category': 'invalid',
            'risk': 'high',
            'domain': ''
        })

    matched_whitelist = match_domain(hostname, rules.get('whitelisted_domains', []))
    if matched_whitelist:
        return jsonify({
            'safe': True,
            'verdict': 'SAFE',
            'reason': f'Whitelisted domain: {matched_whitelist}',
            'category': 'whitelisted',
            'risk': 'low',
            'domain': hostname
        })

    matched_block = match_domain(hostname, rules.get('blocked_domains', []))
    if matched_block:
        return jsonify({
            'safe': False,
            'verdict': 'BLOCKED',
            'reason': f'Blocked domain: {matched_block}',
            'category': 'malicious',
            'risk': 'high',
            'domain': hostname
        })

    if is_suspicious_domain(hostname, rules.get('suspicious_patterns', [])):
        return jsonify({
            'safe': True,
            'verdict': 'SAFE',
            'reason': 'Suspicious domain pattern detected',
            'category': 'suspicious',
            'risk': 'medium',
            'domain': hostname
        })

    return jsonify({
        'safe': True,
        'reason': 'URL appears safe',
        'verdict': 'SAFE',
        'category': 'safe',
        'risk': 'low',
        'domain': hostname
    })

@app.route('/api/save_link', methods=['POST'])
def save_link():
    data = request.json
    url = data.get('url', '')
    name = data.get('name', url)
    
    new_link = {
        'id': str(int(datetime.now().timestamp() * 1000)),
        'name': name,
        'url': url
    }
    
    saved_links.append(new_link)
    return jsonify({'success': True, 'link': new_link})

@app.route('/api/get_links', methods=['GET'])
def get_links():
    # Generate indexing links for the global tunnel
    global global_tunnel_base
    
    indexing_links = [
        {
            'id': 'firewall_guard_main',
            'name': 'Firewall Guard Main Interface',
            'url': f'{global_tunnel_base}/',
            'description': 'Main Firewall Guard dashboard and control panel'
        },
        {
            'id': 'firewall_guard_api',
            'name': 'Firewall Guard API',
            'url': f'{global_tunnel_base}/api/status',
            'description': 'API status and health check endpoint'
        },
        {
            'id': 'firewall_guard_rules',
            'name': 'Firewall Rules Management',
            'url': f'{global_tunnel_base}/api/rules',
            'description': 'Manage and view firewall rules'
        },
        {
            'id': 'firewall_guard_search',
            'name': 'Firewall Search Interface',
            'url': f'{global_tunnel_base}/api/get_links',
            'description': 'Access search and indexing functionality'
        },
        {
            'id': 'firewall_guard_stream',
            'name': 'Firewall Stream Management',
            'url': f'{global_tunnel_base}/api/stream',
            'description': 'Manage streaming and content filtering'
        }
    ]
    
    # Include any saved links as well
    all_links = indexing_links + saved_links
    
    return jsonify({
        'links': all_links,
        'global_tunnel': global_tunnel_base,
        'generated_at': datetime.now().isoformat(),
        'total_links': len(all_links)
    })

@app.route('/api/update_tunnel', methods=['POST'])
def update_tunnel():
    global global_tunnel_base
    
    data = request.json
    new_tunnel_url = data.get('tunnel_url', '').strip()
    
    if not new_tunnel_url:
        return jsonify({
            'success': False,
            'error': 'Tunnel URL is required'
        }), 400
    
    # Basic URL validation
    if not (new_tunnel_url.startswith('http://') or new_tunnel_url.startswith('https://')):
        return jsonify({
            'success': False,
            'error': 'Invalid URL format. Must start with http:// or https://'
        }), 400
    
    old_tunnel = global_tunnel_base
    global_tunnel_base = new_tunnel_url
    
    return jsonify({
        'success': True,
        'old_tunnel': old_tunnel,
        'new_tunnel': global_tunnel_base,
        'updated_at': datetime.now().isoformat(),
        'message': 'Global tunnel URL updated successfully'
    })

@app.route('/api/stream', methods=['POST'])
def stream():
    data = request.json
    url = data.get('url', '')
    
    stream_data = {
        'id': str(int(datetime.now().timestamp() * 1000)),
        'url': url,
        'status': 'active',
        'viewers': 1,
        'started_at': datetime.now().isoformat()
    }
    
    recent_streams.append(stream_data)
    
    return jsonify({
        'success': True,
        'stream_id': stream_data['id'],
        'proxy_url': f'http://localhost:{get_advanced_backend_port()}/proxy/{stream_data["id"]}'
    })

@app.route('/api/rules', methods=['GET'])
def get_rules():
    rules = load_rules_database()
    return jsonify({
        'success': True,
        'rules': rules
    })

@app.route('/api/rules/current', methods=['GET'])
def get_current_rules():
    return jsonify(load_rules_database())

@app.route('/api/rules/update', methods=['GET', 'POST'])
def update_rules():
    if request.method == 'GET':
        rules = load_rules_database()
        return jsonify({
            'success': True,
            'rules': rules,
            'timestamp': datetime.now().isoformat()
        })

    payload = request.get_json(silent=True) or {}
    incoming_rules = payload.get('rules', {})

    if not isinstance(incoming_rules, dict) or not incoming_rules:
        return jsonify({'success': False, 'error': 'No rules payload provided'}), 400

    current_rules = load_rules_database()
    next_rules = normalize_rules(incoming_rules)

    if next_rules != current_rules and parse_version(incoming_rules.get('version'), 0) <= parse_version(current_rules.get('version'), 1):
        next_rules['declared_version'] = parse_version(current_rules.get('declared_version'), 1) + 1
        next_rules['version'] = next_rules['declared_version']

    next_rules['last_updated'] = datetime.now().isoformat()
    saved_rules = save_rules_database(next_rules)

    return jsonify({
        'success': True,
        'rules': saved_rules,
        'version': saved_rules['version'],
        'updated_at': saved_rules['last_updated']
    })

@app.route('/api/console-policy', methods=['GET', 'POST'])
def console_policy():
    if request.method == 'GET':
        policy = load_console_policy()
        return jsonify({
            'success': True,
            'policy': policy,
            'timestamp': datetime.now().isoformat()
        })

    payload = request.get_json(silent=True) or {}
    incoming_policy = payload.get('policy', payload)

    if not isinstance(incoming_policy, dict) or not incoming_policy:
        return jsonify({'success': False, 'error': 'No console policy payload provided'}), 400

    current_policy = load_console_policy()
    next_policy = normalize_console_policy(incoming_policy)

    if next_policy != current_policy and parse_version(incoming_policy.get('version'), 0) <= parse_version(current_policy.get('version'), 1):
        next_policy['version'] = parse_version(current_policy.get('version'), 1) + 1

    next_policy['updatedAt'] = datetime.now().isoformat()
    saved_policy = save_console_policy(next_policy)

    return jsonify({
        'success': True,
        'policy': saved_policy,
        'version': saved_policy['version'],
        'updated_at': saved_policy['updatedAt']
    })

@app.route('/api/console-policy/current', methods=['GET'])
def current_console_policy():
    return jsonify(load_console_policy())

@app.route('/api/ai/analyze', methods=['POST'])
def ai_analyze():
    data = request.get_json()
    command = data.get('command', '')
    command_type = data.get('command_type', 'unknown')
    
    # Simple local analysis
    suspicious_patterns = [
        (r'eval\s*\(', 'Code Injection'),
        (r'Function\s*\(', 'Dynamic Function'),
        (r'document\.write\s*\(', 'DOM Manipulation'),
        (r'insertAdjacentHTML', 'HTML Injection'),
        (r'innerHTML\s*=', 'DOM Injection'),
        (r'outerHTML\s*=', 'DOM Manipulation'),
        (r'setTimeout\s*\(\s*["\'].*eval', 'Delayed Code Execution'),
        (r'setInterval\s*\(\s*["\'].*eval', 'Repeated Code Execution'),
        (r'Function\s*\(\s*["\'].*["\']\s*\)', 'Dynamic Function Creation'),
        (r'atob\s*\(', 'Base64 Decoding'),
        (r'confirm\s*\(', 'Social Engineering'),
        (r'prompt\s*\(', 'Information Harvesting')
    ]
    
    dangerous_patterns = [
        (r'window\.location\s*=', 'URL Redirection'),
        (r'window\.open\s*\(', 'Unsafe Navigation'),
        (r'document\.cookie\s*=', 'Cookie Manipulation'),
        (r'localStorage\.setItem', 'Local Storage Manipulation'),
        (r'sessionStorage\.setItem', 'Session Storage Manipulation'),
        (r'XMLHttpRequest', 'Network Request'),
        (r'fetch\s*\(', 'Network Request'),
        (r'sendBeacon\s*\(', 'Data Exfiltration'),
        (r'WebSocket', 'WebSocket Connection'),
        (r'postMessage', 'Cross-Frame Communication'),
        (r'alert\s*\(', 'UI Manipulation')
    ]
    
    import re
    command_lower = command.lower()
    risk_score = 0
    threat_types = []
    
    for pattern, threat_type in suspicious_patterns:
        if re.search(pattern, command_lower):
            risk_score += 2
            threat_types.append(threat_type)
    
    for pattern, threat_type in dangerous_patterns:
        if re.search(pattern, command_lower):
            risk_score += 5
            threat_types.append(threat_type)

    exfiltration_pattern = re.search(
        r'(document\.cookie|localstorage|sessionstorage|authorization|bearer|token).*(fetch|xmlhttprequest|sendbeacon|postmessage)|(fetch|xmlhttprequest|sendbeacon|postmessage).*(document\.cookie|localstorage|sessionstorage|authorization|bearer|token)',
        command_lower
    )
    if exfiltration_pattern:
        risk_score += 7
        threat_types.append('Sensitive Data Exfiltration')
    
    if risk_score >= 11:
        risk_level = 'CRITICAL'
    elif risk_score >= 7:
        risk_level = 'HIGH'
    elif risk_score >= 4:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'
    
    if 'eval(' in command_lower and risk_level == 'LOW':
        risk_level = 'MEDIUM'
    
    threat_type_str = ', '.join(set(threat_types)) if threat_types else 'UNKNOWN'
    
    analysis = f"""RISK_LEVEL: {risk_level}
THREAT_TYPE: {threat_type_str}
DESCRIPTION: Local analysis detected {risk_level.lower()} risk patterns in the console command.
RECOMMENDATION: {'Block this command immediately' if risk_level == 'HIGH' else 'Monitor this command carefully' if risk_level == 'MEDIUM' else 'Command appears safe'}"""
    
    return jsonify({
        "success": True,
        "analysis": analysis,
        "source": "local",
        "fallback": True,
        "timestamp": datetime.now().isoformat()
    })

@app.route('/proxy/<stream_id>')
def proxy(stream_id):
    stream = next((s for s in recent_streams if s['id'] == stream_id), None)
    if not stream:
        return jsonify({'error': 'Stream not found'}), 404
    
    try:
        response = requests.get(stream['url'], stream=True)
        return send_file(
            response.raw,
            mimetype=response.headers.get('content-type', 'application/octet-stream')
        )
    except Exception as e:
        return f"Error proxying video: {str(e)}", 500

if __name__ == '__main__':
    debug_enabled = is_debug_enabled()
    print("Starting Firewall Backend Server...")
    print("Server will run on http://localhost:5000")
    print("Chrome Extension will connect automatically")
    print(f"Debug mode: {'ON' if debug_enabled else 'OFF'}")
    print("Press Ctrl+C to stop server")
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=debug_enabled,
        request_handler=QuietTLSMismatchRequestHandler
    )
