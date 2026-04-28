"""
Advanced Backend
Enhanced with buffer management, download optimization, and network performance
"""

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
import requests
import threading
import time
import os
import tempfile
import queue
import gc
from collections import deque
from datetime import datetime
import json
import hashlib
import urllib.parse
from pathlib import Path
from werkzeug.serving import WSGIRequestHandler

def is_debug_enabled():
    return os.getenv('FIREWALL_DEBUG', '0').strip().lower() in {'1', 'true', 'yes', 'on'}

def get_server_port():
    raw_value = os.getenv('FIREWALL_ADVANCED_PORT', '3100').strip()
    try:
        return int(raw_value)
    except ValueError:
        print(f"Invalid FIREWALL_ADVANCED_PORT '{raw_value}', falling back to 3100")
        return 3100

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

class AdvancedVideoStreamer:
    def __init__(self):
        self.app = Flask(__name__)
        CORS(self.app, resources={r"/api/*": {"origins": ["*"]}})
        self.backend_dir = Path(__file__).resolve().parent
        self.search_runtime_dir = self.backend_dir / 'search_runtime'
        self.search_runtime_dir.mkdir(parents=True, exist_ok=True)
        self.search_indexed_urls_file = self.search_runtime_dir / 'indexed_urls.txt'
        self.search_state_file = self.search_runtime_dir / 'search_state.json'
        self.search_rules_file = self.search_runtime_dir / 'extracted_rules.txt'
        self.search_stdout_log_file = self.search_runtime_dir / 'search_server.out.log'
        self.search_stderr_log_file = self.search_runtime_dir / 'search_server.err.log'
        
        self.buffer_limit = 50 * 1024 * 1024  # 50MB
        self.chunk_size = 1 * 1024 * 1024     # 1MB chunks
        self.download_buffer = deque(maxlen=50)  # 50 chunks max
        self.buffer_monitoring = {}
        self.buffer_stats = {
            'total_size': 0,
            'chunk_count': 0,
            'cleanup_count': 0,
            'last_cleanup': None
        }
        
        self.download_storage_limit = 200 * 1024 * 1024  # 200MB
        self.downloads_dir = tempfile.mkdtemp(prefix="advanced_videodl_")
        self.download_queue = queue.Queue()
        self.active_downloads = {}
        self.max_concurrent = 3
        self.download_history = []
        
        self.session = requests.Session()
        self.cache = {}
        self.proxy_urls = {}
        self.performance_stats = {
            'total_downloads': 0,
            'successful_downloads': 0,
            'failed_downloads': 0,
            'cache_hits': 0,
            'total_bytes': 0
        }
        
        self.blocked_domains = ['malicious-site.com', 'unsafe-stream.net', 'blocked-content.com']
        self.allowed_domains = ['youtube.com', 'vimeo.com', 'commondatastorage.googleapis.com']
        self.url_whitelist = set()
        self.url_blacklist = set()
        
        self.saved_links = [
            {'id': '1768469843317', 'name': 'https://pixeldrain.dev/u/yLf8pggV', 'url': 'https://pixeldrain.dev/u/yLf8pggV'}
        ]
        self.recent_streams = []
        
        self.setup_routes()
        self.start_background_services()
    
    def setup_routes(self):
        """Setup all API routes"""

        @self.app.route('/', methods=['GET'])
        def index():
            return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Advanced Backend</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 32px; line-height: 1.5; color: #1f2937; }
        h1 { margin-bottom: 8px; }
        code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }
        ul { padding-left: 20px; }
    </style>
</head>
<body>
    <h1>Advanced Backend</h1>
    <p>The server is running. This service exposes API endpoints rather than a full website.</p>
    <p>Useful endpoints:</p>
    <ul>
        <li><code>/api/status</code></li>
        <li><code>/api/advanced_status</code></li>
        <li><code>/api/check_url</code></li>
        <li><code>/api/search-indexing</code></li>
    </ul>
</body>
</html>"""

        @self.app.route('/favicon.ico', methods=['GET'])
        def favicon():
            return ('', 204)
        
        @self.app.route('/api/status', methods=['GET'])
        def get_status():
            return jsonify({
                'backend_connected': True,
                'status': 'active',
                'version': '2.0',
                'features': {
                    'advanced_buffer': True,
                    'download_management': True,
                    'caching': True,
                    'security_filtering': True,
                    'search_indexing': True
                }
            })
        
        @self.app.route('/api/advanced_status', methods=['GET'])
        def get_advanced_status():
            buffer_size = sum(len(chunk) for chunk in self.download_buffer)
            active_downloads = len([d for d in self.active_downloads.values() if d.get('status') == 'downloading'])
            
            return jsonify({
                'buffer': {
                    'current_size': buffer_size,
                    'limit': self.buffer_limit,
                    'chunk_count': len(self.download_buffer),
                    'cleanup_count': self.buffer_stats['cleanup_count'],
                    'last_cleanup': self.buffer_stats['last_cleanup']
                },
                'downloads': {
                    'active': active_downloads,
                    'queued': self.download_queue.qsize(),
                    'max_concurrent': self.max_concurrent,
                    'storage_used': self.get_storage_used(),
                    'storage_limit': self.download_storage_limit
                },
                'performance': self.performance_stats,
                'cache': {
                    'entries': len(self.cache),
                    'hits': self.performance_stats['cache_hits']
                },
                'search_indexing': self.load_search_indexing_summary()
            })

        @self.app.route('/api/search-indexing', methods=['GET'])
        def get_search_indexing():
            return jsonify(self.load_search_indexing_summary())
        
        @self.app.route('/api/check_url', methods=['POST'])
        def check_url():
            data = request.json
            url = data.get('url', '')
            
            try:
                domain = urllib.parse.urlparse(url).hostname
                safe = self.is_url_safe(url)
                
                return jsonify({
                    'safe': safe,
                    'status': 'allowed' if safe else 'blocked',
                    'domain': domain,
                    'risk_level': self.get_risk_level(domain),
                    'reason': self.get_block_reason(url) if not safe else None
                })
            except Exception as e:
                return jsonify({'safe': False, 'status': 'error', 'error': str(e)})
        
        @self.app.route('/api/download_status/<filename>', methods=['GET'])
        def get_download_status(filename):
            if filename in self.active_downloads:
                return jsonify(self.active_downloads[filename])
            else:
                return jsonify({'error': 'Download not found'}), 404
        
        @self.app.route('/api/clear_downloads', methods=['POST'])
        def clear_downloads():
            cleared_count = len(self.active_downloads)
            self.active_downloads.clear()
            self.download_history.clear()
            
            try:
                for file in os.listdir(self.downloads_dir):
                    os.remove(os.path.join(self.downloads_dir, file))
            except:
                pass
            
            return jsonify({
                'success': True,
                'cleared_count': cleared_count
            })
        
        @self.app.route('/api/test_buffer', methods=['POST'])
        def test_buffer():
            """Test buffer system with sample data"""
            test_chunks = []
            for i in range(3):
                chunk = f"test_chunk_{i}_{time.time()}".encode() * 1000  # ~1KB each
                self.download_buffer.append(chunk)
                test_chunks.append(len(chunk))
            
            self.buffer_stats['total_size'] = sum(len(chunk) for chunk in self.download_buffer)
            self.buffer_stats['chunk_count'] = len(self.download_buffer)
            
            return jsonify({
                'success': True,
                'chunks_added': 3,
                'total_size': self.buffer_stats['total_size'],
                'chunk_count': self.buffer_stats['chunk_count']
            })
        
        @self.app.route('/api/clear_buffer', methods=['POST'])
        def clear_buffer():
            cleared_size = sum(len(chunk) for chunk in self.download_buffer)
            cleared_count = len(self.download_buffer)
            
            self.download_buffer.clear()
            self.buffer_monitoring.clear()
            gc.collect()
            
            self.buffer_stats['total_size'] = 0
            self.buffer_stats['chunk_count'] = 0
            self.buffer_stats['cleanup_count'] += 1
            self.buffer_stats['last_cleanup'] = datetime.now().isoformat()
            
            return jsonify({
                'success': True,
                'cleared_size': cleared_size,
                'cleared_count': cleared_count
            })
        
        @self.app.route('/api/save-link', methods=['POST'])
        def save_link():
            data = request.json
            link = {
                'id': str(int(time.time() * 1000)),
                'name': data.get('name', data.get('url')),
                'url': data.get('url'),
                'saved_at': datetime.now().isoformat()
            }
            self.saved_links.append(link)
            return jsonify({'success': True, 'id': link['id']})
        
        @self.app.route('/api/delete-link/<id>', methods=['DELETE'])
        def delete_link(id):
            self.saved_links = [link for link in self.saved_links if link['id'] != id]
            return jsonify({'success': True})
        
        @self.app.route('/api/saved-links', methods=['GET'])
        def get_saved_links():
            return jsonify(self.saved_links)
        
        @self.app.route('/api/add-recent', methods=['POST'])
        def add_recent():
            data = request.json
            stream = {
                'url': data.get('url'),
                'time': data.get('time', datetime.now().strftime('%H:%M:%S')),
                'timestamp': datetime.now().isoformat()
            }
            self.recent_streams.insert(0, stream)
            if len(self.recent_streams) > 10:
                self.recent_streams.pop()
            return jsonify({'success': True})
        
        @self.app.route('/api/recent-streams', methods=['GET'])
        def get_recent_streams():
            return jsonify(self.recent_streams)
        
        @self.app.route('/proxy-video')
        def proxy_video():
            url = request.args.get('url')
            if not url or not self.is_url_safe(url):
                return "URL not allowed", 403
            
            try:
                response = self.session.get(url, stream=True, timeout=30)
                response.raise_for_status()
                
                def generate():
                    for chunk in response.iter_content(chunk_size=self.chunk_size):
                        if chunk:
                            self.download_buffer.append(chunk)
                            self.buffer_stats['total_size'] = sum(len(c) for c in self.download_buffer)
                            self.buffer_stats['chunk_count'] = len(self.download_buffer)
                            yield chunk
                
                return send_file(
                    generate(),
                    mimetype=response.headers.get('content-type', 'video/mp4'),
                    as_attachment=False
                )
            except Exception as e:
                return f"Error proxying video: {str(e)}", 500
    
    def is_url_safe(self, url):
        """Enhanced URL safety checking"""
        try:
            domain = urllib.parse.urlparse(url).hostname
            if not domain:
                return False
            
            if domain in self.blocked_domains:
                return False
            
            if self.allowed_domains and domain not in self.allowed_domains:
                return False
            
            if url in self.url_blacklist:
                return False
            
            if self.url_whitelist and url not in self.url_whitelist:
                return False
            
            return True
        except:
            return False
    
    def get_risk_level(self, domain):
        """Determine risk level for domain"""
        if domain in self.blocked_domains:
            return 'high'
        elif domain in self.allowed_domains:
            return 'low'
        else:
            return 'medium'
    
    def get_block_reason(self, url):
        """Get reason for URL blocking"""
        try:
            domain = urllib.parse.urlparse(url).hostname
            if domain in self.blocked_domains:
                return f'Domain {domain} is blocked'
            elif url in self.url_blacklist:
                return 'URL is blacklisted'
            else:
                return 'URL not in whitelist'
        except:
            return 'Invalid URL format'
    
    def get_storage_used(self):
        """Calculate total storage used by downloads"""
        total = 0
        try:
            for file in os.listdir(self.downloads_dir):
                file_path = os.path.join(self.downloads_dir, file)
                if os.path.isfile(file_path):
                    total += os.path.getsize(file_path)
        except:
            pass
        return total

    def load_search_indexing_summary(self):
        summary = {
            'local_only': True,
            'runtime_dir': str(self.search_runtime_dir),
            'indexed_urls_file': str(self.search_indexed_urls_file),
            'search_state_file': str(self.search_state_file),
            'rule_export_file': str(self.search_rules_file),
            'stdout_log_file': str(self.search_stdout_log_file),
            'stderr_log_file': str(self.search_stderr_log_file),
            'indexed_url_count': 0,
            'indexed_urls_preview': [],
            'blocked_patterns': [],
            'delayed_patterns': [],
            'last_rule_extract': None,
            'files_present': {
                'indexed_urls': self.search_indexed_urls_file.exists(),
                'search_state': self.search_state_file.exists(),
                'rule_export': self.search_rules_file.exists(),
                'stdout_log': self.search_stdout_log_file.exists(),
                'stderr_log': self.search_stderr_log_file.exists()
            }
        }
        errors = []

        if self.search_indexed_urls_file.exists():
            try:
                urls = []
                seen = set()
                for line in self.search_indexed_urls_file.read_text(encoding='utf-8', errors='ignore').splitlines():
                    item = line.strip()
                    key = item.lower()
                    if not item or key in seen:
                        continue
                    seen.add(key)
                    urls.append(item)
                summary['indexed_url_count'] = len(urls)
                summary['indexed_urls_preview'] = list(reversed(urls[-25:]))
            except Exception as error:
                errors.append(f"indexed_urls: {error}")

        if self.search_state_file.exists():
            try:
                state = json.loads(self.search_state_file.read_text(encoding='utf-8', errors='ignore'))
                summary['blocked_patterns'] = list(state.get('blocked_patterns', []))
                summary['delayed_patterns'] = list(state.get('delayed_patterns', []))
                summary['last_rule_extract'] = state.get('last_rule_extract')
            except Exception as error:
                errors.append(f"search_state: {error}")

        if errors:
            summary['errors'] = errors

        return summary
    
    def start_background_services(self):
        """Start background threads for buffer management and downloads"""
        
        def buffer_monitor():
            """Monitor and cleanup buffer"""
            while True:
                self.cleanup_buffer()
                time.sleep(5)  # Check every 5 seconds
        
        def download_manager():
            """Manage concurrent downloads"""
            while True:
                try:
                    if self.download_queue.qsize() > 0:
                        active_count = len([d for d in self.active_downloads.values() if d.get('status') == 'downloading'])
                        if active_count < self.max_concurrent:
                            url = self.download_queue.get(timeout=1)
                            threading.Thread(target=self.download_file, args=(url,), daemon=True).start()
                except queue.Empty:
                    pass
                except Exception as e:
                    print(f"Download manager error: {e}")
                time.sleep(1)
        
        def performance_monitor():
            """Monitor performance metrics"""
            while True:
                self.buffer_stats['total_size'] = sum(len(chunk) for chunk in self.download_buffer)
                self.buffer_stats['chunk_count'] = len(self.download_buffer)
                time.sleep(10)  # Update every 10 seconds
        
        threading.Thread(target=buffer_monitor, daemon=True).start()
        threading.Thread(target=download_manager, daemon=True).start()
        threading.Thread(target=performance_monitor, daemon=True).start()
    
    def cleanup_buffer(self):
        """Automatic buffer cleanup with enhanced logic"""
        current_size = sum(len(chunk) for chunk in self.download_buffer)
        
        if current_size > self.buffer_limit * 0.8:  # Cleanup at 80%
            while len(self.download_buffer) > 30:
                self.download_buffer.popleft()
            
            self.buffer_stats['cleanup_count'] += 1
            self.buffer_stats['last_cleanup'] = datetime.now().isoformat()
            gc.collect()
    
    def download_file(self, url):
        """Enhanced download with caching and optimization"""
        filename = f"video_{int(time.time())}.mp4"
        filepath = os.path.join(self.downloads_dir, filename)
        
        if filename in self.active_downloads:
            self.active_downloads[filename]['status'] = 'downloading'
            
            try:
                cache_key = hashlib.md5(url.encode()).hexdigest()
                if cache_key in self.cache:
                    self.save_to_disk(self.cache[cache_key], filepath)
                    self.active_downloads[filename]['status'] = 'completed'
                    self.performance_stats['cache_hits'] += 1
                    self.performance_stats['successful_downloads'] += 1
                    return
                
                response = self.session.get(url, stream=True, timeout=30)
                response.raise_for_status()
                
                total_size = int(response.headers.get('content-length', 0))
                downloaded = 0
                chunks = []
                
                with open(filepath, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=self.chunk_size):
                        if chunk:
                            chunks.append(chunk)
                            self.download_buffer.append(chunk)
                            self.buffer_monitoring[filename] = {
                                'size': len(chunk),
                                'timestamp': time.time()
                            }
                            
                            f.write(chunk)
                            downloaded += len(chunk)
                            self.performance_stats['total_bytes'] += len(chunk)
                            
                            if total_size > 0:
                                progress = (downloaded / total_size) * 100
                                self.active_downloads[filename]['progress'] = progress
                                self.active_downloads[filename]['size'] = downloaded
                            
                            if downloaded > self.download_storage_limit:
                                break
                
                if downloaded < 10 * 1024 * 1024:  # <10MB
                    self.cache[cache_key] = b''.join(chunks)
                
                self.active_downloads[filename]['status'] = 'completed'
                self.active_downloads[filename]['completed_at'] = datetime.now().isoformat()
                self.performance_stats['successful_downloads'] += 1
                
                self.download_history.append({
                    'filename': filename,
                    'url': url,
                    'size': downloaded,
                    'completed_at': datetime.now().isoformat()
                })
                
            except Exception as e:
                self.active_downloads[filename]['status'] = 'failed'
                self.active_downloads[filename]['error'] = str(e)
                self.performance_stats['failed_downloads'] += 1
    
    def save_to_disk(self, data, filepath):
        """Save data to disk efficiently"""
        with open(filepath, 'wb') as f:
            f.write(data)
    
    def run(self, host='0.0.0.0', port=3000, debug=False):
        """Run the advanced backend server"""
        print("Advanced server")
        print(f"Server will run on http://localhost:{port}")
        print(f"Debug mode: {'ON' if debug else 'OFF'}")
        print("Press Ctrl+C to stop server")
        
        self.app.run(
            host=host,
            port=port,
            debug=debug,
            request_handler=QuietTLSMismatchRequestHandler
        )

if __name__ == '__main__':
    backend = AdvancedVideoStreamer()
    backend.run(port=get_server_port(), debug=is_debug_enabled())
