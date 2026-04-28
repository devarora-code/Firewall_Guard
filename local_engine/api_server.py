import json
import threading
import time
from datetime import datetime
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import firewall_engine

class FirewallAPIHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.engine = firewall_engine.FirewallRulesEngine()
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path == '/':
            self.send_html_response(200, """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Local Firewall Engine</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 32px; line-height: 1.5; color: #1f2937; }
        h1 { margin-bottom: 8px; }
        code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }
        ul { padding-left: 20px; }
    </style>
</head>
<body>
    <h1>Local Firewall Engine</h1>
    <p>The engine is running. Useful endpoints:</p>
    <ul>
        <li><code>/api/status</code></li>
        <li><code>/api/rules/current</code></li>
        <li><code>/api/check_url</code> (POST)</li>
        <li><code>/api/rules/update</code> (POST)</li>
    </ul>
</body>
</html>""")
        elif self.path == '/favicon.ico':
            self.send_response(204)
            self.end_headers()
        elif self.path == '/api/status':
            self.send_json_response(200, self.engine.get_status())
        elif self.path == '/api/rules/current':
            self.send_json_response(200, self.engine.rules)
        else:
            self.send_error(404, "Endpoint not found")

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data.decode('utf-8'))
        except:
            self.send_json_response(400, {'error': 'Invalid JSON'})
            return

        if self.path == '/api/check_url':
            url = data.get('url', '')
            result = self.engine.check_url(url)
            self.send_json_response(200, result)
        elif self.path == '/api/rules/update':
            new_rules = data.get('rules', {})
            success = self.engine.update_rules(new_rules)
            self.send_json_response(200, {'success': success})
        else:
            self.send_error(404, "Endpoint not found")

    def send_json_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        response = json.dumps(data, indent=2)
        self.wfile.write(response.encode('utf-8'))

    def send_html_response(self, status_code, html):
        self.send_response(status_code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def log_message(self, format, *args):
        pass

def run_server():
    server_address = ('localhost', 7000)
    httpd = HTTPServer(server_address, FirewallAPIHandler)
    
    print("="*80)
    print("LOCAL FIREWALL GUARD - API SERVER")
    print("="*80)
    print(f"Local API server running on: http://localhost:7000")
    print(f"Started: {datetime.now()}")
    print()
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[{datetime.now()}] Shutting down local API server...")
        httpd.shutdown()

if __name__ == '__main__':
    run_server()
