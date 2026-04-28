"""
Firewall Extension Backend Server
Simple Flask server for Chrome extension communication
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import json
import logging
from datetime import datetime
import os
from secrets_manager import SecretsManager
from ai_validation import ai_validator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Enable CORS for extension

EXTENSION_VERSION = "1.0.0"
RULES_VERSION = 1

# Initialize secrets manager
secrets_manager = SecretsManager()

@app.route('/api/secure/api-key', methods=['GET'])
def get_api_key():
    """Secure endpoint to provide API key to authenticated extension"""
    try:
        # Get OpenAI API key from secrets manager
        api_key = secrets_manager.get_openai_api_key()
        
        if api_key:
            logger.info("API key retrieved successfully")
            return jsonify({
                "api_key": api_key,
                "status": "success",
                "timestamp": datetime.now().isoformat()
            })
        else:
            logger.error("No API key found in secrets manager")
            return jsonify({
                "error": "API key not found",
                "status": "error",
                "message": "Please initialize the API key first"
            }), 500
            
    except Exception as e:
        logger.error(f"Error retrieving API key: {e}")
        return jsonify({
            "error": "Internal server error",
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/secure/secrets', methods=['GET'])
def list_secrets():
    """List all secrets (without values) - admin only"""
    try:
        # Basic authentication check (in production, use proper auth)
        auth_header = request.headers.get('Authorization')
        if not auth_header or auth_header != 'Bearer admin-token':
            return jsonify({'error': 'Unauthorized'}), 401
        
        secrets = secrets_manager.list_secrets()
        return jsonify({
            'secrets': secrets,
            'count': len(secrets),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error listing secrets: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/secure/secrets/<key>', methods=['POST'])
def store_secret(key):
    """Store a new secret - admin only"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or auth_header != 'Bearer admin-token':
            return jsonify({'error': 'Unauthorized'}), 401
        
        data = request.get_json()
        if not data or 'value' not in data:
            return jsonify({'error': 'Value required'}), 400
        
        description = data.get('description', '')
        secrets_manager.store_secret(key, data['value'], description)
        
        return jsonify({
            'message': f'Secret {key} stored successfully',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error storing secret: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/validate/block', methods=['POST'])
def validate_block_decision():
    """Validate AI analysis before blocking decision"""
    try:
        extension_id = request.headers.get('X-Extension-ID')
        if not extension_id:
            return jsonify({'error': 'Extension ID required'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request data required'}), 400
        
        # Validate required fields
        required_fields = ['command', 'analysis', 'riskLevel', 'type']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Create command data for validation
        command_data = {
            'command': data['command'],
            'analysis': data['analysis'],
            'riskLevel': data['riskLevel'],
            'type': data['type'],
            'domain': data.get('domain', ''),
            'url': data.get('url', ''),
            'timestamp': data.get('timestamp', datetime.now().isoformat())
        }
        
        # Run AI validation
        should_block, validation_result = ai_validator.validate_ai_analysis(command_data)
        
        # Log validation decision
        logger.info(f"AI Validation: {validation_result['validated_risk']} risk, "
                   f"confidence: {validation_result['confidence_score']:.2f}, "
                   f"block: {should_block}")
        
        return jsonify({
            'should_block': should_block,
            'validation_result': validation_result,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in block validation: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/validate/stats', methods=['GET'])
def get_validation_stats():
    """Get AI validation statistics"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or auth_header != 'Bearer admin-token':
            return jsonify({'error': 'Unauthorized'}), 401
        
        stats = ai_validator.get_validation_stats()
        return jsonify({
            'stats': stats,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting validation stats: {e}")
        return jsonify({'error': 'Internal server error'}), 500

MOCK_RULES = {
    "rules": [
        {
            "id": "block_ads",
            "name": "Block Ad Networks",
            "enabled": True,
            "domains": ["doubleclick.net", "googleadservices.com", "googlesyndication.com"],
            "type": "block"
        },
        {
            "id": "block_trackers",
            "name": "Block Trackers", 
            "enabled": True,
            "domains": ["facebook.com", "google-analytics.com", "googletagmanager.com"],
            "type": "block"
        }
    ]
}

@app.route('/api/status', methods=['GET'])
def status():
    """Backend status endpoint"""
    return jsonify({
        "status": "online",
        "version": EXTENSION_VERSION,
        "timestamp": datetime.now().isoformat(),
        "rules_version": RULES_VERSION
    })

@app.route('/api/check_url', methods=['POST'])
def check_url():
    """URL safety check endpoint"""
    try:
        data = request.get_json()
        url = data.get('url', '')
        
        if not url:
            return jsonify({"error": "No URL provided"}), 400
        
        blocked_domains = ["malware-site.com", "phishing-site.com"]
        is_safe = not any(domain in url for domain in blocked_domains)
        
        if is_safe:
            return jsonify({
                "verdict": "SAFE",
                "risk": "low",
                "url": url,
                "source": "backend"
            })
        else:
            return jsonify({
                "verdict": "BLOCKED", 
                "risk": "high",
                "url": url,
                "reason": "Malicious domain detected",
                "source": "backend"
            })
            
    except Exception as e:
        logger.error(f"URL check error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/rules', methods=['GET'])
def get_rules():
    """Get firewall rules"""
    return jsonify(MOCK_RULES)

@app.route('/api/rules/update', methods=['POST'])
def update_rules():
    """Update firewall rules"""
    try:
        data = request.get_json()
        logger.info(f"Rules update requested: {data}")
        return jsonify({
            "success": True,
            "version": RULES_VERSION,
            "updated_at": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Rules update error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/logs', methods=['POST'])
def submit_logs():
    """Submit extension logs"""
    try:
        data = request.get_json()
        logs = data.get('logs', [])
        
        logger.info(f"Received {len(logs)} log entries")
        
        for log_entry in logs:
            logger.info(f"Extension Log: {log_entry}")
        
        return jsonify({
            "success": True,
            "received": len(logs),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Log submission error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/ai/analyze', methods=['POST'])
def ai_analyze():
    """AI-powered command analysis"""
    try:
        data = request.get_json()
        command = data.get('command', '')
        command_type = data.get('type', 'unknown')
        source = data.get('source', 'unknown')
        domain = data.get('domain', 'unknown')
        url = data.get('url', '')
        
        if not command:
            return jsonify({"error": "No command provided"}), 400
        
        # Get OpenAI API key from secrets manager
        api_key = secrets_manager.get_openai_api_key()
        if not api_key:
            logger.warning("OpenAI API key not configured, using local analysis")
            return jsonify({
                "success": True,
                "analysis": get_local_analysis(command, command_type),
                "source": "local",
                "fallback": True,
                "timestamp": datetime.now().isoformat()
            })
        
        # Try OpenAI analysis
        try:
            # Prepare OpenAI request
            prompt = f"""Analyze this browser console command for malicious behavior:
            
Command Type: {command_type}
Command: {command}
Source: {source}
Domain: {domain}
URL: {url}

Is this command malicious? Respond with:
- RISK_LEVEL: (LOW/MEDIUM/HIGH/CRITICAL)
- THREAT_TYPE: (if applicable)
- DESCRIPTION: (brief explanation)
- RECOMMENDATION: (what to do)

Keep response concise and focused on security."""

            import requests
            response = requests.post(
                'https://api.openai.com/v1/chat/completions',
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {api_key}'
                },
                json={
                    'model': 'gpt-3.5-turbo',
                    'messages': [
                        {
                            'role': 'system',
                            'content': 'You are a cybersecurity expert analyzing browser console commands for malicious behavior. Be thorough but concise.'
                        },
                        {
                            'role': 'user',
                            'content': prompt
                        }
                    ],
                    'max_tokens': 200,
                    'temperature': 0.3
                },
                timeout=10
            )
            
            if response.status_code != 200:
                logger.error(f"OpenAI API error: {response.status_code} - {response.text}")
                # Fallback to local analysis
                return jsonify({
                    "success": True,
                    "analysis": get_local_analysis(command, command_type),
                    "source": "local",
                    "fallback": True,
                    "error": f"OpenAI API error: {response.status_code}",
                    "timestamp": datetime.now().isoformat()
                })
            
            result = response.json()
            
            if 'choices' not in result or not result['choices']:
                logger.error("Invalid response from OpenAI")
                return jsonify({
                    "success": True,
                    "analysis": get_local_analysis(command, command_type),
                    "source": "local",
                    "fallback": True,
                    "error": "Invalid OpenAI response",
                    "timestamp": datetime.now().isoformat()
                })
            
            analysis = result['choices'][0]['message']['content'].strip()
            
            # Run AI validation before returning
            should_block, validation_result = ai_validator.validate_ai_analysis({
                'command': command,
                'type': command_type,
                'analysis': analysis,
                'timestamp': datetime.now().isoformat()
            })
            
            logger.info(f"AI Analysis completed for command: {command[:50]}...")
            logger.info(f"Validation result: {validation_result['validated_risk']} risk, "
                       f"confidence: {validation_result['confidence_score']:.2f}")
            
            return jsonify({
                "success": True,
                "analysis": analysis,
                "validation": validation_result,
                "should_block": should_block,
                "source": "ai",
                "timestamp": datetime.now().isoformat()
            })
            
        except Exception as ai_error:
            logger.warning(f"AI analysis failed, using local fallback: {ai_error}")
            # Fallback to local analysis
            return jsonify({
                "success": True,
                "analysis": get_local_analysis(command, command_type),
                "source": "local",
                "fallback": True,
                "error": str(ai_error),
                "timestamp": datetime.now().isoformat()
            })
        
    except Exception as e:
        logger.error(f"AI analysis endpoint error: {e}")
        return jsonify({
            "error": str(e),
            "success": False
        }), 500

def get_local_analysis(command, command_type):
    """Local pattern-based analysis fallback"""
    command_lower = command.lower()
    
    # Define suspicious patterns
    suspicious_patterns = [
        (r'eval\s*\(', 'CODE_EXECUTION'),
        (r'Function\s*\(', 'DYNAMIC_FUNCTION'),
        (r'document\.write', 'DOM_MANIPULATION'),
        (r'insertAdjacentHTML', 'HTML_INJECTION'),
        (r'innerhtml\s*=', 'DOM_INJECTION'),
        (r'settimeout\s*\(', 'DELAYED_EXECUTION'),
        (r'setinterval\s*\(', 'REPEATED_EXECUTION'),
        (r'javascript:', 'PROTOCOL_INJECTION'),
        (r'data:', 'DATA_PROTOCOL'),
        (r'vbscript:', 'VBSCRIPT_INJECTION'),
        (r'onload\s*=', 'EVENT_HANDLER_INJECTION'),
        (r'onerror\s*=', 'ERROR_HANDLER_INJECTION'),
        (r'onclick\s*=', 'CLICK_HANDLER_INJECTION')
    ]
    
    # Define dangerous patterns
    dangerous_patterns = [
        (r'document\.cookie', 'COOKIE_THEFT'),
        (r'localstorage', 'STORAGE_ACCESS'),
        (r'sessionstorage', 'STORAGE_ACCESS'),
        (r'window\.location', 'REDIRECTION'),
        (r'window\.open', 'UNSAFE_NAVIGATION'),
        (r'fetch\s*\(', 'NETWORK_REQUEST'),
        (r'xmlhttprequest', 'NETWORK_REQUEST'),
        (r'sendbeacon\s*\(', 'DATA_EXFILTRATION'),
        (r'postmessage', 'CROSS_ORIGIN_COMMUNICATION'),
        (r'atob\s*\(', 'BASE64_DECODING'),
        (r'btoa\s*\(', 'BASE64_ENCODING')
    ]
    
    risk_score = 0
    threat_types = []
    
    # Check for suspicious patterns
    import re
    for pattern, threat_type in suspicious_patterns:
        if re.search(pattern, command_lower):
            risk_score += 2
            threat_types.append(threat_type)
    
    # Check for dangerous patterns
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
        threat_types.append('SENSITIVE_DATA_EXFILTRATION')
    
    # Determine risk level
    if risk_score >= 11:
        risk_level = 'CRITICAL'
    elif risk_score >= 7:
        risk_level = 'HIGH'
    elif risk_score >= 4:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'
    
    # Special case: eval() is always at least MEDIUM risk
    if 'eval(' in command_lower and risk_level == 'LOW':
        risk_level = 'MEDIUM'
    
    threat_type_str = ', '.join(set(threat_types)) if threat_types else 'UNKNOWN'
    
    return f"""RISK_LEVEL: {risk_level}
THREAT_TYPE: {threat_type_str}
DESCRIPTION: Local analysis detected {risk_level.lower()} risk patterns in the console command.
RECOMMENDATION: {'Block this command immediately' if risk_level == 'HIGH' else 'Monitor this command carefully' if risk_level == 'MEDIUM' else 'Command appears safe'}"""

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "uptime": "running"
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    print("Starting Firewall Extension Backend Server")
    print(f"Server will run on http://localhost:5000")
    print(f"Extension API endpoints:")
    print(f"   GET  /api/status - Backend status")
    print(f"   POST /api/check_url - URL safety check")
    print(f"   GET  /api/rules - Get firewall rules")
    print(f"   POST /api/rules/update - Update rules")
    print(f"   POST /api/logs - Submit logs")
    print(f"   POST /api/ai/analyze - AI command analysis")
    print(f"   GET  /health - Health check")
    print("Firewall Extension Backend Ready!")
    
    try:
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=False
        )
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        print(f"Server startup failed: {e}")
