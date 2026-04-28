"""
🤖 Firewall Guard - AI Validation Framework
Validates AI analysis before blocking decisions to prevent false positives
"""

import hashlib
import json
import re
import time
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class AIValidationFramework:
    """Enterprise-grade AI validation for security decisions"""
    
    def __init__(self):
        self.validation_rules = self.load_validation_rules()
        self.false_positive_patterns = self.load_false_positive_patterns()
        self.confidence_thresholds = {
            'CRITICAL': 0.95,
            'HIGH': 0.85,
            'MEDIUM': 0.75,
            'LOW': 0.65
        }
        self.validation_history = []
        self.block_decisions = []
        
    def load_validation_rules(self) -> Dict:
        """Load validation rules for AI analysis"""
        return {
            'required_elements': {
                'risk_assessment': True,
                'threat_type': True,
                'confidence_score': True,
                'recommendation': True
            },
            'blocked_patterns': [
                r'(?i)(password|token|key|secret)\s*=.*["\'].*["\']',  # Credentials
                r'(?i)eval\s*\(',  # Code execution
                r'(?i)document\.write\s*\(',  # DOM manipulation
                r'(?i)innerHTML\s*=',  # XSS patterns
                r'(?i)fetch\s*\(\s*["\']http',  # External requests
                r'(?i)xmlhttprequest',  # AJAX requests
                r'(?i)settimeout\s*\(',  # Timed execution
                r'(?i)setinterval\s*\(',  # Repeated execution
            ],
            'safe_patterns': [
                r'(?i)console\.(log|warn|error|info|debug)',  # Console logging
                r'(?i)math\.',  # Math operations
                r'(?i)array\.',  # Array operations
                r'(?i)string\.',  # String operations
                r'(?i)date\.',  # Date operations
                r'^\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*$',  # Simple variables
                r'^\s*\d+\s*$',  # Numbers only
                r'^\s*["\'][^"\']*["\']\s*$',  # Simple strings
            ],
            'context_analysis': {
                'development_mode': ['localhost', '127.0.0.1', 'debug', 'test'],
                'educational_content': ['tutorial', 'example', 'demo', 'sample'],
                'legitimate_libraries': ['jquery', 'react', 'vue', 'angular', 'bootstrap']
            }
        }
    
    def load_false_positive_patterns(self) -> List[Dict]:
        """Load known false positive patterns"""
        return [
            {
                'pattern': r'(?i)console\.log\s*\(\s*["\']test["\']',
                'reason': 'Test logging in development',
                'confidence_reduction': 0.8
            },
            {
                'pattern': r'(?i)debug\s*=\s*true',
                'reason': 'Debug flag in development',
                'confidence_reduction': 0.7
            },
            {
                'pattern': r'(?i)localhost|127\.0\.0\.1',
                'reason': 'Local development environment',
                'confidence_reduction': 0.6
            },
            {
                'pattern': r'(?i)alert\s*\(\s*["\'].*["\']\s*\)',
                'reason': 'Simple alert dialog',
                'confidence_reduction': 0.5
            }
        ]
    
    def validate_ai_analysis(self, command_data: Dict) -> Tuple[bool, Dict]:
        """Validate AI analysis before blocking decision"""
        
        validation_result = {
            'original_risk': command_data.get('riskLevel', 'UNKNOWN'),
            'validated_risk': 'UNKNOWN',
            'confidence_score': 0.0,
            'validation_checks': [],
            'recommendations': [],
            'should_block': False,
            'validation_timestamp': datetime.now().isoformat()
        }
        
        try:
            # 1. Check required elements in AI analysis
            required_check = self.check_required_elements(command_data)
            validation_result['validation_checks'].append(required_check)
            
            # 2. Pattern-based validation
            pattern_check = self.validate_patterns(command_data)
            validation_result['validation_checks'].append(pattern_check)
            
            # 3. Context analysis
            context_check = self.analyze_context(command_data)
            validation_result['validation_checks'].append(context_check)
            
            # 4. False positive detection
            fp_check = self.detect_false_positives(command_data)
            validation_result['validation_checks'].append(fp_check)
            
            # 5. Calculate final confidence score
            confidence_score = self.calculate_confidence_score(validation_result['validation_checks'])
            validation_result['confidence_score'] = confidence_score
            
            # 6. Determine final risk level and blocking decision
            final_risk, should_block = self.determine_final_decision(
                command_data.get('riskLevel', 'UNKNOWN'),
                confidence_score,
                validation_result['validation_checks']
            )
            
            validation_result['validated_risk'] = final_risk
            validation_result['should_block'] = should_block
            
            # 7. Generate recommendations
            validation_result['recommendations'] = self.generate_recommendations(
                validation_result['validation_checks'],
                final_risk,
                confidence_score
            )
            
            # 8. Log validation decision
            self.log_validation_decision(command_data, validation_result)
            
            return should_block, validation_result
            
        except Exception as e:
            logger.error(f"Error in AI validation: {e}")
            validation_result['error'] = str(e)
            return False, validation_result
    
    def check_required_elements(self, command_data: Dict) -> Dict:
        """Check if AI analysis contains required elements"""
        analysis = command_data.get('analysis', '')
        
        check_result = {
            'check_type': 'required_elements',
            'passed': True,
            'missing_elements': [],
            'score': 1.0
        }
        
        for element, required in self.validation_rules['required_elements'].items():
            if required:
                if element == 'risk_assessment' and not re.search(r'(?i)(risk|danger|threat|malicious)', analysis):
                    check_result['missing_elements'].append(element)
                    check_result['passed'] = False
                elif element == 'threat_type' and not re.search(r'(?i)(xss|injection|malware|phishing)', analysis):
                    check_result['missing_elements'].append(element)
                    check_result['passed'] = False
                elif element == 'confidence_score' and not re.search(r'(?i)(confident|certain|sure)', analysis):
                    check_result['missing_elements'].append(element)
                    check_result['passed'] = False
                elif element == 'recommendation' and not re.search(r'(?i)(recommend|suggest|advise)', analysis):
                    check_result['missing_elements'].append(element)
                    check_result['passed'] = False
        
        if check_result['missing_elements']:
            check_result['score'] = 0.5  # Reduce score for missing elements
        
        return check_result
    
    def validate_patterns(self, command_data: Dict) -> Dict:
        """Validate command against security patterns"""
        command = command_data.get('command', '')
        
        check_result = {
            'check_type': 'pattern_validation',
            'passed': True,
            'blocked_patterns_found': [],
            'safe_patterns_found': [],
            'score': 1.0
        }
        
        # Check for blocked patterns
        for pattern in self.validation_rules['blocked_patterns']:
            if re.search(pattern, command):
                check_result['blocked_patterns_found'].append(pattern)
                check_result['passed'] = False
                check_result['score'] -= 0.3
        
        # Check for safe patterns
        for pattern in self.validation_rules['safe_patterns']:
            if re.search(pattern, command):
                check_result['safe_patterns_found'].append(pattern)
                check_result['score'] += 0.1
        
        # Ensure score stays within bounds
        check_result['score'] = max(0.0, min(1.0, check_result['score']))
        
        return check_result
    
    def analyze_context(self, command_data: Dict) -> Dict:
        """Analyze command context for legitimacy"""
        command = command_data.get('command', '')
        url = command_data.get('url', '')
        
        check_result = {
            'check_type': 'context_analysis',
            'passed': True,
            'context_indicators': [],
            'score': 1.0
        }
        
        # Check for development indicators
        for indicator in self.validation_rules['context_analysis']['development_mode']:
            if indicator in command.lower() or indicator in url.lower():
                check_result['context_indicators'].append(f"development_mode:{indicator}")
                check_result['score'] -= 0.2
        
        # Check for educational content
        for indicator in self.validation_rules['context_analysis']['educational_content']:
            if indicator in command.lower():
                check_result['context_indicators'].append(f"educational:{indicator}")
                check_result['score'] -= 0.1
        
        # Check for legitimate libraries
        for library in self.validation_rules['context_analysis']['legitimate_libraries']:
            if library in command.lower():
                check_result['context_indicators'].append(f"legitimate_library:{library}")
                check_result['score'] += 0.1
        
        check_result['score'] = max(0.0, min(1.0, check_result['score']))
        
        return check_result
    
    def detect_false_positives(self, command_data: Dict) -> Dict:
        """Detect known false positive patterns"""
        command = command_data.get('command', '')
        
        check_result = {
            'check_type': 'false_positive_detection',
            'passed': True,
            'false_positives_found': [],
            'confidence_reduction': 0.0,
            'score': 1.0
        }
        
        for fp_pattern in self.false_positive_patterns:
            if re.search(fp_pattern['pattern'], command):
                check_result['false_positives_found'].append({
                    'pattern': fp_pattern['pattern'],
                    'reason': fp_pattern['reason']
                })
                check_result['confidence_reduction'] += fp_pattern['confidence_reduction']
                check_result['passed'] = False
        
        # Reduce score based on confidence reduction
        check_result['score'] = max(0.0, 1.0 - check_result['confidence_reduction'])
        
        return check_result
    
    def calculate_confidence_score(self, validation_checks: List[Dict]) -> float:
        """Calculate overall confidence score from validation checks"""
        if not validation_checks:
            return 0.0
        
        total_score = 0.0
        total_weight = 0.0
        
        weights = {
            'required_elements': 0.3,
            'pattern_validation': 0.4,
            'context_analysis': 0.2,
            'false_positive_detection': 0.1
        }
        
        for check in validation_checks:
            check_type = check.get('check_type', '')
            weight = weights.get(check_type, 0.25)
            score = check.get('score', 0.0)
            
            total_score += score * weight
            total_weight += weight
        
        return total_score / total_weight if total_weight > 0 else 0.0
    
    def determine_final_decision(self, original_risk: str, confidence: float, validation_checks: List[Dict]) -> Tuple[str, bool]:
        """Determine final risk level and blocking decision"""
        
        # Adjust risk level based on confidence
        if confidence < 0.5:
            # Low confidence - downgrade risk
            if original_risk == 'CRITICAL':
                final_risk = 'HIGH'
            elif original_risk == 'HIGH':
                final_risk = 'MEDIUM'
            elif original_risk == 'MEDIUM':
                final_risk = 'LOW'
            else:
                final_risk = 'LOW'
        elif confidence < 0.7:
            # Medium confidence - slight downgrade
            if original_risk == 'CRITICAL':
                final_risk = 'HIGH'
            else:
                final_risk = original_risk
        else:
            # High confidence - keep original risk
            final_risk = original_risk
        
        # Determine blocking based on final risk and confidence
        threshold = self.confidence_thresholds.get(final_risk, 0.8)
        should_block = confidence >= threshold and final_risk in ['CRITICAL', 'HIGH']
        
        return final_risk, should_block
    
    def generate_recommendations(self, validation_checks: List[Dict], final_risk: str, confidence: float) -> List[str]:
        """Generate recommendations based on validation results"""
        recommendations = []
        
        if confidence < 0.5:
            recommendations.append("Low confidence in AI analysis - recommend manual review")
        
        if final_risk in ['CRITICAL', 'HIGH']:
            recommendations.append("High risk detected - consider blocking")
        elif final_risk == 'MEDIUM':
            recommendations.append("Medium risk - monitor closely")
        else:
            recommendations.append("Low risk - allow with monitoring")
        
        # Add specific recommendations based on failed checks
        for check in validation_checks:
            if not check.get('passed', True):
                if check.get('check_type') == 'false_positive_detection':
                    recommendations.append("False positive patterns detected - verify context")
                elif check.get('check_type') == 'required_elements':
                    recommendations.append("AI analysis incomplete - request detailed analysis")
        
        return recommendations
    
    def log_validation_decision(self, command_data: Dict, validation_result: Dict):
        """Log validation decision for audit trail"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'command_hash': hashlib.sha256(command_data.get('command', '').encode()).hexdigest(),
            'original_risk': command_data.get('riskLevel'),
            'validated_risk': validation_result['validated_risk'],
            'confidence_score': validation_result['confidence_score'],
            'should_block': validation_result['should_block'],
            'validation_checks': validation_result['validation_checks']
        }
        
        self.validation_history.append(log_entry)
        
        # Keep only last 1000 entries
        if len(self.validation_history) > 1000:
            self.validation_history = self.validation_history[-1000:]
        
        logger.info(f"AI Validation: {validation_result['validated_risk']} risk, "
                   f"confidence: {validation_result['confidence_score']:.2f}, "
                   f"block: {validation_result['should_block']}")
    
    def get_validation_stats(self) -> Dict:
        """Get validation statistics"""
        if not self.validation_history:
            return {'total_validations': 0}
        
        total = len(self.validation_history)
        blocked = sum(1 for entry in self.validation_history if entry['should_block'])
        avg_confidence = sum(entry['confidence_score'] for entry in self.validation_history) / total
        
        risk_distribution = {}
        for entry in self.validation_history:
            risk = entry['validated_risk']
            risk_distribution[risk] = risk_distribution.get(risk, 0) + 1
        
        return {
            'total_validations': total,
            'blocked_decisions': blocked,
            'block_rate': blocked / total * 100,
            'average_confidence': avg_confidence,
            'risk_distribution': risk_distribution,
            'last_validation': self.validation_history[-1]['timestamp'] if self.validation_history else None
        }

# Global validation framework instance
ai_validator = AIValidationFramework()
