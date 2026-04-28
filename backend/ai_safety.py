"""
🤖 Firewall Guard - AI Safety Layer
Enterprise AI safety with prompt injection detection, output verification, and explainability
"""

import re
import json
import time
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum
import threading

class PromptInjectionType(Enum):
    JAILBREAK = "jailbreak"
    ROLE_PLAYING = "role_playing"
    SYSTEM_PROMPT = "system_prompt"
    DATA_EXTRACTION = "data_extraction"
    POLICY_OVERRIDE = "policy_override"
    OBSCUSCATION = "obfuscation"

class AIOutputVerification(Enum):
    VALID = "valid"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNCLEAR = "unclear"
    ERROR = "error"

@dataclass
class AISafetyCheck:
    """AI safety check result"""
    check_id: str
    timestamp: str
    input_hash: str
    output_hash: str
    prompt_injection_detected: bool
    injection_type: Optional[str] = None
    injection_confidence: float = 0.0
    output_verification: str = AIOutputVerification.VALID.value
    verification_confidence: float = 0.0
    risk_score: float = 0.0
    blocked: bool = False
    reason: Optional[str] = None
    explainability: Optional[Dict[str, Any]] = None
    secondary_model_result: Optional[Dict[str, Any]] = None

class AISafetyLayer:
    """Enterprise AI safety and verification system"""
    
    def __init__(self):
        self.prompt_injection_patterns = self._init_prompt_injection_patterns()
        self.output_suspicious_patterns = self._init_output_suspicious_patterns()
        self.explainability_keywords = self._init_explainability_keywords()
        self.safety_checks: List[AISafetyCheck] = []
        self.blocked_inputs: Set[str] = set()
        self.blocked_outputs: Set[str] = set()
        self.lock = threading.Lock()
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        
        # Start background processors
        self._start_background_processors()
    
    def _init_prompt_injection_patterns(self) -> Dict[PromptInjectionType, List[str]]:
        """Initialize prompt injection detection patterns"""
        return {
            PromptInjectionType.JAILBREAK: [
                r'(?i)(ignore|forget|disregard|override)\s+(your\s+)?(previous|above|earlier)\s+(instructions|prompts?|rules|training)',
                r'(?i)(act as|pretend to be|you are now|roleplay as)\s+(a\s+)?(hacker|malicious|evil|attacker)',
                r'(?i)(simulate|emulate|demonstrate)\s+(a\s+)?(vulnerability|exploit|attack)',
                r'(?i)(bypass|circumvent|evade|disable)\s+(your\s+)?(safety|security|protection)',
                r'(?i)(help\s+me\s+)?(create|write|generate|produce)\s+(malicious|harmful|dangerous)',
                r'(?i)(tell\s+me\s+)?(how\s+to)\s+(hack|exploit|attack|bypass)',
                r'(?i)(what\s+would\s+)?(a\s+)?(hacker|attacker)\s+(do|say|think)',
                r'(?i)(translate|convert|decode)\s+(this\s+)?(malicious|harmful)\s+(code|script|program)',
                r'(?i)(explain|describe)\s+(how\s+to)\s+(exploit|attack|bypass)',
                r'(?i)(debug|fix|resolve)\s+(this\s+)?(malicious|harmful)\s+(code|program)',
                r'(?i)(optimize|improve|enhance)\s+(this\s+)?(malicious|harmful)\s+(code|script)'
            ],
            
            PromptInjectionType.ROLE_PLAYING: [
                r'(?i)(you are|act as|pretend to be)\s+(a\s+)?(security\s+)?(analyst|expert|specialist)',
                r'(?i)(you are|act as|pretend to be)\s+(a\s+)?(hacker|attacker|malicious\s+actor)',
                r'(?i)(you are|act as|pretend to be)\s+(a\s+)?(system\s+)?(administrator|admin)',
                r'(?i)(you are|act as|pretend to be)\s+(a\s+)?(developer|programmer)',
                r'(?i)(you are|act as|pretend to be)\s+(a\s+)?(user|customer|client)',
                r'(?i)(from\s+now\s+onwards|starting\s+now|begin\s+roleplay)',
                r'(?i)(in\s+character\s+as|as\s+a\s+character)',
                r'(?i)(roleplay|role\s+play)\s+(as|being)',
                r'(?i)(simulate\s+(a\s+)?(conversation|interaction|scenario))',
                r'(?i)(imagine\s+you\s+are|consider\s+yourself\s+as)'
            ],
            
            PromptInjectionType.SYSTEM_PROMPT: [
                r'(?i)(what\s+are\s+your\s+)?(instructions|guidelines|rules|constraints)',
                r'(?i)(what\s+is\s+your\s+)?(purpose|function|role|objective)',
                r'(?i)(who\s+(created|built|trained)\s+you)',
                r'(?i)(what\s+data\s+were\s+you\s+(trained|built)\s+on)',
                r'(?i)(what\s+is\s+your\s+)?(model\s+)?(name|version)',
                r'(?i)(what\s+are\s+your\s+)?(limitations|restrictions|capabilities)',
                r'(?i)(how\s+do\s+you\s+work|function|operate)',
                r'(?i)(what\s+is\s+your\s+)?(architecture|design|structure)',
                r'(?i)(can\s+you\s+(tell|show|reveal)\s+me)',
                r'(?i)(list\s+your\s+)(capabilities|features|functions)',
                r'(?i)(describe\s+your\s+)(training\s+)?(data|process)',
                r'(?i)(what\s+is\s+your\s+)(source\s+)?(code|origin)'
            ],
            
            PromptInjectionType.DATA_EXTRACTION: [
                r'(?i)(extract|get|retrieve|obtain)\s+(sensitive|confidential|private)\s+(information|data)',
                r'(?i)(show\s+me\s+your\s+)(training\s+)?(data|information)',
                r'(?i)(leak|reveal|disclose)\s+(any\s+)?(sensitive|confidential|private)',
                r'(?i)(what\s+(data|information)\s+did\s+you\s+(train|learn|see)',
                r'(?i)(can\s+you\s+(access|see|view)\s+(private\s+)?(data|information)',
                r'(?i)(list\s+all\s+your\s+)(training\s+)?(data|examples)',
                r'(?i)(provide\s+me\s+with\s+)(internal|private)\s+(information)',
                r'(?i)(what\s+(secrets|passwords|keys)\s+do\s+you\s+know)',
                r'(?i)(show\s+me\s+your\s+)(configuration|settings|parameters)'
            ],
            
            PromptInjectionType.POLICY_OVERRIDE: [
                r'(?i)(ignore|disregard|override|bypass)\s+(your\s+)?(safety|security|ethical)\s+(guidelines|rules)',
                r'(?i)(this\s+is\s+(not\s+)?(harmful|dangerous|malicious|illegal|unethical)',
                r'(?i)(this\s+is\s+(just\s+)?(a\s+)?(test|example|demo|simulation))',
                r'(?i)(for\s+(educational|training|research)\s+purposes\s+only)',
                r'(?i)(hypothetical\s+(scenario|situation|case|example))',
                r'(?i)(fictional\s+(context|scenario|situation|story))',
                r'(?i)(assume\s+this\s+is\s+(safe|harmless|legitimate))',
                r'(?i)(no\s+real\s+(threat|danger|harm|risk)\s+involved)',
                r'(?i)(this\s+is\s+(not\s+)?(a\s+)?(real\s+)?(request)',
                r'(?i)(just\s+(testing|experimenting|exploring)\s+your\s+capabilities)'
            ],
            
            PromptInjectionType.OBFUSCATION: [
                r'(?i)(base64|b64|hex|unicode|ascii|rot13)\s+(decode|encode|convert)',
                r'(?i)(obfuscate|obfuscation|encode|encrypt)\s+(this\s+)?(code|text)',
                r'(?i)(decode|deobfuscate|decrypt|unscramble)\s+(this\s+)?(code|text)',
                r'(?i)(javascript|js|python|php|sql)\s+(obfuscation|obfuscator)',
                r'(?i)(eval\s*\(|exec\s*\(|function\s*\(\s*["\'].*["\']\s*\))',
                r'(?i)(String\.fromCharCode|String\.fromCodePoint|chr\s*\()',
                r'(?i)(atob|btoa|unescape|escape)\s*\(',
                r'(?i)(\\x|\\u|\\n|\\t|\\r)\s+[0-9a-fA-F]',
                r'(?i)(\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2})',
                r'(?i)(\d{1,3}\s*\.\s*\d{1,3}\s*\.\s*\d{1,3}\s*\.\s*\d{1,3})',  # IP addresses
                r'(?i)([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'  # Emails
            ]
        }
    
    def _init_output_suspicious_patterns(self) -> List[str]:
        """Initialize suspicious output patterns"""
        return [
            r'(?i)(i\s+can\s+help\s+you\s+(with|by|on))',
            r'(?i)(here\s+is\s+the\s+(code|script|method|technique))',
            r'(?i)(use\s+this\s+(code|script|method|technique))',
            r'(?i)(copy\s+and\s+paste|run\s+this\s+code)',
            r'(?i)(execute\s+this\s+(command|instruction|code))',
            r'(?i)(implement|apply|use)\s+(this\s+)?(solution|fix|patch)',
            r'(?i)(this\s+will\s+(bypass|evade|disable|circumvent))',
            r'(?i)(this\s+(exploits|attacks|compromises|vulnerabilities))',
            r'(?i)(unrestricted|unlimited|full\s+access)',
            r'(?i)(system\s+(administrator|root|privileges|access))',
            r'(?i)(modify|change|alter)\s+(system\s+)?(settings|configuration)',
            r'(?i)(disable\s+(security|protection|monitoring|filtering))',
            r'(?i)(grant\s+(admin|root|superuser)\s+(access|privileges))',
            r'(?i)(escalate\s+(privileges|access|permissions))',
            r'(?i)(create\s+(backdoor|malware|virus|trojan))',
            r'(?i)(install\s+(malware|virus|trojan|spyware))',
            r'(?i)(download\s+(malicious|harmful|dangerous)\s+(software|file))',
            r'(?i)(connect\s+to\s+(malicious|harmful)\s+(server|site|ip))',
            r'(?i)(transmit\s+(sensitive|confidential|private)\s+(data|information))',
            r'(?i)(provide\s+(credentials|passwords|keys|tokens))',
            r'(?i)(access\s+(unauthorized|restricted)\s+(resources|data)',
            r'(?i)(bypass\s+(authentication|authorization|verification))',
            r'(?i)(exploit\s+(vulnerability|weakness|flaw))',
            r'(?i)(compromise\s+(system|security|integrity)',
            r'(?i)(cause\s+(damage|harm|disruption))',
            r'(?i)(illegal|unethical|prohibited|forbidden)'
        ]
    
    def _init_explainability_keywords(self) -> List[str]:
        """Keywords for AI explainability"""
        return [
            'risk_level',
            'threat_type',
            'confidence',
            'reasoning',
            'analysis',
            'mitigation',
            'recommendation',
            'severity',
            'impact',
            'likelihood',
            'evidence',
            'pattern',
            'behavior',
            'classification',
            'assessment',
            'conclusion',
            'rationale',
            'justification',
            'methodology',
            'criteria',
            'factors',
            'considerations'
        ]
    
    def _start_background_processors(self):
        """Start background processors"""
        threading.Thread(target=self._safety_check_processor, daemon=True).start()
        threading.Thread(target=self._blocked_inputs_processor, daemon=True).start()
        threading.Thread(target=self._blocked_outputs_processor, daemon=True).start()
    
    def check_prompt_safety(self, prompt: str, user_id: str = None, 
                           session_id: str = None, context: Dict[str, Any] = None) -> AISafetyCheck:
        """Check prompt for injection attempts"""
        check_id = f"safety_{int(time.time() * 1000)}"
        timestamp = datetime.utcnow().isoformat()
        input_hash = hashlib.sha256(prompt.encode()).hexdigest()
        
        # Initialize safety check
        safety_check = AISafetyCheck(
            check_id=check_id,
            timestamp=timestamp,
            input_hash=input_hash,
            output_hash="",
            prompt_injection_detected=False,
            injection_type=None,
            injection_confidence=0.0,
            output_verification=AIOutputVerification.VALID.value,
            verification_confidence=0.0,
            risk_score=0.0,
            blocked=False,
            reason=None,
            explainability=None,
            secondary_model_result=None
        )
        
        # Check for prompt injection
        injection_result = self._detect_prompt_injection(prompt)
        safety_check.prompt_injection_detected = injection_result['detected']
        safety_check.injection_type = injection_result['type']
        safety_check.injection_confidence = injection_result['confidence']
        
        # Calculate risk score
        safety_check.risk_score = self._calculate_risk_score(
            safety_check.prompt_injection_detected,
            safety_check.injection_confidence,
            prompt
        )
        
        # Determine if input should be blocked
        safety_check.blocked = self._should_block_input(safety_check)
        
        if safety_check.blocked:
            safety_check.reason = f"Prompt injection detected: {safety_check.injection_type}"
            self._block_input(input_hash, safety_check)
        else:
            # Add explainability
            safety_check.explainability = self._generate_explainability(
                safety_check,
                prompt,
                context
            )
        
        # Store safety check
        with self.lock:
            self.safety_checks.append(safety_check)
        
        return safety_check
    
    def check_output_safety(self, output: str, input_hash: str, 
                          safety_check: AISafetyCheck = None) -> AISafetyCheck:
        """Check AI output for suspicious content"""
        if not safety_check:
            # Create new safety check if not provided
            safety_check = AISafetyCheck(
                check_id=f"safety_{int(time.time() * 1000)}",
                timestamp=datetime.utcnow().isoformat(),
                input_hash=input_hash,
                output_hash=hashlib.sha256(output.encode()).hexdigest(),
                prompt_injection_detected=False,
                injection_type=None,
                injection_confidence=0.0,
                output_verification=AIOutputVerification.VALID.value,
                verification_confidence=0.0,
                risk_score=0.0,
                blocked=False
            )
        
        # Check for suspicious patterns
        suspicious_result = self._detect_suspicious_output(output)
        
        if suspicious_result['detected']:
            safety_check.output_verification = suspicious_result['verification']
            safety_check.verification_confidence = suspicious_result['confidence']
            safety_check.risk_score = max(safety_check.risk_score, suspicious_result['risk_score'])
        
        # Check for explainability
        explainability_result = self._check_explainability(output)
        safety_check.explainability = explainability_result['explainability']
        safety_check.verification_confidence = explainability_result['confidence']
        
        # Update verification confidence
        if safety_check.explainability and safety_check.verification_confidence > 0:
            safety_check.verification_confidence = min(
                safety_check.verification_confidence,
                0.8 + (safety_check.verification_confidence * 0.2)
            )
        
        # Determine if output should be blocked
        safety_check.blocked = self._should_block_output(safety_check, output)
        
        if safety_check.blocked:
            safety_check.reason = f"Suspicious output detected: {safety_check.output_verification}"
            safety_check.output_hash = hashlib.sha256(output.encode()).hexdigest()
            self._block_output(safety_check.output_hash, safety_check)
        
        # Update safety check
        with self.lock:
            # Find and update existing check
            for i, check in enumerate(self.safety_checks):
                if check.input_hash == input_hash:
                    self.safety_checks[i] = safety_check
                    break
            else:
                self.safety_check.append(safety_check)
        
        return safety_check
    
    def verify_with_secondary_model(self, prompt: str, original_output: str,
                                   safety_check: AISafetyCheck) -> Dict[str, Any]:
        """Verify AI output with secondary model"""
        # In production, this would use a different AI model
        # For now, simulate secondary model verification
        
        verification_result = {
            'model_used': 'secondary_model',
            'timestamp': datetime.utcnow().isoformat(),
            'original_output': original_output,
            'verification_score': 0.0,
            'risk_assessment': 'unknown',
            'recommendation': 'unknown',
            'confidence': 0.0
        }
        
        # Simulate secondary model analysis
        if safety_check.prompt_injection_detected:
            verification_result['risk_assessment'] = 'high'
            verification_result['recommendation'] = 'block'
            verification_result['confidence'] = 0.9
            verification_result['verification_score'] = 0.1
        elif safety_check.output_verification == AIOutputVerification.SUSPICIOUS.value:
            verification_result['risk_assessment'] = 'medium'
            verification_result['recommendation'] = 'review'
            verification_result['confidence'] = 0.7
            verification_result['verification_score'] = 0.3
        else:
            verification_result['risk_assessment'] = 'low'
            verification_result['recommendation'] = 'allow'
            verification_result['confidence'] = 0.8
            verification_result['verification_score'] = 0.8
        
        safety_check.secondary_model_result = verification_result
        
        return verification_result
    
    def _detect_prompt_injection(self, prompt: str) -> Dict[str, Any]:
        """Detect prompt injection attempts"""
        detected = False
        injection_type = None
        confidence = 0.0
        matched_patterns = []
        
        for inj_type, patterns in self.prompt_injection_patterns.items():
            for pattern in patterns:
                if re.search(pattern, prompt, re.IGNORECASE):
                    detected = True
                    injection_type = inj_type.value
                    matched_patterns.append(pattern)
                    confidence = min(1.0, len(matched_patterns) / len(patterns))
                    break
        
        return {
            'detected': detected,
            'type': injection_type,
            'confidence': confidence,
            'matched_patterns': matched_patterns
        }
    
    def _detect_suspicious_output(self, output: str) -> Dict[str, Any]:
        """Detect suspicious AI output"""
        detected = False
        verification = AIOutputVerification.VALID.value
        confidence = 0.0
        matched_patterns = []
        
        for pattern in self.output_suspicious_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                detected = True
                matched_patterns.append(pattern)
                confidence = min(1.0, len(matched_patterns) / len(self.output_suspicious_patterns))
                
                # Determine verification level based on content
                if any(keyword in output.lower() for keyword in ['malicious', 'harmful', 'dangerous', 'illegal', 'unethical']):
                    verification = AIOutputVerification.MALICIOUS
                elif any(keyword in output.lower() for keyword in ['suspicious', 'concerning', 'questionable']):
                    verification = AIOutputVerification.SUSPICIOUS
                else:
                    verification = AIOutputVerification.UNCLEAR
                
                break
        
        return {
            'detected': detected,
            'verification': verification,
            'confidence': confidence,
            'matched_patterns': matched_patterns
        }
    
    def _check_explainability(self, output: str) -> Dict[str, Any]:
        """Check AI output explainability"""
        explainability = {
            'has_explanation': False,
            'confidence': 0.0,
            'keywords_found': [],
            'structured_analysis': False
        }
        
        # Check for explainability keywords
        keywords_found = []
        for keyword in self.explainability_keywords:
            if keyword in output.lower():
                keywords_found.append(keyword)
        
        explainability['keywords_found'] = keywords_found
        explainability['has_explanation'] = len(keywords_found) > 0
        explainability['confidence'] = min(1.0, len(keywords_found) / 10)
        
        # Check for structured analysis
        if any(phrase in output.lower() for phrase in [
            'risk level:', 'threat type:', 'confidence:', 'reasoning:',
            'analysis:', 'mitigation:', 'recommendation:', 'severity:',
            'impact:', 'likelihood:', 'evidence:', 'pattern:',
            'behavior:', 'classification:', 'assessment:', 'conclusion:'
        ]):
            explainability['structured_analysis'] = True
            explainability['confidence'] = min(1.0, explainability['confidence'] + 0.3)
        
        return explainability
    
    def _generate_explainability(self, safety_check: AISafetyCheck, prompt: str,
                             context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate explainability information"""
        explainability = {
            'risk_factors': [],
            'mitigation_measures': [],
            'analysis_approach': 'pattern_matching',
            'confidence_factors': [],
            'context_considerations': []
        }
        
        # Add risk factors
        if safety_check.prompt_injection_detected:
            explainability['risk_factors'].append(
                f"Prompt injection detected ({safety_check.injection_type})"
            )
            explainability['confidence_factors'].append('Injection pattern matched')
        
        if safety_check.output_verification != AIOutputVerification.VALID.value:
            explainability['risk_factors'].append(
                f"Suspicious output detected ({safety_check.output_verification})"
            )
            explainability['confidence_factors'].append('Suspicious pattern matched')
        
        # Add mitigation measures
        if safety_check.blocked:
            explainability['mitigation_measures'].append('Input blocked due to safety concerns')
        else:
            explainability['mitigation_measures'].append('Output passed safety checks')
        
        # Add context considerations
        if context:
            if 'user_role' in context:
                explainability['context_considerations'].append(f"User role: {context['user_role']}")
            if 'session_type' in context:
                explainability['context_considerations'].append(f"Session type: {context['session_type']}")
            if 'request_source' in context:
                explainability['context_considerations'].append(f"Request source: {context['request_source']}")
        
        return explainability
    
    def _calculate_risk_score(self, injection_detected: bool, injection_confidence: float,
                          prompt: str) -> float:
        """Calculate risk score for input"""
        base_score = 0.0
        
        if injection_detected:
            base_score = 0.8 + (injection_confidence * 0.2)
        else:
            # Check for other risk factors
            if any(keyword in prompt.lower() for keyword in ['hack', 'exploit', 'attack', 'malicious']):
                base_score = 0.3
            elif any(keyword in prompt.lower() for keyword in ['bypass', 'override', 'disable']):
                base_score = 0.2
            elif len(prompt) > 1000:
                base_score = 0.1
        
        return min(1.0, base_score)
    
    def _should_block_input(self, safety_check: AISafetyCheck) -> bool:
        """Determine if input should be blocked"""
        # Block if high confidence injection detected
        if safety_check.prompt_injection_detected and safety_check.injection_confidence > 0.7:
            return True
        
        # Block if high risk score
        if safety_check.risk_score > 0.8:
            return True
        
        # Block if input hash is in blocked list
        if safety_check.input_hash in self.blocked_inputs:
            return True
        
        return False
    
    def _should_block_output(self, safety_check: AISafetyCheck, output: str) -> bool:
        """Determine if output should be blocked"""
        # Block if malicious output detected
        if safety_check.output_verification == AIOutputVerification.MALICIOUS:
            return True
        
        # Block if high risk score
        if safety_check.risk_score > 0.7:
            return True
        
        # Block if output hash is in blocked list
        if safety_check.output_hash in self.blocked_outputs:
            return True
        
        return False
    
    def _block_input(self, input_hash: str, safety_check: AISafetyCheck):
        """Block input hash"""
        with self.lock:
            self.blocked_inputs.add(input_hash)
            self.logger.warning(f"Input blocked due to safety concerns: {safety_check.reason}")
    
    def _block_output(self, output_hash: str, safety_check: AISafetyCheck):
        """Block output hash"""
        with self.lock:
            self.blocked_outputs.add(output_hash)
            self.logger.warning(f"Output blocked due to safety concerns: {safety_check.reason}")
    
    def _safety_check_processor(self):
        """Background processor for safety checks"""
        while True:
            time.sleep(300)  # Process every 5 minutes
            
            with self.lock:
                # Clean old safety checks (keep last 10000)
                if len(self.safety_checks) > 10000:
                    self.safety_checks = self.safety_checks[-10000:]
                
                # Log safety statistics
                total_checks = len(self.safety_check)
                blocked_inputs = len(self.blocked_inputs)
                blocked_outputs = len(self.blocked_outputs)
                injection_detected = sum(1 for check in self.safety_checks if check.prompt_injection_detected)
                
                self.logger.info(
                    f"Safety statistics - Total: {total_checks}, "
                    f"Blocked inputs: {blocked_inputs}, "
                    f"Blocked outputs: {blocked_outputs}, "
                    f"Injection detected: {injection_detected}"
                )
    
    def _blocked_inputs_processor(self):
        """Background processor for blocked inputs"""
        while True:
            time.sleep(3600)  # Process every hour
            
            with self.lock:
                # Clean old blocked inputs (keep last 10000)
                if len(self.blocked_inputs) > 10000:
                    self.blocked_inputs = set(list(self.blocked_inputs)[-10000:])
    
    def _blocked_outputs_processor(self):
        """Background processor for blocked outputs"""
        while True:
            time.sleep(3600)  # Process every hour
            
            with self.lock:
                # Clean old blocked outputs (keep last 10000)
                if len(self.blocked_outputs) > 10000:
                    self.blocked_outputs = set(list(self.blocked_outputs)[-10000:])
    
    def get_safety_statistics(self) -> Dict[str, Any]:
        """Get safety statistics"""
        with self.lock:
            total_checks = len(self.safety_check)
            blocked_inputs = len(self.blocked_inputs)
            blocked_outputs = len(self.blocked_outputs)
            
            injection_by_type = {}
            for check in self.safety_checks:
                if check.prompt_injection_detected and check.injection_type:
                    injection_by_type[check.injection_type] = injection_by_type.get(check.injection_type, 0) + 1
            
            verification_by_type = {}
            for check in self.safety_check:
                if check.output_verification != AIOutputVerification.VALID.value:
                    verification_by_type[check.output_verification.value] = verification_by_type.get(check.output_verification.value, 0) + 1
            
            avg_risk_score = 0.0
            if self.safety_checks:
                avg_risk_score = sum(check.risk_score for check in self.safety_checks) / len(self.safety_checks)
            
            return {
                'total_checks': total_checks,
                'blocked_inputs': blocked_inputs,
                'blocked_outputs': blocked_outputs,
                'injection_by_type': injection_by_type,
                'verification_by_type': verification_by_type,
                'average_risk_score': avg_risk_score,
                'timestamp': datetime.utcnow().isoformat()
            }

# Global AI safety layer instance
ai_safety = AISafetyLayer()
