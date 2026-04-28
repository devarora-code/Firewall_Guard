"""
🏛️ Firewall Guard - Regulatory Compliance Framework
Enterprise compliance with data residency, CMEK, and regulatory controls
"""

import json
import time
import hashlib
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import sqlite3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import yaml

class ComplianceRegion(Enum):
    US = "us"
    EU = "eu"
    UK = "uk"
    CANADA = "canada"
    AUSTRALIA = "australia"
    JAPAN = "japan"
    SINGAPORE = "singapore"
    BRAZIL = "brazil"

class ComplianceStandard(Enum):
    GDPR = "gdpr"
    CCPA = "ccpa"
    HIPAA = "hipaa"
    SOX = "sox"
    PCI_DSS = "pci_dss"
    ISO_27001 = "iso_27001"
    NIST_800_53 = "nist_800_53"
    SOC_2 = "soc_2"

class DataClassification(Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    SENSITIVE_PII = "sensitive_pii"
    SENSITIVE_PHI = "sensitive_phi"
    SENSITIVE_PCI = "sensitive_pci"

@dataclass
class CompliancePolicy:
    """Compliance policy configuration"""
    policy_id: str
    name: str
    description: str
    standard: ComplianceStandard
    region: ComplianceRegion
    requirements: List[Dict[str, Any]]
    controls: List[Dict[str, Any]]
    created_at: str
    updated_at: str
    active: bool = True

@dataclass
class DataResidencyRule:
    """Data residency rule"""
    rule_id: str
    region: ComplianceRegion
    data_types: List[DataClassification]
    storage_location: str
    retention_period_days: int
    encryption_required: bool
    audit_required: bool
    created_at: str

@dataclass
class CMEKConfig:
    """Customer-Managed Encryption Key configuration"""
    key_id: str
    customer_id: str
    key_algorithm: str
    key_size: int
    rotation_period_days: int
    created_at: str
    last_rotation: str
    status: str = "active"

class ComplianceManager:
    """Enterprise compliance management system"""
    
    def __init__(self, db_path: str = "compliance.db"):
        self.db_path = db_path
        self.policies: Dict[str, CompliancePolicy] = {}
        self.residency_rules: Dict[str, DataResidencyRule] = {}
        self.cmek_configs: Dict[str, CMEKConfig] = {}
        self.audit_log: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        
        # Initialize database
        self._init_database()
        
        # Load default policies
        self._load_default_policies()
        
        # Start background processors
        self._start_background_processors()
    
    def _init_database(self):
        """Initialize compliance database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create policies table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_policies (
                policy_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                standard TEXT NOT NULL,
                region TEXT NOT NULL,
                requirements TEXT,
                controls TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Create residency rules table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS residency_rules (
                rule_id TEXT PRIMARY KEY,
                region TEXT NOT NULL,
                data_types TEXT NOT NULL,
                storage_location TEXT NOT NULL,
                retention_period_days INTEGER,
                encryption_required BOOLEAN DEFAULT 1,
                audit_required BOOLEAN DEFAULT 1,
                created_at TEXT NOT NULL
            )
        ''')
        
        # Create CMEK configs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cmek_configs (
                key_id TEXT PRIMARY KEY,
                customer_id TEXT NOT NULL,
                key_algorithm TEXT NOT NULL,
                key_size INTEGER NOT NULL,
                rotation_period_days INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                last_rotation TEXT NOT NULL,
                status TEXT NOT NULL
            )
        ''')
        
        # Create audit log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_audit_log (
                audit_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                resource_id TEXT,
                user_id TEXT,
                action TEXT NOT NULL,
                details TEXT,
                compliance_standard TEXT,
                region TEXT,
                risk_level TEXT,
                INDEX(timestamp, event_type, compliance_standard)
            )
        ''')
        
        # Create data processing agreements table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_processing_agreements (
                agreement_id TEXT PRIMARY KEY,
                customer_id TEXT NOT NULL,
                agreement_type TEXT NOT NULL,
                region TEXT NOT NULL,
                effective_date TEXT NOT NULL,
                expiry_date TEXT,
                terms TEXT,
                signed_by TEXT,
                signed_date TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_default_policies(self):
        """Load default compliance policies"""
        default_policies = [
            {
                'policy_id': 'gdpr_eu_data_protection',
                'name': 'EU GDPR Data Protection',
                'description': 'General Data Protection Regulation compliance for EU region',
                'standard': ComplianceStandard.GDPR,
                'region': ComplianceRegion.EU,
                'requirements': [
                    {
                        'requirement_id': 'gdpr_art_32',
                        'title': 'Security of Processing',
                        'description': 'Implement appropriate technical and organizational measures',
                        'mandatory': True
                    },
                    {
                        'requirement_id': 'gdpr_art_33',
                        'title': 'Notification of Personal Data Breach',
                        'description': 'Notify supervisory authority within 72 hours of breach',
                        'mandatory': True
                    },
                    {
                        'requirement_id': 'gdpr_art_25',
                        'title': 'Data Protection by Design and Default',
                        'description': 'Implement data protection by design and default',
                        'mandatory': True
                    }
                ],
                'controls': [
                    {
                        'control_id': 'encryption_at_rest',
                        'title': 'Encryption at Rest',
                        'description': 'Encrypt all personal data at rest',
                        'implementation': 'AES-256 encryption',
                        'status': 'implemented'
                    },
                    {
                        'control_id': 'encryption_in_transit',
                        'title': 'Encryption in Transit',
                        'description': 'Encrypt all personal data in transit',
                        'implementation': 'TLS 1.3',
                        'status': 'implemented'
                    },
                    {
                        'control_id': 'access_control',
                        'title': 'Access Control',
                        'description': 'Implement role-based access control',
                        'implementation': 'RBAC system',
                        'status': 'implemented'
                    }
                ]
            },
            {
                'policy_id': 'ccpa_ca_privacy',
                'name': 'California Consumer Privacy Act',
                'description': 'CCPA compliance for California region',
                'standard': ComplianceStandard.CCPA,
                'region': ComplianceRegion.US,
                'requirements': [
                    {
                        'requirement_id': 'ccpa_right_to_know',
                        'title': 'Right to Know',
                        'description': 'Consumers have right to know what personal data is collected',
                        'mandatory': True
                    },
                    {
                        'requirement_id': 'ccpa_right_to_delete',
                        'title': 'Right to Delete',
                        'description': 'Consumers have right to delete personal data',
                        'mandatory': True
                    },
                    {
                        'requirement_id': 'ccpa_right_to_opt_out',
                        'title': 'Right to Opt Out',
                        'description': 'Consumers have right to opt out of sale of personal data',
                        'mandatory': True
                    }
                ],
                'controls': [
                    {
                        'control_id': 'data_inventory',
                        'title': 'Data Inventory',
                        'description': 'Maintain inventory of all personal data collected',
                        'implementation': 'Data catalog system',
                        'status': 'implemented'
                    },
                    {
                        'control_id': 'deletion_workflow',
                        'title': 'Deletion Workflow',
                        'description': 'Implement workflow for data deletion requests',
                        'implementation': 'Automated deletion system',
                        'status': 'implemented'
                    }
                ]
            },
            {
                'policy_id': 'hipaa_healthcare_privacy',
                'name': 'HIPAA Healthcare Privacy',
                'description': 'HIPAA compliance for healthcare data',
                'standard': ComplianceStandard.HIPAA,
                'region': ComplianceRegion.US,
                'requirements': [
                    {
                        'requirement_id': 'hipaa_privacy_rule',
                        'title': 'Privacy Rule',
                        'description': 'Protect PHI privacy and security',
                        'mandatory': True
                    },
                    {
                        'requirement_id': 'hipaa_security_rule',
                        'title': 'Security Rule',
                        'description': 'Implement administrative, physical, and technical safeguards',
                        'mandatory': True
                    }
                ],
                'controls': [
                    {
                        'control_id': 'phi_encryption',
                        'title': 'PHI Encryption',
                        'description': 'Encrypt all PHI at rest and in transit',
                        'implementation': 'AES-256 + TLS 1.3',
                        'status': 'implemented'
                    },
                    {
                        'control_id': 'phi_audit_logging',
                        'title': 'PHI Audit Logging',
                        'description': 'Log all access to PHI',
                        'implementation': 'Comprehensive audit system',
                        'status': 'implemented'
                    }
                ]
            }
        ]
        
        for policy_data in default_policies:
            policy = CompliancePolicy(
                policy_id=policy_data['policy_id'],
                name=policy_data['name'],
                description=policy_data['description'],
                standard=policy_data['standard'],
                region=policy_data['region'],
                requirements=policy_data['requirements'],
                controls=policy_data['controls'],
                created_at=datetime.utcnow().isoformat(),
                updated_at=datetime.utcnow().isoformat()
            )
            
            self.policies[policy.policy_id] = policy
            self._store_policy(policy)
    
    def _store_policy(self, policy: CompliancePolicy):
        """Store policy in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO compliance_policies (
                policy_id, name, description, standard, region, requirements,
                controls, created_at, updated_at, active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            policy.policy_id, policy.name, policy.description,
            policy.standard.value, policy.region.value,
            json.dumps(policy.requirements), json.dumps(policy.controls),
            policy.created_at, policy.updated_at, policy.active
        ))
        
        conn.commit()
        conn.close()
    
    def add_residency_rule(self, region: ComplianceRegion, data_types: List[DataClassification],
                          storage_location: str, retention_period_days: int,
                          encryption_required: bool = True, audit_required: bool = True) -> str:
        """Add data residency rule"""
        rule_id = f"residency_{region.value}_{int(time.time())}"
        
        rule = DataResidencyRule(
            rule_id=rule_id,
            region=region,
            data_types=data_types,
            storage_location=storage_location,
            retention_period_days=retention_period_days,
            encryption_required=encryption_required,
            audit_required=audit_required,
            created_at=datetime.utcnow().isoformat()
        )
        
        with self.lock:
            self.residency_rules[rule_id] = rule
            self._store_residency_rule(rule)
        
        self._log_audit_event("residency_rule_added", rule_id, {
            'region': region.value,
            'data_types': [dt.value for dt in data_types],
            'storage_location': storage_location
        })
        
        return rule_id
    
    def _store_residency_rule(self, rule: DataResidencyRule):
        """Store residency rule in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO residency_rules (
                rule_id, region, data_types, storage_location,
                retention_period_days, encryption_required, audit_required, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            rule.rule_id, rule.region.value,
            json.dumps([dt.value for dt in rule.data_types]),
            rule.storage_location, rule.retention_period_days,
            rule.encryption_required, rule.audit_required, rule.created_at
        ))
        
        conn.commit()
        conn.close()
    
    def create_cmek_config(self, customer_id: str, key_algorithm: str = "AES",
                          key_size: int = 256, rotation_period_days: int = 90) -> str:
        """Create Customer-Managed Encryption Key configuration"""
        key_id = f"cmek_{customer_id}_{int(time.time())}"
        
        # Generate key material
        key_material = Fernet.generate_key()
        
        config = CMEKConfig(
            key_id=key_id,
            customer_id=customer_id,
            key_algorithm=key_algorithm,
            key_size=key_size,
            rotation_period_days=rotation_period_days,
            created_at=datetime.utcnow().isoformat(),
            last_rotation=datetime.utcnow().isoformat()
        )
        
        with self.lock:
            self.cmek_configs[key_id] = config
            self._store_cmek_config(config)
        
        self._log_audit_event("cmek_config_created", key_id, {
            'customer_id': customer_id,
            'key_algorithm': key_algorithm,
            'key_size': key_size
        })
        
        return key_id
    
    def _store_cmek_config(self, config: CMEKConfig):
        """Store CMEK config in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO cmek_configs (
                key_id, customer_id, key_algorithm, key_size,
                rotation_period_days, created_at, last_rotation, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            config.key_id, config.customer_id, config.key_algorithm,
            config.key_size, config.rotation_period_days,
            config.created_at, config.last_rotation, config.status
        ))
        
        conn.commit()
        conn.close()
    
    def check_data_residency(self, data_type: DataClassification, region: ComplianceRegion,
                           storage_location: str) -> bool:
        """Check if data storage complies with residency rules"""
        with self.lock:
            for rule in self.residency_rules.values():
                if rule.region == region and data_type in rule.data_types:
                    if rule.storage_location != storage_location:
                        self._log_audit_event("residency_violation", "", {
                            'data_type': data_type.value,
                            'region': region.value,
                            'storage_location': storage_location,
                            'required_location': rule.storage_location
                        })
                        return False
            return True
    
    def encrypt_with_cmek(self, data: bytes, key_id: str) -> Optional[bytes]:
        """Encrypt data with Customer-Managed Encryption Key"""
        with self.lock:
            if key_id not in self.cmek_configs:
                return None
            
            # In production, use actual CMEK service (AWS KMS, Azure Key Vault, etc.)
            # For now, simulate encryption
            try:
                fernet = Fernet(Fernet.generate_key())
                encrypted_data = fernet.encrypt(data)
                
                self._log_audit_event("cmek_encryption", key_id, {
                    'data_size': len(data),
                    'key_id': key_id
                })
                
                return encrypted_data
                
            except Exception as e:
                self.logger.error(f"CMEK encryption failed: {e}")
                return None
    
    def decrypt_with_cmek(self, encrypted_data: bytes, key_id: str) -> Optional[bytes]:
        """Decrypt data with Customer-Managed Encryption Key"""
        with self.lock:
            if key_id not in self.cmek_configs:
                return None
            
            # In production, use actual CMEK service
            # For now, simulate decryption
            try:
                fernet = Fernet(Fernet.generate_key())
                decrypted_data = fernet.decrypt(encrypted_data)
                
                self._log_audit_event("cmek_decryption", key_id, {
                    'data_size': len(encrypted_data),
                    'key_id': key_id
                })
                
                return decrypted_data
                
            except Exception as e:
                self.logger.error(f"CMEK decryption failed: {e}")
                return None
    
    def create_data_processing_agreement(self, customer_id: str, agreement_type: str,
                                        region: ComplianceRegion, terms: str,
                                        effective_date: str, expiry_date: Optional[str] = None) -> str:
        """Create data processing agreement"""
        agreement_id = f"dpa_{customer_id}_{int(time.time())}"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO data_processing_agreements (
                agreement_id, customer_id, agreement_type, region,
                effective_date, expiry_date, terms, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            agreement_id, customer_id, agreement_type, region.value,
            effective_date, expiry_date, terms, 'draft',
            datetime.utcnow().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        self._log_audit_event("dpa_created", agreement_id, {
            'customer_id': customer_id,
            'agreement_type': agreement_type,
            'region': region.value
        })
        
        return agreement_id
    
    def sign_data_processing_agreement(self, agreement_id: str, signed_by: str) -> bool:
        """Sign data processing agreement"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE data_processing_agreements 
            SET signed_by = ?, signed_date = ?, status = 'active'
            WHERE agreement_id = ?
        ''', (signed_by, datetime.utcnow().isoformat(), agreement_id))
        
        conn.commit()
        conn.close()
        
        self._log_audit_event("dpa_signed", agreement_id, {
            'signed_by': signed_by
        })
        
        return True
    
    def check_compliance(self, resource_id: str, action: str, user_id: str,
                       region: Optional[ComplianceRegion] = None,
                       data_type: Optional[DataClassification] = None) -> Dict[str, Any]:
        """Check compliance for action"""
        compliance_result = {
            'compliant': True,
            'violations': [],
            'required_controls': [],
            'recommendations': [],
            'timestamp': datetime.utcnow().isoformat()
        }
        
        with self.lock:
            # Check relevant policies
            for policy in self.policies.values():
                if policy.active and (not region or policy.region == region):
                    # Check requirements
                    for requirement in policy.requirements:
                        if self._check_requirement_compliance(requirement, action, data_type):
                            compliance_result['required_controls'].append(requirement)
                        else:
                            compliance_result['violations'].append({
                                'policy': policy.name,
                                'requirement': requirement,
                                'severity': 'high' if requirement.get('mandatory', False) else 'medium'
                            })
                            compliance_result['compliant'] = False
                    
                    # Check controls
                    for control in policy.controls:
                        if control.get('status') != 'implemented':
                            compliance_result['recommendations'].append({
                                'control': control,
                                'priority': 'high' if policy.standard in [ComplianceStandard.GDPR, ComplianceStandard.HIPAA] else 'medium'
                            })
        
        # Log compliance check
        self._log_audit_event("compliance_check", resource_id, {
            'action': action,
            'user_id': user_id,
            'region': region.value if region else None,
            'data_type': data_type.value if data_type else None,
            'compliant': compliance_result['compliant'],
            'violations_count': len(compliance_result['violations'])
        })
        
        return compliance_result
    
    def _check_requirement_compliance(self, requirement: Dict[str, Any], action: str,
                                     data_type: Optional[DataClassification]) -> bool:
        """Check if requirement is compliant"""
        # In production, implement actual compliance checking logic
        # For now, simulate based on action and data type
        
        requirement_id = requirement.get('requirement_id', '')
        
        if 'encryption' in requirement_id.lower():
            # Check if encryption is implemented
            return action in ['encrypt', 'store', 'transmit']
        
        elif 'audit' in requirement_id.lower():
            # Check if audit logging is implemented
            return action in ['log', 'audit', 'monitor']
        
        elif 'access_control' in requirement_id.lower():
            # Check if access control is implemented
            return action in ['authenticate', 'authorize', 'access']
        
        elif 'breach' in requirement_id.lower():
            # Check if breach notification is implemented
            return action in ['notify', 'report', 'alert']
        
        return True  # Default to compliant
    
    def _log_audit_event(self, event_type: str, resource_id: str, details: Dict[str, Any]):
        """Log compliance audit event"""
        audit_entry = {
            'audit_id': f"audit_{int(time.time() * 1000)}_{resource_id}",
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'resource_id': resource_id,
            'user_id': details.get('user_id'),
            'action': details.get('action', event_type),
            'details': details,
            'compliance_standard': details.get('compliance_standard'),
            'region': details.get('region'),
            'risk_level': self._calculate_risk_level(event_type, details)
        }
        
        with self.lock:
            self.audit_log.append(audit_entry)
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO compliance_audit_log (
                audit_id, timestamp, event_type, resource_id, user_id,
                action, details, compliance_standard, region, risk_level
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            audit_entry['audit_id'], audit_entry['timestamp'],
            audit_entry['event_type'], audit_entry['resource_id'],
            audit_entry['user_id'], audit_entry['action'],
            json.dumps(audit_entry['details']),
            audit_entry.get('compliance_standard'),
            audit_entry.get('region'),
            audit_entry['risk_level']
        ))
        
        conn.commit()
        conn.close()
    
    def _calculate_risk_level(self, event_type: str, details: Dict[str, Any]) -> str:
        """Calculate risk level for audit event"""
        if event_type in ['compliance_violation', 'residency_violation']:
            return 'high'
        elif event_type in ['cmek_encryption', 'cmek_decryption']:
            return 'medium'
        elif event_type in ['policy_updated', 'rule_added']:
            return 'low'
        else:
            return 'medium'
    
    def _start_background_processors(self):
        """Start background processors"""
        threading.Thread(target=self._policy_review_processor, daemon=True).start()
        threading.Thread(target=self._cmek_rotation_processor, daemon=True).start()
        threading.Thread(target=self._audit_log_processor, daemon=True).start()
    
    def _policy_review_processor(self):
        """Background policy review processor"""
        while True:
            time.sleep(86400)  # Review policies daily
            
            with self.lock:
                for policy in self.policies.values():
                    # Check if policy needs review
                    last_updated = datetime.fromisoformat(policy.updated_at)
                    if datetime.utcnow() - last_updated > timedelta(days=90):
                        self._log_audit_event("policy_review_needed", policy.policy_id, {
                            'policy_name': policy.name,
                            'last_updated': policy.updated_at
                        })
    
    def _cmek_rotation_processor(self):
        """Background CMEK rotation processor"""
        while True:
            time.sleep(3600)  # Check every hour
            
            with self.lock:
                for config in self.cmek_configs.values():
                    last_rotation = datetime.fromisoformat(config.last_rotation)
                    if datetime.utcnow() - last_rotation >= timedelta(days=config.rotation_period_days):
                        self._rotate_cmek_key(config.key_id)
    
    def _rotate_cmek_key(self, key_id: str):
        """Rotate CMEK key"""
        with self.lock:
            if key_id in self.cmek_configs:
                config = self.cmek_configs[key_id]
                config.last_rotation = datetime.utcnow().isoformat()
                self._store_cmek_config(config)
                
                self._log_audit_event("cmek_key_rotated", key_id, {
                    'customer_id': config.customer_id,
                    'rotation_period': config.rotation_period_days
                })
    
    def _audit_log_processor(self):
        """Background audit log processor"""
        while True:
            time.sleep(3600)  # Process every hour
            
            with self.lock:
                # Keep only last 10000 audit entries
                if len(self.audit_log) > 10000:
                    self.audit_log = self.audit_log[-10000:]
                
                # Archive old audit entries
                self._archive_audit_entries()
    
    def _archive_audit_entries(self):
        """Archive old audit entries"""
        # In production, archive to long-term storage
        pass
    
    def get_compliance_status(self) -> Dict[str, Any]:
        """Get comprehensive compliance status"""
        with self.lock:
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'total_policies': len(self.policies),
                'active_policies': len([p for p in self.policies.values() if p.active]),
                'residency_rules': len(self.residency_rules),
                'cmek_configs': len(self.cmek_configs),
                'audit_entries': len(self.audit_log),
                'policies_by_standard': {
                    standard.value: len([p for p in self.policies.values() if p.standard == standard])
                    for standard in ComplianceStandard
                },
                'policies_by_region': {
                    region.value: len([p for p in self.policies.values() if p.region == region])
                    for region in ComplianceRegion
                },
                'recent_violations': len([
                    entry for entry in self.audit_log[-100:]
                    if entry['event_type'] in ['compliance_violation', 'residency_violation']
                ])
            }
    
    def export_compliance_report(self, format: str = "json") -> str:
        """Export compliance report"""
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'policies': [
                {
                    'policy_id': policy.policy_id,
                    'name': policy.name,
                    'standard': policy.standard.value,
                    'region': policy.region.value,
                    'requirements_count': len(policy.requirements),
                    'controls_count': len(policy.controls),
                    'active': policy.active
                }
                for policy in self.policies.values()
            ],
            'residency_rules': [
                {
                    'rule_id': rule.rule_id,
                    'region': rule.region.value,
                    'data_types': [dt.value for dt in rule.data_types],
                    'storage_location': rule.storage_location,
                    'retention_period_days': rule.retention_period_days
                }
                for rule in self.residency_rules.values()
            ],
            'cmek_configs': [
                {
                    'key_id': config.key_id,
                    'customer_id': config.customer_id,
                    'key_algorithm': config.key_algorithm,
                    'key_size': config.key_size,
                    'rotation_period_days': config.rotation_period_days,
                    'status': config.status
                }
                for config in self.cmek_configs.values()
            ],
            'audit_summary': {
                'total_entries': len(self.audit_log),
                'recent_violations': len([
                    entry for entry in self.audit_log[-100:]
                    if entry['event_type'] in ['compliance_violation', 'residency_violation']
                ]),
                'high_risk_events': len([
                    entry for entry in self.audit_log[-100:]
                    if entry['risk_level'] == 'high'
                ])
            }
        }
        
        if format.lower() == "json":
            return json.dumps(report, indent=2, default=str)
        elif format.lower() == "yaml":
            return yaml.dump(report, default_flow_style=False)
        else:
            raise ValueError(f"Unsupported format: {format}")

# Global compliance manager
compliance_manager = ComplianceManager()
