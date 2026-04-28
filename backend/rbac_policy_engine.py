"""
🔐 Firewall Guard - Enterprise RBAC & Policy Engine
Granular role-based access control with policy-as-code system
"""

import json
import yaml
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from enum import Enum
from dataclasses import dataclass
import threading
from pathlib import Path

class Permission(Enum):
    # Read permissions
    READ_EVENTS = "read_events"
    READ_POLICIES = "read_policies"
    READ_USERS = "read_users"
    READ_TENANTS = "read_tenants"
    READ_AUDIT_LOGS = "read_audit_logs"
    READ_METRICS = "read_metrics"
    
    # Write permissions
    WRITE_EVENTS = "write_events"
    WRITE_POLICIES = "write_policies"
    WRITE_USERS = "write_users"
    
    # Action permissions
    INVESTIGATE_INCIDENTS = "investigate_incidents"
    CONTAIN_THREATS = "contain_threats"
    RESPOND_ALERTS = "respond_alerts"
    CHANGE_POLICIES = "change_policies"
    APPROVE_POLICIES = "approve_policies"
    
    # Admin permissions
    MANAGE_TENANTS = "manage_tenants"
    MANAGE_USERS = "manage_users"
    MANAGE_ROLES = "manage_roles"
    SYSTEM_ADMIN = "system_admin"

class Role(Enum):
    SOC_ANALYST = "soc_analyst"
    SOC_TIER_2 = "soc_tier_2"
    ADMIN = "admin"
    AUDITOR = "auditor"
    TENANT_ADMIN = "tenant_admin"

@dataclass
class User:
    """Enterprise user with granular permissions"""
    user_id: str
    username: str
    email: str
    role: Role
    tenant_id: str
    permissions: Set[Permission]
    created_at: str
    last_login: Optional[str] = None
    active: bool = True
    mfa_enabled: bool = False

@dataclass
class Policy:
    """Policy-as-code definition"""
    policy_id: str
    name: str
    description: str
    version: str
    status: str  # draft, pending_approval, active, deprecated
    created_by: str
    created_at: str
    tenant_id: str = "default"
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    rules: List[Dict[str, Any]] = None
    conditions: List[Dict[str, Any]] = None
    actions: List[Dict[str, Any]] = None

class PolicyEngine:
    """Enterprise policy engine with approval workflow"""
    
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.policies: Dict[str, Policy] = {}
        self.role_permissions = self._init_role_permissions()
        self.approval_queue: List[str] = []
        self.audit_log: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
        
        # Initialize default policies
        self._init_default_policies()
    
    def _init_role_permissions(self) -> Dict[Role, Set[Permission]]:
        """Define granular permissions for each role"""
        return {
            Role.SOC_ANALYST: {
                Permission.READ_EVENTS,
                Permission.READ_POLICIES,
                Permission.READ_USERS,
                Permission.READ_TENANTS,
                Permission.READ_AUDIT_LOGS,
                Permission.READ_METRICS,
                Permission.INVESTIGATE_INCIDENTS
            },
            
            Role.SOC_TIER_2: {
                Permission.READ_EVENTS,
                Permission.READ_POLICIES,
                Permission.READ_USERS,
                Permission.READ_TENANTS,
                Permission.READ_AUDIT_LOGS,
                Permission.READ_METRICS,
                Permission.INVESTIGATE_INCIDENTS,
                Permission.CONTAIN_THREATS,
                Permission.RESPOND_ALERTS
            },
            
            Role.ADMIN: {
                Permission.READ_EVENTS,
                Permission.READ_POLICIES,
                Permission.READ_USERS,
                Permission.READ_TENANTS,
                Permission.READ_AUDIT_LOGS,
                Permission.READ_METRICS,
                Permission.WRITE_EVENTS,
                Permission.WRITE_POLICIES,
                Permission.WRITE_USERS,
                Permission.INVESTIGATE_INCIDENTS,
                Permission.CONTAIN_THREATS,
                Permission.RESPOND_ALERTS,
                Permission.CHANGE_POLICIES,
                Permission.MANAGE_TENANTS,
                Permission.MANAGE_USERS,
                Permission.MANAGE_ROLES
            },
            
            Role.AUDITOR: {
                Permission.READ_EVENTS,
                Permission.READ_POLICIES,
                Permission.READ_USERS,
                Permission.READ_TENANTS,
                Permission.READ_AUDIT_LOGS,
                Permission.READ_METRICS
            },
            
            Role.TENANT_ADMIN: {
                Permission.READ_EVENTS,
                Permission.READ_POLICIES,
                Permission.READ_USERS,
                Permission.WRITE_EVENTS,
                Permission.WRITE_POLICIES,
                Permission.WRITE_USERS,
                Permission.INVESTIGATE_INCIDENTS,
                Permission.CONTAIN_THREATS,
                Permission.RESPOND_ALERTS,
                Permission.CHANGE_POLICIES,
                Permission.MANAGE_USERS
            }
        }
    
    def _init_default_policies(self):
        """Initialize default security policies"""
        default_policies = [
            {
                "policy_id": "default_threat_blocking",
                "name": "Default Threat Blocking Policy",
                "description": "Automatically block high-risk threats",
                "version": "1.0.0",
                "status": "active",
                "created_by": "system",
                "created_at": datetime.utcnow().isoformat(),
                "rules": [
                    {
                        "condition": "risk_level == 'CRITICAL'",
                        "action": "block",
                        "confidence_threshold": 0.9
                    },
                    {
                        "condition": "risk_level == 'HIGH' and confidence >= 0.85",
                        "action": "block",
                        "confidence_threshold": 0.85
                    }
                ]
            },
            {
                "policy_id": "default_data_retention",
                "name": "Default Data Retention Policy",
                "description": "Data retention and lifecycle management",
                "version": "1.0.0",
                "status": "active",
                "created_by": "system",
                "created_at": datetime.utcnow().isoformat(),
                "rules": [
                    {
                        "condition": "event_age_days > 365",
                        "action": "archive",
                        "data_type": "all"
                    },
                    {
                        "condition": "event_age_days > 90 and severity == 'LOW'",
                        "action": "delete",
                        "data_type": "events"
                    }
                ]
            }
        ]
        
        for policy_data in default_policies:
            policy = Policy(
                policy_id=policy_data["policy_id"],
                name=policy_data["name"],
                description=policy_data["description"],
                version=policy_data["version"],
                status=policy_data["status"],
                created_by=policy_data["created_by"],
                created_at=policy_data["created_at"],
                tenant_id=policy_data.get("tenant_id", "default"),
                rules=policy_data.get("rules", []),
                conditions=policy_data.get("conditions", []),
                actions=policy_data.get("actions", [])
            )
            self.policies[policy.policy_id] = policy
    
    def create_user(self, username: str, email: str, role: Role, tenant_id: str) -> User:
        """Create new user with role-based permissions"""
        user_id = str(int(time.time() * 1000)) + "_" + hashlib.md5(username.encode()).hexdigest()[:8]
        
        user = User(
            user_id=user_id,
            username=username,
            email=email,
            role=role,
            tenant_id=tenant_id,
            permissions=self.role_permissions[role],
            created_at=datetime.utcnow().isoformat()
        )
        
        with self.lock:
            self.users[user_id] = user
            self._log_audit_event("user_created", user_id, {
                "username": username,
                "role": role.value,
                "tenant_id": tenant_id
            })
        
        return user
    
    def authenticate_user(self, username: str, password: str, tenant_id: str) -> Optional[User]:
        """Authenticate user and return user object"""
        # In production, integrate with enterprise auth system
        with self.lock:
            for user in self.users.values():
                if user.username == username and user.tenant_id == tenant_id and user.active:
                    user.last_login = datetime.utcnow().isoformat()
                    self._log_audit_event("user_authenticated", user.user_id, {
                        "username": username,
                        "tenant_id": tenant_id
                    })
                    return user
        return None
    
    def check_permission(self, user: User, permission: Permission) -> bool:
        """Check if user has specific permission"""
        return permission in user.permissions
    
    def check_policy_permission(self, user: User, policy_id: str, action: str) -> bool:
        """Check if user can perform action on policy"""
        if action == "read":
            return Permission.READ_POLICIES in user.permissions
        elif action == "write":
            return Permission.WRITE_POLICIES in user.permissions
        elif action == "change":
            return Permission.CHANGE_POLICIES in user.permissions
        elif action == "approve":
            return Permission.APPROVE_POLICIES in user.permissions
        return False
    
    def create_policy(self, user: User, policy_data: Dict[str, Any]) -> Policy:
        """Create new policy (requires write permissions)"""
        policy = Policy(
            policy_id=policy_data["policy_id"],
            name=policy_data["name"],
            description=policy_data["description"],
            version=policy_data["version"],
            status=policy_data["status"],
            created_by=policy_data["created_by"],
            created_at=policy_data["created_at"],
            tenant_id=policy_data.get("tenant_id", "default"),
            rules=policy_data.get("rules", []),
            conditions=policy_data.get("conditions", []),
            actions=policy_data.get("actions", [])
        )
        self.policies[policy.policy_id] = policy
        with self.lock:
            self.policies[policy_id] = policy
            self._log_audit_event("policy_created", policy_id, {
                "name": policy.name,
                "created_by": user.user_id,
                "status": "draft"
            })
        
        return policy
    
    def submit_policy_for_approval(self, user: User, policy_id: str) -> bool:
        """Submit policy for approval"""
        policy = self.policies.get(policy_id)
        if not policy:
            return False
        
        if policy.created_by != user.user_id:
            return False
        
        if policy.status != "draft":
            return False
        
        with self.lock:
            policy.status = "pending_approval"
            self.approval_queue.append(policy_id)
            self._log_audit_event("policy_submitted_for_approval", policy_id, {
                "submitted_by": user.user_id,
                "policy_name": policy.name
            })
        
        return True
    
    def approve_policy(self, user: User, policy_id: str) -> bool:
        """Approve policy (requires approve permissions)"""
        if not self.check_policy_permission(user, "approve"):
            raise PermissionError("User does not have policy approval permissions")
        
        policy = self.policies.get(policy_id)
        if not policy or policy.status != "pending_approval":
            return False
        
        with self.lock:
            policy.status = "active"
            policy.approved_by = user.user_id
            policy.approved_at = datetime.utcnow().isoformat()
            
            if policy_id in self.approval_queue:
                self.approval_queue.remove(policy_id)
            
            self._log_audit_event("policy_approved", policy_id, {
                "approved_by": user.user_id,
                "policy_name": policy.name
            })
        
        return True
    
    def evaluate_policy(self, policy_id: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate policy against context"""
        policy = self.policies.get(policy_id)
        if not policy or policy.status != "active":
            return []
        
        results = []
        
        for rule in policy.rules or []:
            if self._evaluate_rule(rule, context):
                results.append({
                    "policy_id": policy_id,
                    "policy_name": policy.name,
                    "rule": rule,
                    "action": rule.get("action"),
                    "matched": True,
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        return results
    
    def _evaluate_rule(self, rule: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Evaluate individual rule condition"""
        condition = rule.get("condition", "")
        
        # Simple condition evaluation (in production, use proper expression parser)
        if "risk_level" in condition:
            risk_level = context.get("risk_level", "")
            expected_risk = condition.split("==")[1].strip().strip('"\'')
            return risk_level == expected_risk
        
        if "confidence" in condition:
            confidence = context.get("confidence", 0)
            if ">=" in condition:
                threshold = float(condition.split(">=")[1].strip())
                return confidence >= threshold
        
        return False
    
    def get_user_policies(self, user: User) -> List[Policy]:
        """Get policies user can access"""
        if not self.check_permission(user, Permission.READ_POLICIES):
            return []
        
        return [policy for policy in self.policies.values() 
                if policy.status in ["active", "pending_approval"]]
                and (policy.tenant_id == user.tenant_id or user.role == Role.ADMIN)]
    
    def get_approval_queue(self, user: User) -> List[Policy]:
        """Get policies awaiting approval"""
        if not self.check_permission(user, Permission.APPROVE_POLICIES):
            return []
        
        return [self.policies[policy_id] for policy_id in self.approval_queue 
                if policy_id in self.policies]
    
    def _log_audit_event(self, event_type: str, resource_id: str, details: Dict[str, Any]):
        """Log audit event for compliance"""
        audit_entry = {
            "event_id": f"audit_{int(time.time() * 1000)}",
            "event_type": event_type,
            "resource_id": resource_id,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details
        }
        
        self.audit_log.append(audit_entry)
        
        # Keep only last 10000 audit entries
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-10000:]
    
    def get_audit_log(self, user: User, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Get audit log (requires read permissions)"""
        if not self.check_permission(user, Permission.READ_AUDIT_LOGS):
            return []
        
        filtered_log = self.audit_log
        
        if filters:
            if "event_type" in filters:
                filtered_log = [entry for entry in filtered_log 
                              if entry["event_type"] == filters["event_type"]]
            
            if "resource_id" in filters:
                filtered_log = [entry for entry in filtered_log 
                              if entry["resource_id"] == filters["resource_id"]]
            
            if "start_date" in filters:
                start_date = datetime.fromisoformat(filters["start_date"])
                filtered_log = [entry for entry in filtered_log 
                              if datetime.fromisoformat(entry["timestamp"]) >= start_date]
            
            if "end_date" in filters:
                end_date = datetime.fromisoformat(filters["end_date"])
                filtered_log = [entry for entry in filtered_log 
                              if datetime.fromisoformat(entry["timestamp"]) <= end_date]
        
        # Tenant isolation
        if user.role != Role.ADMIN:
            filtered_log = [entry for entry in filtered_log 
                          if entry.get("details", {}).get("tenant_id") == user.tenant_id]
        
        return filtered_log
    
    def export_policies(self, user: User, format: str = "yaml") -> str:
        """Export policies in specified format"""
        if not self.check_permission(user, Permission.READ_POLICIES):
            raise PermissionError("User does not have policy read permissions")
        
        policies_data = []
        for policy in self.get_user_policies(user):
            policy_dict = {
                "policy_id": policy.policy_id,
                "name": policy.name,
                "description": policy.description,
                "version": policy.version,
                "status": policy.status,
                "created_by": policy.created_by,
                "created_at": policy.created_at,
                "rules": policy.rules,
                "conditions": policy.conditions,
                "actions": policy.actions
            }
            
            if policy.approved_by:
                policy_dict["approved_by"] = policy.approved_by
                policy_dict["approved_at"] = policy.approved_at
            
            policies_data.append(policy_dict)
        
        if format.lower() == "yaml":
            return yaml.dump({"policies": policies_data}, default_flow_style=False)
        else:
            return json.dumps({"policies": policies_data}, indent=2)
    
    def import_policies(self, user: User, policies_data: str, format: str = "yaml") -> int:
        """Import policies from exported data"""
        if not self.check_permission(user, Permission.WRITE_POLICIES):
            raise PermissionError("User does not have policy write permissions")
        
        try:
            if format.lower() == "yaml":
                data = yaml.safe_load(policies_data)
            else:
                data = json.loads(policies_data)
            
            imported_count = 0
            for policy_data in data.get("policies", []):
                # Check if policy already exists
                existing_policy = self.policies.get(policy_data.get("policy_id"))
                if existing_policy:
                    continue  # Skip existing policies
                
                policy = Policy(
                    policy_id=policy_data["policy_id"],
                    name=policy_data["name"],
                    description=policy_data["description"],
                    version=policy_data["version"],
                    status="draft",
                    created_by=user.user_id,
                    created_at=datetime.utcnow().isoformat(),
                    rules=policy_data.get("rules", []),
                    conditions=policy_data.get("conditions", []),
                    actions=policy_data.get("actions", [])
                )
                
                with self.lock:
                    self.policies[policy.policy_id] = policy
                    imported_count += 1
                    self._log_audit_event("policy_imported", policy.policy_id, {
                        "name": policy.name,
                        "imported_by": user.user_id
                    })
            
            return imported_count
            
        except Exception as e:
            raise ValueError(f"Failed to import policies: {str(e)}")

# Global policy engine instance
policy_engine = PolicyEngine()
