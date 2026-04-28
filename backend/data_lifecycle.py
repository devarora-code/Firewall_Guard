"""
📊 Firewall Guard - Event Schema & Data Lifecycle Management
Standardized event schema, retention policies, and enterprise data governance
"""

import json
import time
import hashlib
import sqlite3
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum
import threading
from pathlib import Path
import gzip
import shutil

MODULE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = MODULE_DIR / "firewall_events.db"
DEFAULT_STORAGE_BASE_PATH = MODULE_DIR / "data_storage"
SEARCH_CONTENT_POLICY_FILE = MODULE_DIR / "search_content_policy.json"

class EventSeverity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class EventType(Enum):
    SECURITY_EVENT = "security_event"
    AI_ANALYSIS = "ai_analysis"
    SYSTEM_EVENT = "system_event"
    USER_ACTION = "user_action"
    PERFORMANCE = "performance"
    ERROR = "error"
    AUDIT = "audit"

class StorageTier(Enum):
    HOT = "hot"      # 7 days, real-time access
    WARM = "warm"    # 90 days, frequent access
    COLD = "cold"    # 365 days, archival access
    LEGAL_HOLD = "legal_hold"  # Permanent, legal hold

@dataclass
class StandardEvent:
    """Standardized enterprise event schema"""
    # Core fields
    event_id: str
    tenant_id: str
    source: str
    event_type: str
    timestamp: str
    severity: str
    confidence: float
    
    # Context fields
    correlation_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    tags: Optional[List[str]] = None
    
    # Data fields
    raw_data: Optional[Dict[str, Any]] = None
    processed_data: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    
    # Governance fields
    data_classification: str = "internal"
    retention_policy: str = "standard"
    legal_hold: bool = False
    compliance_flags: Optional[List[str]] = None
    
    # System fields
    storage_tier: str = StorageTier.HOT.value
    created_at: str = ""
    updated_at: str = ""
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StandardEvent':
        return cls(**data)


DEFAULT_SEARCH_CONTENT_POLICY = {
    "version": 1,
    "updated_at": datetime.utcnow().isoformat(),
    "blocked_content_patterns": [
        {
            "id": "captcha-challenge",
            "pattern": "captcha",
            "reason": "Challenge page content should be blocked from search results.",
            "enabled": True
        },
        {
            "id": "access-denied",
            "pattern": "access denied",
            "reason": "Access denied pages should be blocked from search content.",
            "enabled": True
        },
        {
            "id": "forbidden-403",
            "pattern": "403 forbidden",
            "reason": "Forbidden content should be blocked from search content.",
            "enabled": True
        }
    ],
    "delayed_content_patterns": [
        {
            "id": "just-a-moment",
            "pattern": "just a moment",
            "delay_ms": 2000,
            "reason": "Interstitial challenge pages should incur a small verification delay.",
            "enabled": True
        },
        {
            "id": "checking-your-browser",
            "pattern": "checking your browser",
            "delay_ms": 2000,
            "reason": "Browser verification pages should incur a small verification delay.",
            "enabled": True
        },
        {
            "id": "please-wait",
            "pattern": "please wait",
            "delay_ms": 1500,
            "reason": "Wait screens should incur a small verification delay.",
            "enabled": True
        }
    ]
}


def _parse_int(value, fallback=0):
    try:
        if isinstance(value, bool):
            return fallback
        if isinstance(value, (int, float)):
            return int(value)
        text = str(value or "").strip()
        if not text:
            return fallback
        return int(float(text))
    except (TypeError, ValueError):
        return fallback


def _normalize_content_rule(rule, *, delay_rule=False):
    source = rule if isinstance(rule, dict) else {}
    pattern = str(source.get("pattern") or "").strip()
    if not pattern:
        return None

    normalized = {
        "id": str(source.get("id") or hashlib.sha1(pattern.encode("utf-8")).hexdigest()[:12]).strip(),
        "pattern": pattern,
        "reason": str(
            source.get("reason")
            or ("Search content delay match" if delay_rule else "Search content block match")
        ).strip(),
        "enabled": source.get("enabled", True) is not False
    }

    if delay_rule:
        normalized["delay_ms"] = max(0, _parse_int(source.get("delay_ms", source.get("delayMs", 0)), 0))

    return normalized


def normalize_search_content_policy(raw_policy, *, source_path: Optional[Path] = None) -> Dict[str, Any]:
    source = raw_policy if isinstance(raw_policy, dict) else {}
    source_stat = source_path.stat() if source_path and source_path.exists() else None
    updated_at = source.get("updated_at")

    if not updated_at and source_stat:
        updated_at = datetime.fromtimestamp(source_stat.st_mtime).isoformat()
    if not updated_at:
        updated_at = datetime.utcnow().isoformat()

    blocked_rules = []
    seen_block_rules = set()
    for rule in source.get("blocked_content_patterns", DEFAULT_SEARCH_CONTENT_POLICY["blocked_content_patterns"]):
        normalized = _normalize_content_rule(rule, delay_rule=False)
        if not normalized:
            continue
        rule_key = normalized["id"].lower()
        if rule_key in seen_block_rules:
            continue
        seen_block_rules.add(rule_key)
        blocked_rules.append(normalized)

    delayed_rules = []
    seen_delay_rules = set()
    for rule in source.get("delayed_content_patterns", DEFAULT_SEARCH_CONTENT_POLICY["delayed_content_patterns"]):
        normalized = _normalize_content_rule(rule, delay_rule=True)
        if not normalized:
            continue
        rule_key = normalized["id"].lower()
        if rule_key in seen_delay_rules:
            continue
        seen_delay_rules.add(rule_key)
        delayed_rules.append(normalized)

    version = _parse_int(source.get("version"), DEFAULT_SEARCH_CONTENT_POLICY["version"])
    if source_stat:
        version = max(version, int(source_stat.st_mtime))

    return {
        "version": version,
        "updated_at": updated_at,
        "blocked_content_patterns": blocked_rules,
        "delayed_content_patterns": delayed_rules
    }


def save_search_content_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    normalized = normalize_search_content_policy(policy)
    SEARCH_CONTENT_POLICY_FILE.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
    return normalize_search_content_policy(normalized, source_path=SEARCH_CONTENT_POLICY_FILE)


def load_search_content_policy() -> Dict[str, Any]:
    if SEARCH_CONTENT_POLICY_FILE.exists():
        try:
            raw_policy = json.loads(SEARCH_CONTENT_POLICY_FILE.read_text(encoding="utf-8"))
            return normalize_search_content_policy(raw_policy, source_path=SEARCH_CONTENT_POLICY_FILE)
        except Exception:
            pass

    return save_search_content_policy(DEFAULT_SEARCH_CONTENT_POLICY)


def _content_pattern_matches(content: str, pattern: str) -> bool:
    candidate = str(pattern or "").strip()
    if not candidate:
        return False

    text = str(content or "")
    if candidate.lower().startswith("regex:"):
        try:
            return re.search(candidate.split(":", 1)[1].strip(), text, re.IGNORECASE) is not None
        except re.error:
            return False

    return candidate.lower() in text.lower()


def evaluate_search_content_policy(content: str, *, url: str = "", policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    current_policy = normalize_search_content_policy(policy or load_search_content_policy())
    text = str(content or "")

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
        "policy_version": current_policy.get("version"),
        "content_length": len(text)
    }

    if not text.strip():
        return summary

    for rule in current_policy.get("blocked_content_patterns", []):
        if not rule.get("enabled", True):
            continue
        if _content_pattern_matches(text, rule.get("pattern", "")):
            summary.update({
                "blocked": True,
                "block_rule": rule.get("id", ""),
                "block_pattern": rule.get("pattern", ""),
                "block_reason": rule.get("reason", "")
            })
            return summary

    best_delay_rule = None
    for rule in current_policy.get("delayed_content_patterns", []):
        if not rule.get("enabled", True):
            continue
        if not _content_pattern_matches(text, rule.get("pattern", "")):
            continue
        if best_delay_rule is None or int(rule.get("delay_ms", 0)) >= int(best_delay_rule.get("delay_ms", 0)):
            best_delay_rule = rule

    if best_delay_rule:
        summary.update({
            "delay_ms": int(best_delay_rule.get("delay_ms", 0)),
            "delay_rule": best_delay_rule.get("id", ""),
            "delay_pattern": best_delay_rule.get("pattern", ""),
            "delay_reason": best_delay_rule.get("reason", "")
        })

    return summary

class DataLifecycleManager:
    """Enterprise data lifecycle and retention management"""
    
    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        db_candidate = Path(db_path) if db_path else DEFAULT_DB_PATH
        if not db_candidate.is_absolute():
            db_candidate = MODULE_DIR / db_candidate
        self.db_path = str(db_candidate)
        self.storage_paths = self._init_storage_paths()
        self.retention_policies = self._init_retention_policies()
        self.lock = threading.Lock()
        
        # Initialize database
        self._init_database()
        
        # Start background processors
        self._start_background_processors()
    
    def _init_storage_paths(self) -> Dict[str, Path]:
        """Initialize storage paths for different tiers"""
        base_path = DEFAULT_STORAGE_BASE_PATH
        base_path.mkdir(exist_ok=True)
        
        return {
            StorageTier.HOT.value: base_path / "hot",
            StorageTier.WARM.value: base_path / "warm", 
            StorageTier.COLD.value: base_path / "cold",
            StorageTier.LEGAL_HOLD.value: base_path / "legal_hold"
        }
    
    def _init_retention_policies(self) -> Dict[str, Dict[str, Any]]:
        """Define retention policies by data classification"""
        return {
            "standard": {
                StorageTier.HOT.value: {"duration_days": 7, "max_events": 10000},
                StorageTier.WARM.value: {"duration_days": 90, "max_events": 100000},
                StorageTier.COLD.value: {"duration_days": 365, "max_events": 1000000},
                StorageTier.LEGAL_HOLD.value: {"duration_days": -1, "max_events": -1}
            },
            "sensitive": {
                StorageTier.HOT.value: {"duration_days": 30, "max_events": 5000},
                StorageTier.WARM.value: {"duration_days": 180, "max_events": 50000},
                StorageTier.COLD.value: {"duration_days": 2555, "max_events": 500000},
                StorageTier.LEGAL_HOLD.value: {"duration_days": -1, "max_events": -1}
            },
            "critical": {
                StorageTier.HOT.value: {"duration_days": 90, "max_events": 2000},
                StorageTier.WARM.value: {"duration_days": 365, "max_events": 20000},
                StorageTier.COLD.value: {"duration_days": -1, "max_events": 200000},
                StorageTier.LEGAL_HOLD.value: {"duration_days": -1, "max_events": -1}
            }
        }
    
    def _init_database(self):
        """Initialize SQLite database for event metadata"""
        # Create storage directories
        for path in self.storage_paths.values():
            path.mkdir(exist_ok=True)
        
        # Initialize database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                correlation_id TEXT,
                user_id TEXT,
                session_id TEXT,
                tags TEXT,
                raw_data TEXT,
                processed_data TEXT,
                metadata TEXT,
                data_classification TEXT DEFAULT 'internal',
                retention_policy TEXT DEFAULT 'standard',
                legal_hold BOOLEAN DEFAULT 0,
                compliance_flags TEXT,
                storage_tier TEXT DEFAULT 'hot',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                file_path TEXT,
                compressed BOOLEAN DEFAULT 0,
                INDEX(tenant_id, timestamp),
                INDEX(event_type, severity),
                INDEX(storage_tier, created_at),
                INDEX(legal_hold)
            )
        ''')
        
        # Create retention policies table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS retention_policies (
                policy_name TEXT PRIMARY KEY,
                data_classification TEXT,
                storage_tier TEXT,
                duration_days INTEGER,
                max_events INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')
        
        # Create legal holds table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS legal_holds (
                hold_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                active BOOLEAN DEFAULT 1,
                FOREIGN KEY (event_id) REFERENCES events (event_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _start_background_processors(self):
        """Start background processors for data lifecycle"""
        threading.Thread(target=self._retention_processor, daemon=True).start()
        threading.Thread(target=self._storage_tier_migration, daemon=True).start()
        threading.Thread(target=self._compression_processor, daemon=True).start()
        threading.Thread(target=self._legal_hold_processor, daemon=True).start()
    
    def store_event(self, event: StandardEvent) -> str:
        """Store event with proper lifecycle management"""
        # Validate event schema
        self._validate_event(event)
        
        # Determine initial storage tier
        event.storage_tier = self._determine_storage_tier(event)
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO events (
                    event_id, tenant_id, source, event_type, timestamp, severity,
                    confidence, correlation_id, user_id, session_id, tags,
                    raw_data, processed_data, metadata, data_classification,
                    retention_policy, legal_hold, compliance_flags, storage_tier,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.event_id, event.tenant_id, event.source, event.event_type,
                event.timestamp, event.severity, event.confidence,
                event.correlation_id, event.user_id, event.session_id,
                json.dumps(event.tags) if event.tags else None,
                json.dumps(event.raw_data) if event.raw_data else None,
                json.dumps(event.processed_data) if event.processed_data else None,
                json.dumps(event.metadata) if event.metadata else None,
                event.data_classification, event.retention_policy,
                event.legal_hold, json.dumps(event.compliance_flags) if event.compliance_flags else None,
                event.storage_tier, event.created_at, event.updated_at
            ))
            
            # Store in appropriate file storage
            file_path = self._store_in_file(event)
            
            # Update database with file path
            cursor.execute('UPDATE events SET file_path = ? WHERE event_id = ?',
                           (file_path, event.event_id))
            
            conn.commit()
            
            return event.event_id
            
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def _validate_event(self, event: StandardEvent):
        """Validate event schema compliance"""
        required_fields = ['event_id', 'tenant_id', 'source', 'event_type', 'timestamp', 'severity', 'confidence']
        
        for field in required_fields:
            if not getattr(event, field, None):
                raise ValueError(f"Missing required field: {field}")
        
        # Validate severity
        if event.severity not in [s.value for s in EventSeverity]:
            raise ValueError(f"Invalid severity: {event.severity}")
        
        # Validate confidence
        if not 0 <= event.confidence <= 1:
            raise ValueError(f"Confidence must be between 0 and 1: {event.confidence}")
        
        # Validate timestamp
        try:
            datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
        except ValueError:
            raise ValueError(f"Invalid timestamp format: {event.timestamp}")
    
    def _determine_storage_tier(self, event: StandardEvent) -> str:
        """Determine initial storage tier based on event properties"""
        if event.legal_hold:
            return StorageTier.LEGAL_HOLD.value
        
        if event.severity == EventSeverity.CRITICAL.value:
            return StorageTier.HOT.value
        
        if event.severity in [EventSeverity.HIGH.value, EventSeverity.MEDIUM.value]:
            return StorageTier.WARM.value
        
        return StorageTier.HOT.value
    
    def _store_in_file(self, event: StandardEvent) -> str:
        """Store event in appropriate file storage"""
        storage_path = self.storage_paths[event.storage_tier]
        
        # Create subdirectories by date and tenant
        date_str = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00')).strftime('%Y/%m/%d')
        tenant_dir = storage_path / event.tenant_id / date_str
        tenant_dir.mkdir(parents=True, exist_ok=True)
        
        # Create file path
        file_path = tenant_dir / f"{event.event_id}.json"
        
        # Store event as JSON
        with open(file_path, 'w') as f:
            f.write(event.to_json())
        
        return str(file_path)
    
    def retrieve_event(self, event_id: str) -> Optional[StandardEvent]:
        """Retrieve event by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT * FROM events WHERE event_id = ?
            ''', (event_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            # Convert row to event object
            event_data = {
                'event_id': row[0],
                'tenant_id': row[1],
                'source': row[2],
                'event_type': row[3],
                'timestamp': row[4],
                'severity': row[5],
                'confidence': row[6],
                'correlation_id': row[7],
                'user_id': row[8],
                'session_id': row[9],
                'tags': json.loads(row[10]) if row[10] else None,
                'raw_data': json.loads(row[11]) if row[11] else None,
                'processed_data': json.loads(row[12]) if row[12] else None,
                'metadata': json.loads(row[13]) if row[13] else None,
                'data_classification': row[14],
                'retention_policy': row[15],
                'legal_hold': bool(row[16]),
                'compliance_flags': json.loads(row[17]) if row[17] else None,
                'storage_tier': row[18],
                'created_at': row[19],
                'updated_at': row[20]
            }
            
            return StandardEvent.from_dict(event_data)
            
        finally:
            conn.close()
    
    def query_events(self, filters: Dict[str, Any], limit: int = 1000) -> List[StandardEvent]:
        """Query events with filters"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Build query
            query = "SELECT * FROM events WHERE 1=1"
            params = []
            
            if 'tenant_id' in filters:
                query += " AND tenant_id = ?"
                params.append(filters['tenant_id'])
            
            if 'event_type' in filters:
                query += " AND event_type = ?"
                params.append(filters['event_type'])
            
            if 'severity' in filters:
                query += " AND severity = ?"
                params.append(filters['severity'])
            
            if 'start_time' in filters:
                query += " AND timestamp >= ?"
                params.append(filters['start_time'])
            
            if 'end_time' in filters:
                query += " AND timestamp <= ?"
                params.append(filters['end_time'])
            
            if 'storage_tier' in filters:
                query += " AND storage_tier = ?"
                params.append(filters['storage_tier'])
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            events = []
            for row in rows:
                event_data = {
                    'event_id': row[0],
                    'tenant_id': row[1],
                    'source': row[2],
                    'event_type': row[3],
                    'timestamp': row[4],
                    'severity': row[5],
                    'confidence': row[6],
                    'correlation_id': row[7],
                    'user_id': row[8],
                    'session_id': row[9],
                    'tags': json.loads(row[10]) if row[10] else None,
                    'raw_data': json.loads(row[11]) if row[11] else None,
                    'processed_data': json.loads(row[12]) if row[12] else None,
                    'metadata': json.loads(row[13]) if row[13] else None,
                    'data_classification': row[14],
                    'retention_policy': row[15],
                    'legal_hold': bool(row[16]),
                    'compliance_flags': json.loads(row[17]) if row[17] else None,
                    'storage_tier': row[18],
                    'created_at': row[19],
                    'updated_at': row[20]
                }
                events.append(StandardEvent.from_dict(event_data))
            
            return events
            
        finally:
            conn.close()
    
    def place_legal_hold(self, event_id: str, reason: str, requested_by: str, 
                        expires_at: Optional[str] = None) -> bool:
        """Place legal hold on event"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check if event exists
            cursor.execute('SELECT event_id FROM events WHERE event_id = ?', (event_id,))
            if not cursor.fetchone():
                return False
            
            # Create legal hold
            hold_id = f"hold_{int(time.time() * 1000)}_{event_id}"
            
            cursor.execute('''
                INSERT INTO legal_holds (hold_id, event_id, reason, requested_by, created_at, expires_at, active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (hold_id, event_id, reason, requested_by, datetime.utcnow().isoformat(), expires_at, True))
            
            # Update event legal hold status
            cursor.execute('UPDATE events SET legal_hold = 1, updated_at = ? WHERE event_id = ?',
                           (datetime.utcnow().isoformat(), event_id))
            
            # Move to legal hold storage tier
            self._move_event_tier(event_id, StorageTier.LEGAL_HOLD.value)
            
            conn.commit()
            return True
            
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def release_legal_hold(self, event_id: str, released_by: str) -> bool:
        """Release legal hold on event"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Update legal hold
            cursor.execute('''
                UPDATE legal_holds SET active = 0, released_at = ?, released_by = ?
                WHERE event_id = ? AND active = 1
            ''', (datetime.utcnow().isoformat(), released_by, event_id))
            
            # Update event legal hold status
            cursor.execute('UPDATE events SET legal_hold = 0, updated_at = ? WHERE event_id = ?',
                           (datetime.utcnow().isoformat(), event_id))
            
            # Move back to appropriate storage tier
            event = self.retrieve_event(event_id)
            if event:
                new_tier = self._determine_storage_tier(event)
                self._move_event_tier(event_id, new_tier)
            
            conn.commit()
            return True
            
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def _move_event_tier(self, event_id: str, new_tier: str):
        """Move event between storage tiers"""
        event = self.retrieve_event(event_id)
        if not event:
            return
        
        # Remove from old location
        if event.storage_tier != new_tier:
            old_path = self.storage_paths[event.storage_tier]
            date_str = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00')).strftime('%Y/%m/%d')
            old_file = old_path / event.tenant_id / date_str / f"{event_id}.json"
            
            if old_file.exists():
                old_file.unlink()
            
            # Store in new location
            event.storage_tier = new_tier
            event.updated_at = datetime.utcnow().isoformat()
            
            new_path = self.storage_paths[new_tier]
            date_str = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00')).strftime('%Y/%m/%d')
            new_dir = new_path / event.tenant_id / date_str
            new_dir.mkdir(parents=True, exist_ok=True)
            
            new_file = new_dir / f"{event_id}.json"
            with open(new_file, 'w') as f:
                f.write(event.to_json())
            
            # Update database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('UPDATE events SET storage_tier = ?, updated_at = ?, file_path = ? WHERE event_id = ?',
                           (new_tier, event.updated_at, str(new_file), event_id))
            conn.commit()
            conn.close()
    
    def _retention_processor(self):
        """Background processor for data retention"""
        while True:
            time.sleep(3600)  # Process every hour
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            try:
                # Get all events for processing
                cursor.execute('SELECT * FROM events WHERE legal_hold = 0')
                events = cursor.fetchall()
                
                for row in events:
                    event_id = row[0]
                    event_tier = row[18]
                    created_at = datetime.fromisoformat(row[19].replace('Z', '+00:00'))
                    classification = row[14]
                    retention_policy = row[15]
                    
                    # Calculate age
                    age_days = (datetime.utcnow() - created_at).days
                    
                    # Get retention policy
                    policy = self.retention_policies.get(retention_policy, self.retention_policies["standard"])
                    tier_policy = policy.get(event_tier, {})
                    
                    # Check if event should be moved or deleted
                    if tier_policy["duration_days"] > 0 and age_days > tier_policy["duration_days"]:
                        if event_tier != StorageTier.COLD.value:
                            # Move to cold storage
                            self._move_event_tier(event_id, StorageTier.COLD.value)
                        elif event_tier == StorageTier.COLD.value:
                            # Delete from cold storage
                            self._delete_event(event_id)
                    
                    # Check event count limits
                    cursor.execute('SELECT COUNT(*) FROM events WHERE storage_tier = ?', (event_tier,))
                    count = cursor.fetchone()[0]
                    
                    if count > tier_policy.get("max_events", float('inf')):
                        # Delete oldest events
                        cursor.execute('''
                            DELETE FROM events WHERE storage_tier = ? 
                            ORDER BY created_at ASC 
                            LIMIT ?
                        ''', (event_tier, count - tier_policy["max_events"]))
                
                conn.commit()
                
            except Exception as e:
                conn.rollback()
                print(f"Retention processor error: {e}")
            finally:
                conn.close()
    
    def _storage_tier_migration(self):
        """Background processor for storage tier migration"""
        while True:
            time.sleep(86400)  # Process every day
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            try:
                # Find events that need tier migration
                cursor.execute('''
                    SELECT * FROM events WHERE legal_hold = 0
                ''')
                events = cursor.fetchall()
                
                for row in events:
                    event_id = row[0]
                    current_tier = row[18]
                    created_at = datetime.fromisoformat(row[19].replace('Z', '+00:00'))
                    classification = row[14]
                    retention_policy = row[15]
                    
                    age_days = (datetime.utcnow() - created_at).days
                    
                    # Get retention policy
                    policy = self.retention_policies.get(retention_policy, self.retention_policies["standard"])
                    
                    # Determine appropriate tier
                    if classification == "critical":
                        if age_days <= 90:
                            target_tier = StorageTier.HOT.value
                        elif age_days <= 365:
                            target_tier = StorageTier.WARM.value
                        else:
                            target_tier = StorageTier.COLD.value
                    elif classification == "sensitive":
                        if age_days <= 30:
                            target_tier = StorageTier.HOT.value
                        elif age_days <= 180:
                            target_tier = StorageTier.WARM.value
                        else:
                            target_tier = StorageTier.COLD.value
                    else:  # standard
                        if age_days <= 7:
                            target_tier = StorageTier.HOT.value
                        elif age_days <= 90:
                            target_tier = StorageTier.WARM.value
                        else:
                            target_tier = StorageTier.COLD.value
                    
                    # Migrate if needed
                    if current_tier != target_tier:
                        self._move_event_tier(event_id, target_tier)
                
                conn.commit()
                
            except Exception as e:
                conn.rollback()
                print(f"Storage tier migration error: {e}")
            finally:
                conn.close()
    
    def _compression_processor(self):
        """Background processor for file compression"""
        while True:
            time.sleep(86400)  # Process every day
            
            # Compress cold storage files
            cold_path = self.storage_paths[StorageTier.COLD.value]
            
            for file_path in cold_path.rglob("*.json"):
                if file_path.stat().st_size > 1024 * 1024:  # Compress files > 1MB
                    try:
                        # Read and compress
                        with open(file_path, 'rb') as f_in:
                            with gzip.open(f"{file_path}.gz", 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)
                        
                        # Remove original
                        file_path.unlink()
                        
                    except Exception as e:
                        print(f"Compression error for {file_path}: {e}")
    
    def _legal_hold_processor(self):
        """Background processor for legal hold expiration"""
        while True:
            time.sleep(3600)  # Process every hour
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            try:
                # Find expired legal holds
                cursor.execute('''
                    SELECT * FROM legal_holds 
                    WHERE active = 1 AND expires_at IS NOT NULL 
                    AND expires_at < ?
                ''', (datetime.utcnow().isoformat(),))
                
                expired_holds = cursor.fetchall()
                
                for hold in expired_holds:
                    self.release_legal_hold(hold[1], "system_auto_expire")
                
                conn.commit()
                
            except Exception as e:
                conn.rollback()
                print(f"Legal hold processor error: {e}")
            finally:
                conn.close()
    
    def _delete_event(self, event_id: str):
        """Delete event from storage and database"""
        event = self.retrieve_event(event_id)
        if not event:
            return
        
        # Delete file
        if event.storage_tier in self.storage_paths:
            date_str = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00')).strftime('%Y/%m/%d')
            file_path = self.storage_paths[event.storage_tier] / event.tenant_id / date_str / f"{event_id}.json"
            
            if file_path.exists():
                file_path.unlink()
        
        # Delete from database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM events WHERE event_id = ?', (event_id,))
        conn.commit()
        conn.close()
    
    def get_storage_statistics(self) -> Dict[str, Any]:
        """Get storage statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            stats = {}
            
            # Count by storage tier
            cursor.execute('''
                SELECT storage_tier, COUNT(*) as count 
                FROM events 
                GROUP BY storage_tier
            ''')
            
            for row in cursor.fetchall():
                stats[row[0]] = row[1]
            
            # Count by classification
            cursor.execute('''
                SELECT data_classification, COUNT(*) as count 
                FROM events 
                GROUP BY data_classification
            ''')
            
            stats['by_classification'] = dict(cursor.fetchall())
            
            # Count by legal hold
            cursor.execute('SELECT COUNT(*) FROM events WHERE legal_hold = 1')
            stats['legal_holds'] = cursor.fetchone()[0]
            
            # Storage sizes
            stats['storage_sizes'] = {}
            for tier, path in self.storage_paths.items():
                if path.exists():
                    stats['storage_sizes'][tier] = sum(
                        f.stat().st_size for f in path.rglob('*') if f.is_file()
                    )
            
            return stats
            
        finally:
            conn.close()

class _LazyDataLifecycleProxy:
    def __init__(self):
        self._instance = None
        self._lock = threading.Lock()

    def _get_instance(self):
        if self._instance is None:
            with self._lock:
                if self._instance is None:
                    self._instance = DataLifecycleManager()
        return self._instance

    def __getattr__(self, name):
        return getattr(self._get_instance(), name)


# Global data lifecycle manager (lazy to avoid side effects on import)
data_lifecycle = _LazyDataLifecycleProxy()
