"""
🔍 Firewall Guard - Centralized Observability Stack
Enterprise-grade monitoring, logging, and tracing system
"""

import json
import time
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import statistics
import uuid
from pathlib import Path

class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class EventType(Enum):
    SECURITY_EVENT = "security_event"
    AI_ANALYSIS = "ai_analysis"
    SYSTEM_EVENT = "system_event"
    USER_ACTION = "user_action"
    PERFORMANCE = "performance"
    ERROR = "error"

@dataclass
class StandardEvent:
    """Standardized event schema for enterprise correlation"""
    event_id: str
    tenant_id: str
    source: str
    event_type: str
    timestamp: str
    severity: str
    confidence: float
    raw_data: Dict[str, Any]
    correlation_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    tags: Optional[List[str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class ObservabilityStack:
    """Enterprise-grade observability and monitoring system"""
    
    def __init__(self):
        self.events = []
        self.metrics = {}
        self.traces = {}
        self.health_status = {}
        self.slo_metrics = {}
        self.retention_policies = self._init_retention_policies()
        self.lock = threading.Lock()
        
        # Initialize SLO definitions
        self._init_slos()
        
        # Start background processors
        self._start_background_processors()
    
    def _init_retention_policies(self) -> Dict[str, Dict]:
        """Define data retention and lifecycle policies"""
        return {
            "hot_storage": {
                "duration_days": 7,
                "max_events": 10000,
                "access_pattern": "real_time"
            },
            "warm_storage": {
                "duration_days": 90,
                "max_events": 100000,
                "access_pattern": "frequent"
            },
            "cold_storage": {
                "duration_days": 365,
                "max_events": 1000000,
                "access_pattern": "archival"
            },
            "legal_hold": {
                "duration_days": -1,  # Permanent
                "max_events": -1,
                "access_pattern": "legal"
            }
        }
    
    def _init_slos(self):
        """Define Service Level Objectives"""
        self.slo_metrics = {
            "detection_latency_p95": {
                "target_ms": 1000,
                "warning_threshold_ms": 1500,
                "critical_threshold_ms": 2000,
                "current_value": 0,
                "measurements": []
            },
            "api_uptime_percentage": {
                "target": 99.9,
                "warning_threshold": 99.5,
                "critical_threshold": 99.0,
                "current_value": 100.0,
                "total_requests": 0,
                "failed_requests": 0
            },
            "alert_delivery_time_p95": {
                "target_ms": 500,
                "warning_threshold_ms": 1000,
                "critical_threshold_ms": 2000,
                "current_value": 0,
                "measurements": []
            },
            "ai_analysis_accuracy": {
                "target": 95.0,
                "warning_threshold": 90.0,
                "critical_threshold": 85.0,
                "current_value": 0,
                "correct_predictions": 0,
                "total_predictions": 0
            }
        }
    
    def _start_background_processors(self):
        """Start background processing threads"""
        threading.Thread(target=self._metrics_processor, daemon=True).start()
        threading.Thread(target=self._retention_processor, daemon=True).start()
        threading.Thread(target=self._health_checker, daemon=True).start()
        threading.Thread(target=self._slo_monitor, daemon=True).start()
    
    def log_event(self, event: StandardEvent):
        """Log standardized event with correlation"""
        with self.lock:
            event.timestamp = datetime.utcnow().isoformat()
            
            # Add to events list
            self.events.append(event)
            
            # Update metrics
            self._update_metrics(event)
            
            # Check SLO violations
            self._check_slo_violations(event)
            
            # Trigger alerts if needed
            if event.severity in ["ERROR", "CRITICAL"]:
                self._trigger_alert(event)
    
    def create_event(self, tenant_id: str, source: str, event_type: EventType, 
                     severity: str, confidence: float, raw_data: Dict[str, Any],
                     correlation_id: Optional[str] = None, user_id: Optional[str] = None,
                     session_id: Optional[str] = None, tags: Optional[List[str]] = None) -> StandardEvent:
        """Create standardized event"""
        return StandardEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            source=source,
            event_type=event_type.value,
            timestamp=datetime.utcnow().isoformat(),
            severity=severity,
            confidence=confidence,
            raw_data=raw_data,
            correlation_id=correlation_id,
            user_id=user_id,
            session_id=session_id,
            tags=tags or []
        )
    
    def trace_operation(self, operation_name: str, tenant_id: str, 
                       operation_data: Dict[str, Any]) -> str:
        """Start distributed tracing for operation"""
        trace_id = str(uuid.uuid4())
        
        with self.lock:
            self.traces[trace_id] = {
                "trace_id": trace_id,
                "operation_name": operation_name,
                "tenant_id": tenant_id,
                "start_time": time.time(),
                "spans": [],
                "status": "running"
            }
        
        return trace_id
    
    def add_span(self, trace_id: str, span_name: str, span_data: Dict[str, Any]):
        """Add span to existing trace"""
        with self.lock:
            if trace_id in self.traces:
                span = {
                    "span_id": str(uuid.uuid4()),
                    "span_name": span_name,
                    "start_time": time.time(),
                    "data": span_data,
                    "status": "completed"
                }
                self.traces[trace_id]["spans"].append(span)
    
    def complete_trace(self, trace_id: str, status: str = "completed"):
        """Complete distributed trace"""
        with self.lock:
            if trace_id in self.traces:
                self.traces[trace_id]["end_time"] = time.time()
                self.traces[trace_id]["duration_ms"] = (
                    self.traces[trace_id]["end_time"] - self.traces[trace_id]["start_time"]
                ) * 1000
                self.traces[trace_id]["status"] = status
                
                # Update SLO metrics
                if "detection" in self.traces[trace_id]["operation_name"].lower():
                    self._update_detection_latency_slo(self.traces[trace_id]["duration_ms"])
    
    def record_metric(self, metric_name: str, value: float, tags: Optional[Dict[str, str]] = None):
        """Record Prometheus-style metric"""
        with self.lock:
            if metric_name not in self.metrics:
                self.metrics[metric_name] = {
                    "values": [],
                    "tags": tags or {},
                    "last_updated": time.time()
                }
            
            self.metrics[metric_name]["values"].append({
                "value": value,
                "timestamp": time.time(),
                "tags": tags or {}
            })
            
            # Keep only last 1000 values per metric
            if len(self.metrics[metric_name]["values"]) > 1000:
                self.metrics[metric_name]["values"] = self.metrics[metric_name]["values"][-1000:]
    
    def check_health(self, service_name: str) -> Dict[str, Any]:
        """Check health of specific service"""
        health_status = {
            "service": service_name,
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "checks": []
        }
        
        # Check basic connectivity
        try:
            # Simulate health check
            health_status["checks"].append({
                "name": "connectivity",
                "status": "pass",
                "duration_ms": 50
            })
        except Exception as e:
            health_status["status"] = "unhealthy"
            health_status["checks"].append({
                "name": "connectivity",
                "status": "fail",
                "error": str(e)
            })
        
        # Check performance
        if service_name in self.metrics:
            recent_metrics = [m for m in self.metrics[service_name]["values"] 
                            if time.time() - m["timestamp"] < 300]  # Last 5 minutes
            
            if recent_metrics:
                avg_response = statistics.mean([m["value"] for m in recent_metrics])
                if avg_response > 1000:  # 1 second threshold
                    health_status["status"] = "degraded"
                
                health_status["checks"].append({
                    "name": "performance",
                    "status": "pass" if avg_response < 1000 else "fail",
                    "avg_response_ms": avg_response
                })
        
        with self.lock:
            self.health_status[service_name] = health_status
        
        return health_status
    
    def get_slo_status(self) -> Dict[str, Any]:
        """Get current SLO compliance status"""
        slo_status = {
            "timestamp": datetime.utcnow().isoformat(),
            "overall_compliance": "healthy",
            "slos": {}
        }
        
        for slo_name, slo_config in self.slo_metrics.items():
            compliance = "healthy"
            
            if slo_name == "detection_latency_p95":
                if slo_config["current_value"] > slo_config["critical_threshold_ms"]:
                    compliance = "critical"
                elif slo_config["current_value"] > slo_config["warning_threshold_ms"]:
                    compliance = "warning"
            
            elif slo_name == "api_uptime_percentage":
                if slo_config["current_value"] < slo_config["critical_threshold"]:
                    compliance = "critical"
                elif slo_config["current_value"] < slo_config["warning_threshold"]:
                    compliance = "warning"
            
            elif slo_name == "alert_delivery_time_p95":
                if slo_config["current_value"] > slo_config["critical_threshold_ms"]:
                    compliance = "critical"
                elif slo_config["current_value"] > slo_config["warning_threshold_ms"]:
                    compliance = "warning"
            
            elif slo_name == "ai_analysis_accuracy":
                if slo_config["current_value"] < slo_config["critical_threshold"]:
                    compliance = "critical"
                elif slo_config["current_value"] < slo_config["warning_threshold"]:
                    compliance = "warning"
            
            slo_status["slos"][slo_name] = {
                "compliance": compliance,
                "target": slo_config["target"],
                "current": slo_config["current_value"],
                "unit": self._get_slo_unit(slo_name)
            }
            
            # Update overall compliance
            if compliance == "critical":
                slo_status["overall_compliance"] = "critical"
            elif compliance == "warning" and slo_status["overall_compliance"] == "healthy":
                slo_status["overall_compliance"] = "warning"
        
        return slo_status
    
    def _get_slo_unit(self, slo_name: str) -> str:
        """Get unit for SLO metric"""
        if "latency" in slo_name or "time" in slo_name:
            return "ms"
        elif "percentage" in slo_name or "accuracy" in slo_name:
            return "%"
        else:
            return "count"
    
    def _update_metrics(self, event: StandardEvent):
        """Update metrics based on event"""
        # Update event counts by type
        metric_name = f"events_{event.event_type}"
        self.record_metric(metric_name, 1, {"severity": event.severity, "source": event.source})
        
        # Update severity distribution
        metric_name = f"severity_{event.severity.lower()}"
        self.record_metric(metric_name, 1, {"event_type": event.event_type})
        
        # Update confidence distribution
        self.record_metric("confidence_score", event.confidence, {"event_type": event.event_type})
    
    def _update_detection_latency_slo(self, latency_ms: float):
        """Update detection latency SLO"""
        slo = self.slo_metrics["detection_latency_p95"]
        slo["measurements"].append(latency_ms)
        
        # Keep only last 100 measurements
        if len(slo["measurements"]) > 100:
            slo["measurements"] = slo["measurements"][-100:]
        
        # Calculate P95
        if len(slo["measurements"]) >= 10:
            slo["current_value"] = statistics.quantile(slo["measurements"], 0.95)
    
    def _check_slo_violations(self, event: StandardEvent):
        """Check for SLO violations and trigger alerts"""
        if event.event_type == EventType.AI_ANALYSIS.value:
            # Update AI accuracy SLO
            slo = self.slo_metrics["ai_analysis_accuracy"]
            if "correct" in event.raw_data.get("validation_result", {}):
                slo["correct_predictions"] += 1
            slo["total_predictions"] += 1
            
            if slo["total_predictions"] > 0:
                slo["current_value"] = (slo["correct_predictions"] / slo["total_predictions"]) * 100
    
    def _trigger_alert(self, event: StandardEvent):
        """Trigger alert for critical events"""
        alert = {
            "alert_id": str(uuid.uuid4()),
            "event_id": event.event_id,
            "severity": event.severity,
            "source": event.source,
            "message": f"Critical {event.event_type} event in {event.source}",
            "timestamp": datetime.utcnow().isoformat(),
            "event_data": event.to_dict()
        }
        
        # Log alert
        self.record_metric("alerts_triggered", 1, {"severity": event.severity})
        
        # In production, this would send to alerting system
        print(f"🚨 ALERT: {alert['message']}")
    
    def _metrics_processor(self):
        """Background processor for metrics aggregation"""
        while True:
            time.sleep(60)  # Process every minute
            
            with self.lock:
                # Aggregate metrics
                for metric_name, metric_data in self.metrics.items():
                    if metric_data["values"]:
                        recent_values = [v for v in metric_data["values"] 
                                       if time.time() - v["timestamp"] < 300]  # Last 5 minutes
                        
                        if recent_values:
                            avg_value = statistics.mean([v["value"] for v in recent_values])
                            self.record_metric(f"{metric_name}_avg_5m", avg_value)
                            
                            p95_value = statistics.quantile([v["value"] for v in recent_values], 0.95)
                            self.record_metric(f"{metric_name}_p95_5m", p95_value)
    
    def _retention_processor(self):
        """Background processor for data retention"""
        while True:
            time.sleep(3600)  # Process every hour
            
            with self.lock:
                current_time = time.time()
                
                # Process events retention
                events_to_remove = []
                for event in self.events:
                    event_time = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00')).timestamp()
                    age_days = (current_time - event_time) / 86400
                    
                    # Move events between storage tiers
                    if age_days > self.retention_policies["hot_storage"]["duration_days"]:
                        # Move to warm storage
                        pass  # In production, move to different storage system
                    
                    if age_days > self.retention_policies["warm_storage"]["duration_days"]:
                        # Move to cold storage
                        pass  # In production, archive to cold storage
                    
                    if age_days > self.retention_policies["cold_storage"]["duration_days"]:
                        # Remove from memory
                        events_to_remove.append(event)
                
                for event in events_to_remove:
                    self.events.remove(event)
                
                # Clean old metrics
                for metric_name, metric_data in self.metrics.items():
                    metric_data["values"] = [v for v in metric_data["values"] 
                                           if current_time - v["timestamp"] < 86400]  # Keep last 24 hours
    
    def _health_checker(self):
        """Background health checker for all services"""
        services = ["api_server", "ai_service", "local_engine", "extension"]
        
        while True:
            time.sleep(30)  # Check every 30 seconds
            
            for service in services:
                self.check_health(service)
    
    def _slo_monitor(self):
        """Background SLO compliance monitor"""
        while True:
            time.sleep(60)  # Check every minute
            
            slo_status = self.get_slo_status()
            
            # Log SLO violations
            for slo_name, slo_data in slo_status["slos"].items():
                if slo_data["compliance"] in ["warning", "critical"]:
                    self.record_metric("slo_violations", 1, {
                        "slo": slo_name,
                        "compliance": slo_data["compliance"]
                    })
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get data for observability dashboard"""
        with self.lock:
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "events_count": len(self.events),
                "metrics_count": len(self.metrics),
                "traces_count": len(self.traces),
                "health_status": self.health_status,
                "slo_status": self.get_slo_status(),
                "recent_events": [e.to_dict() for e in self.events[-10:]],
                "top_metrics": self._get_top_metrics()
            }
    
    def _get_top_metrics(self) -> Dict[str, Any]:
        """Get top metrics for dashboard"""
        top_metrics = {}
        
        for metric_name, metric_data in self.metrics.items():
            if metric_data["values"]:
                recent_values = [v for v in metric_data["values"] 
                               if time.time() - v["timestamp"] < 300]  # Last 5 minutes
                
                if recent_values:
                    top_metrics[metric_name] = {
                        "current": recent_values[-1]["value"],
                        "avg": statistics.mean([v["value"] for v in recent_values]),
                        "min": min([v["value"] for v in recent_values]),
                        "max": max([v["value"] for v in recent_values]),
                        "count": len(recent_values)
                    }
        
        return top_metrics

# Global observability instance
observability = ObservabilityStack()

# Structured logging helper
class StructuredLogger:
    """Enterprise structured logging with correlation"""
    
    def __init__(self, component: str):
        self.component = component
    
    def log(self, level: LogLevel, message: str, tenant_id: str = "default",
             correlation_id: Optional[str] = None, user_id: Optional[str] = None,
             **kwargs):
        """Log structured event"""
        event = observability.create_event(
            tenant_id=tenant_id,
            source=self.component,
            event_type=EventType.SYSTEM_EVENT,
            severity=level.value,
            confidence=1.0,
            raw_data={
                "message": message,
                "level": level.value,
                **kwargs
            },
            correlation_id=correlation_id,
            user_id=user_id
        )
        
        observability.log_event(event)
        
        # Also log to standard logging
        log_level = getattr(logging, level.value)
        logging.getLogger(self.component).log(log_level, message, extra=kwargs)
