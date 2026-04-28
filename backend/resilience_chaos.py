"""
🔧 Firewall Guard - Resilience Patterns & Chaos Testing
Enterprise resilience with circuit breakers, failover, and chaos testing
"""

import time
import random
import threading
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict
import statistics

class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class FailoverStrategy(Enum):
    ACTIVE_PASSIVE = "active_passive"
    ACTIVE_ACTIVE = "active_active"
    ROUND_ROBIN = "round_robin"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    LEAST_CONNECTIONS = "least_connections"

class ChaosTestType(Enum):
    LATENCY_INJECTION = "latency_injection"
    FAULT_INJECTION = "fault_injection"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    NETWORK_PARTITION = "network_partition"
    SERVICE_CRASH = "service_crash"
    MEMORY_PRESSURE = "memory_pressure"
    CPU_PRESSURE = "cpu_pressure"
    DISK_PRESSURE = "disk_pressure"

@dataclass
class ServiceEndpoint:
    """Service endpoint configuration"""
    name: str
    url: str
    weight: int = 1
    active: bool = True
    health_check_url: Optional[str] = None
    timeout: float = 30.0
    max_connections: int = 100
    current_connections: int = 0
    last_health_check: Optional[datetime] = None
    response_time: float = 0.0
    error_rate: float = 0.0
    success_rate: float = 1.0

@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration"""
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    expected_exception: type = Exception
    fallback_function: Optional[Callable] = None
    half_open_max_calls: int = 3
    success_threshold: float = 0.5

@dataclass
class ChaosTestConfig:
    """Chaos test configuration"""
    test_type: ChaosTestType
    target_service: str
    probability: float = 0.1
    duration: float = 60.0
    magnitude: float = 1.0
    enabled: bool = True
    schedule: Optional[str] = None  # Cron-like schedule

class CircuitBreaker:
    """Enterprise circuit breaker implementation"""
    
    def __init__(self, name: str, config: CircuitBreakerConfig):
        self.name = name
        self.config = config
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time = None
        self.half_open_calls = 0
        self.half_open_successes = 0
        self.lock = threading.Lock()
        self.logger = logging.getLogger(f"circuit_breaker.{name}")
        
        # Metrics
        self.total_calls = 0
        self.successful_calls = 0
        self.failed_calls = 0
        self.call_history = []
        
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        with self.lock:
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitState.HALF_OPEN
                    self.half_open_calls = 0
                    self.half_open_successes = 0
                    self.logger.info(f"Circuit breaker {self.name} transitioning to HALF_OPEN")
                else:
                    self._record_call(False, "Circuit breaker OPEN")
                    if self.config.fallback_function:
                        return self.config.fallback_function(*args, **kwargs)
                    raise Exception(f"Circuit breaker {self.name} is OPEN")
            
            elif self.state == CircuitState.HALF_OPEN:
                if self.half_open_calls >= self.config.half_open_max_calls:
                    self._record_call(False, "Circuit breaker HALF_OPEN max calls exceeded")
                    if self.config.fallback_function:
                        return self.config.fallback_function(*args, **kwargs)
                    raise Exception(f"Circuit breaker {self.name} is HALF_OPEN")
        
        # Execute the function
        try:
            start_time = time.time()
            result = func(*args, **kwargs)
            end_time = time.time()
            
            with self.lock:
                self._record_call(True, end_time - start_time)
                
                if self.state == CircuitState.HALF_OPEN:
                    self.half_open_successes += 1
                    if self.half_open_successes >= self.config.half_open_max_calls * self.config.success_threshold:
                        self.state = CircuitState.CLOSED
                        self.failure_count = 0
                        self.logger.info(f"Circuit breaker {self.name} transitioning to CLOSED")
            
            return result
            
        except self.config.expected_exception as e:
            with self.lock:
                self._record_call(False, str(e))
                self.failure_count += 1
                self.last_failure_time = time.time()
                
                if self.state == CircuitState.HALF_OPEN:
                    self.state = CircuitState.OPEN
                    self.logger.info(f"Circuit breaker {self.name} transitioning to OPEN")
                elif self.failure_count >= self.config.failure_threshold:
                    self.state = CircuitState.OPEN
                    self.logger.info(f"Circuit breaker {self.name} transitioning to OPEN")
            
            if self.config.fallback_function:
                return self.config.fallback_function(*args, **kwargs)
            raise
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt reset"""
        return (self.last_failure_time and 
                time.time() - self.last_failure_time >= self.config.recovery_timeout)
    
    def _record_call(self, success: bool, details: Union[str, float]):
        """Record call for metrics"""
        self.total_calls += 1
        
        if success:
            self.successful_calls += 1
            if isinstance(details, float):
                self.call_history.append({
                    'timestamp': time.time(),
                    'success': True,
                    'response_time': details
                })
        else:
            self.failed_calls += 1
            self.call_history.append({
                'timestamp': time.time(),
                'success': False,
                'error': str(details)
            })
        
        # Keep only last 1000 calls
        if len(self.call_history) > 1000:
            self.call_history = self.call_history[-1000:]
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get circuit breaker metrics"""
        with self.lock:
            success_rate = self.successful_calls / self.total_calls if self.total_calls > 0 else 0.0
            
            recent_calls = [call for call in self.call_history 
                          if time.time() - call['timestamp'] < 300]  # Last 5 minutes
            
            recent_success_rate = (sum(1 for call in recent_calls if call['success']) / 
                               len(recent_calls)) if recent_calls else 0.0
            
            avg_response_time = 0.0
            if recent_calls:
                response_times = [call.get('response_time', 0) for call in recent_calls 
                                if 'response_time' in call]
                if response_times:
                    avg_response_time = statistics.mean(response_times)
            
            return {
                'name': self.name,
                'state': self.state.value,
                'total_calls': self.total_calls,
                'successful_calls': self.successful_calls,
                'failed_calls': self.failed_calls,
                'success_rate': success_rate,
                'recent_success_rate': recent_success_rate,
                'avg_response_time': avg_response_time,
                'failure_count': self.failure_count,
                'last_failure_time': self.last_failure_time,
                'timestamp': datetime.utcnow().isoformat()
            }

class LoadBalancer:
    """Enterprise load balancer with multiple strategies"""
    
    def __init__(self, strategy: FailoverStrategy = FailoverStrategy.ROUND_ROBIN):
        self.strategy = strategy
        self.endpoints: Dict[str, ServiceEndpoint] = {}
        self.current_index = 0
        self.lock = threading.Lock()
        self.logger = logging.getLogger("load_balancer")
        
        # Health check thread
        threading.Thread(target=self._health_checker, daemon=True).start()
    
    def add_endpoint(self, endpoint: ServiceEndpoint):
        """Add service endpoint"""
        with self.lock:
            self.endpoints[endpoint.name] = endpoint
            self.logger.info(f"Added endpoint: {endpoint.name}")
    
    def remove_endpoint(self, name: str):
        """Remove service endpoint"""
        with self.lock:
            if name in self.endpoints:
                del self.endpoints[name]
                self.logger.info(f"Removed endpoint: {name}")
    
    def get_endpoint(self) -> Optional[ServiceEndpoint]:
        """Get next endpoint based on strategy"""
        with self.lock:
            active_endpoints = [ep for ep in self.endpoints.values() if ep.active]
            
            if not active_endpoints:
                return None
            
            if self.strategy == FailoverStrategy.ROUND_ROBIN:
                endpoint = active_endpoints[self.current_index % len(active_endpoints)]
                self.current_index += 1
                return endpoint
            
            elif self.strategy == FailoverStrategy.WEIGHTED_ROUND_ROBIN:
                total_weight = sum(ep.weight for ep in active_endpoints)
                if total_weight == 0:
                    return active_endpoints[0]
                
                weight_sum = 0
                random_weight = random.uniform(0, total_weight)
                
                for endpoint in active_endpoints:
                    weight_sum += endpoint.weight
                    if weight_sum >= random_weight:
                        return endpoint
                
                return active_endpoints[-1]
            
            elif self.strategy == FailoverStrategy.LEAST_CONNECTIONS:
                return min(active_endpoints, key=lambda ep: ep.current_connections)
            
            elif self.strategy == FailoverStrategy.ACTIVE_ACTIVE:
                # Random selection from active endpoints
                return random.choice(active_endpoints)
            
            else:  # ACTIVE_PASSIVE
                # Return first active endpoint
                return active_endpoints[0]
    
    def _health_checker(self):
        """Background health checker for endpoints"""
        while True:
            time.sleep(30)  # Check every 30 seconds
            
            with self.lock:
                for endpoint in self.endpoints.values():
                    try:
                        # Simulate health check
                        start_time = time.time()
                        
                        # In production, make actual health check request
                        # For now, simulate based on endpoint configuration
                        if endpoint.health_check_url:
                            # Simulate health check
                            health_status = random.choice(['healthy', 'healthy', 'healthy', 'unhealthy'])
                        else:
                            health_status = 'healthy'
                        
                        end_time = time.time()
                        response_time = end_time - start_time
                        
                        # Update endpoint metrics
                        endpoint.last_health_check = datetime.utcnow()
                        endpoint.response_time = response_time
                        
                        if health_status == 'healthy':
                            endpoint.active = True
                            endpoint.success_rate = max(0.9, endpoint.success_rate - 0.01)
                        else:
                            endpoint.active = False
                            endpoint.success_rate = max(0.0, endpoint.success_rate - 0.1)
                        
                        # Update error rate
                        if health_status == 'unhealthy':
                            endpoint.error_rate = min(1.0, endpoint.error_rate + 0.1)
                        else:
                            endpoint.error_rate = max(0.0, endpoint.error_rate - 0.05)
                        
                    except Exception as e:
                        self.logger.error(f"Health check failed for {endpoint.name}: {e}")
                        endpoint.active = False
                        endpoint.error_rate = min(1.0, endpoint.error_rate + 0.2)
    
    def get_status(self) -> Dict[str, Any]:
        """Get load balancer status"""
        with self.lock:
            active_endpoints = [ep for ep in self.endpoints.values() if ep.active]
            
            return {
                'strategy': self.strategy.value,
                'total_endpoints': len(self.endpoints),
                'active_endpoints': len(active_endpoints),
                'endpoints': {
                    name: {
                        'active': ep.active,
                        'weight': ep.weight,
                        'current_connections': ep.current_connections,
                        'response_time': ep.response_time,
                        'success_rate': ep.success_rate,
                        'error_rate': ep.error_rate,
                        'last_health_check': ep.last_health_check.isoformat() if ep.last_health_check else None
                    }
                    for name, ep in self.endpoints.items()
                },
                'timestamp': datetime.utcnow().isoformat()
            }

class ChaosTestingFramework:
    """Enterprise chaos testing framework"""
    
    def __init__(self):
        self.tests: Dict[str, ChaosTestConfig] = {}
        self.active_tests: Dict[str, Dict[str, Any]] = {}
        self.test_history: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
        self.logger = logging.getLogger("chaos_testing")
        
        # Start background processors
        threading.Thread(target=self._test_executor, daemon=True).start()
        threading.Thread(target=self._test_scheduler, daemon=True).start()
    
    def add_test(self, test_config: ChaosTestConfig) -> str:
        """Add chaos test"""
        test_id = f"chaos_{int(time.time() * 1000)}"
        
        with self.lock:
            self.tests[test_id] = test_config
            self.logger.info(f"Added chaos test: {test_config.test_type.value} for {test_config.target_service}")
        
        return test_id
    
    def enable_test(self, test_id: str):
        """Enable chaos test"""
        with self.lock:
            if test_id in self.tests:
                self.tests[test_id].enabled = True
                self.logger.info(f"Enabled chaos test: {test_id}")
    
    def disable_test(self, test_id: str):
        """Disable chaos test"""
        with self.lock:
            if test_id in self.tests:
                self.tests[test_id].enabled = False
                self.logger.info(f"Disabled chaos test: {test_id}")
    
    def execute_test(self, test_id: str) -> bool:
        """Execute chaos test immediately"""
        with self.lock:
            if test_id not in self.tests:
                return False
            
            test_config = self.tests[test_id]
            if not test_config.enabled:
                return False
            
            # Start test
            active_test = {
                'test_id': test_id,
                'test_type': test_config.test_type.value,
                'target_service': test_config.target_service,
                'start_time': time.time(),
                'end_time': time.time() + test_config.duration,
                'status': 'running',
                'magnitude': test_config.magnitude,
                'probability': test_config.probability
            }
            
            self.active_tests[test_id] = active_test
            
            # Execute test based on type
            self._execute_chaos_test(test_config)
            
            return True
    
    def _execute_chaos_test(self, test_config: ChaosTestConfig):
        """Execute specific chaos test"""
        if test_config.test_type == ChaosTestType.LATENCY_INJECTION:
            self._inject_latency(test_config)
        elif test_config.test_type == ChaosTestType.FAULT_INJECTION:
            self._inject_fault(test_config)
        elif test_config.test_type == ChaosTestType.RESOURCE_EXHAUSTION:
            self._exhaust_resources(test_config)
        elif test_config.test_type == ChaosTestType.NETWORK_PARTITION:
            self._create_network_partition(test_config)
        elif test_config.test_type == ChaosTestType.SERVICE_CRASH:
            self._crash_service(test_config)
        elif test_config.test_type == ChaosTestType.MEMORY_PRESSURE:
            self._apply_memory_pressure(test_config)
        elif test_config.test_type == ChaosTestType.CPU_PRESSURE:
            self._apply_cpu_pressure(test_config)
        elif test_config.test_type == ChaosTestType.DISK_PRESSURE:
            self._apply_disk_pressure(test_config)
    
    def _inject_latency(self, test_config: ChaosTestConfig):
        """Inject latency into service"""
        # In production, this would use service mesh or proxy to inject latency
        self.logger.info(f"Injecting {test_config.magnitude * 1000}ms latency into {test_config.target_service}")
    
    def _inject_fault(self, test_config: ChaosTestConfig):
        """Inject fault into service"""
        # In production, this would simulate service failures
        self.logger.info(f"Injecting fault into {test_config.target_service}")
    
    def _exhaust_resources(self, test_config: ChaosTestConfig):
        """Exhaust resources of service"""
        # In production, this would consume resources
        self.logger.info(f"Exhausting resources in {test_config.target_service}")
    
    def _create_network_partition(self, test_config: ChaosTestConfig):
        """Create network partition"""
        # In production, this would use network policies
        self.logger.info(f"Creating network partition for {test_config.target_service}")
    
    def _crash_service(self, test_config: ChaosTestConfig):
        """Crash service"""
        # In production, this would simulate service crash
        self.logger.info(f"Simulating crash of {test_config.target_service}")
    
    def _apply_memory_pressure(self, test_config: ChaosTestConfig):
        """Apply memory pressure"""
        # In production, this would consume memory
        self.logger.info(f"Applying memory pressure to {test_config.target_service}")
    
    def _apply_cpu_pressure(self, test_config: ChaosTestConfig):
        """Apply CPU pressure"""
        # In production, this would consume CPU
        self.logger.info(f"Applying CPU pressure to {test_config.target_service}")
    
    def _apply_disk_pressure(self, test_config: ChaosTestConfig):
        """Apply disk pressure"""
        # In production, this would consume disk space
        self.logger.info(f"Applying disk pressure to {test_config.target_service}")
    
    def _test_executor(self):
        """Background test executor"""
        while True:
            time.sleep(10)  # Check every 10 seconds
            
            with self.lock:
                current_time = time.time()
                
                # Check for completed tests
                completed_tests = []
                for test_id, active_test in self.active_tests.items():
                    if current_time >= active_test['end_time']:
                        completed_tests.append(test_id)
                        
                        # Record test completion
                        test_history = {
                            'test_id': test_id,
                            'test_type': active_test['test_type'],
                            'target_service': active_test['target_service'],
                            'start_time': active_test['start_time'],
                            'end_time': active_test['end_time'],
                            'duration': active_test['end_time'] - active_test['start_time'],
                            'status': 'completed',
                            'magnitude': active_test['magnitude'],
                            'probability': active_test['probability']
                        }
                        
                        self.test_history.append(test_history)
                        self.logger.info(f"Completed chaos test: {test_id}")
                
                # Remove completed tests
                for test_id in completed_tests:
                    del self.active_tests[test_id]
                
                # Keep only last 1000 test history entries
                if len(self.test_history) > 1000:
                    self.test_history = self.test_history[-1000:]
    
    def _test_scheduler(self):
        """Background test scheduler"""
        while True:
            time.sleep(60)  # Check every minute
            
            with self.lock:
                current_time = time.time()
                
                # Check for scheduled tests
                for test_id, test_config in self.tests.items():
                    if test_config.enabled and test_config.schedule:
                        # In production, parse cron-like schedule
                        # For now, simulate random execution
                        if random.random() < test_config.probability:
                            self.execute_test(test_id)
    
    def get_test_status(self) -> Dict[str, Any]:
        """Get chaos testing status"""
        with self.lock:
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'total_tests': len(self.tests),
                'enabled_tests': len([t for t in self.tests.values() if t.enabled]),
                'active_tests': len(self.active_tests),
                'test_history_count': len(self.test_history),
                'active_tests_detail': {
                    test_id: {
                        'test_type': test['test_type'],
                        'target_service': test['target_service'],
                        'start_time': test['start_time'],
                        'end_time': test['end_time'],
                        'status': test['status'],
                        'magnitude': test['magnitude']
                    }
                    for test_id, test in self.active_tests.items()
                },
                'test_types': {
                    test_type.value: len([t for t in self.tests.values() if t.test_type == test_type])
                    for test_type in ChaosTestType
                }
            }

class ResilienceManager:
    """Enterprise resilience manager"""
    
    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.load_balancers: Dict[str, LoadBalancer] = {}
        self.chaos_framework = ChaosTestingFramework()
        self.auto_scaling = AutoScalingManager()
        self.lock = threading.Lock()
        self.logger = logging.getLogger("resilience_manager")
        
        # Initialize default configurations
        self._init_default_configurations()
    
    def _init_default_configurations(self):
        """Initialize default resilience configurations"""
        # Create circuit breakers for critical services
        critical_services = ['api_server', 'ai_service', 'local_engine', 'database']
        
        for service in critical_services:
            config = CircuitBreakerConfig(
                failure_threshold=5,
                recovery_timeout=60.0,
                expected_exception=Exception,
                half_open_max_calls=3,
                success_threshold=0.5
            )
            self.circuit_breakers[service] = CircuitBreaker(service, config)
        
        # Create load balancers
        self.load_balancers['api'] = LoadBalancer(FailoverStrategy.ROUND_ROBIN)
        self.load_balancers['ai'] = LoadBalancer(FailoverStrategy.WEIGHTED_ROUND_ROBIN)
        self.load_balancers['engine'] = LoadBalancer(FailoverStrategy.LEAST_CONNECTIONS)
        
        # Add default endpoints
        self._add_default_endpoints()
        
        # Add default chaos tests
        self._add_default_chaos_tests()
    
    def _add_default_endpoints(self):
        """Add default service endpoints"""
        # API endpoints
        self.load_balancers['api'].add_endpoint(ServiceEndpoint(
            name='api_primary',
            url='http://localhost:5000',
            weight=3,
            health_check_url='http://localhost:5000/health'
        ))
        
        self.load_balancers['api'].add_endpoint(ServiceEndpoint(
            name='api_secondary',
            url='http://localhost:5001',
            weight=2,
            health_check_url='http://localhost:5001/health'
        ))
        
        # AI service endpoints
        self.load_balancers['ai'].add_endpoint(ServiceEndpoint(
            name='ai_primary',
            url='http://localhost:6001',
            weight=3,
            health_check_url='http://localhost:6001/health'
        ))
        
        self.load_balancers['ai'].add_endpoint(ServiceEndpoint(
            name='ai_secondary',
            url='http://localhost:6002',
            weight=2,
            health_check_url='http://localhost:6002/health'
        ))
        
        # Engine endpoints
        self.load_balancers['engine'].add_endpoint(ServiceEndpoint(
            name='engine_primary',
            url='http://localhost:7000',
            weight=3,
            health_check_url='http://localhost:7000/health'
        ))
        
        self.load_balancers['engine'].add_endpoint(ServiceEndpoint(
            name='engine_secondary',
            url='http://localhost:7001',
            weight=2,
            health_check_url='http://localhost:7001/health'
        ))
    
    def _add_default_chaos_tests(self):
        """Add default chaos tests"""
        # Latency injection tests
        self.chaos_framework.add_test(ChaosTestConfig(
            test_type=ChaosTestType.LATENCY_INJECTION,
            target_service='api_server',
            probability=0.05,
            duration=30.0,
            magnitude=0.5  # 500ms
        ))
        
        self.chaos_framework.add_test(ChaosTestConfig(
            test_type=ChaosTestType.LATENCY_INJECTION,
            target_service='ai_service',
            probability=0.05,
            duration=30.0,
            magnitude=1.0  # 1000ms
        ))
        
        # Fault injection tests
        self.chaos_framework.add_test(ChaosTestConfig(
            test_type=ChaosTestType.FAULT_INJECTION,
            target_service='local_engine',
            probability=0.02,
            duration=15.0,
            magnitude=1.0
        ))
        
        # Resource exhaustion tests
        self.chaos_framework.add_test(ChaosTestConfig(
            test_type=ChaosTestType.RESOURCE_EXHAUSTION,
            target_service='api_server',
            probability=0.01,
            duration=20.0,
            magnitude=0.8
        ))
    
    def call_with_circuit_breaker(self, service_name: str, func: Callable, *args, **kwargs) -> Any:
        """Call function with circuit breaker protection"""
        if service_name not in self.circuit_breakers:
            return func(*args, **kwargs)
        
        return self.circuit_breakers[service_name].call(func, *args, **kwargs)
    
    def get_load_balanced_endpoint(self, service_name: str) -> Optional[ServiceEndpoint]:
        """Get load balanced endpoint"""
        if service_name not in self.load_balancers:
            return None
        
        return self.load_balancers[service_name].get_endpoint()
    
    def get_resilience_status(self) -> Dict[str, Any]:
        """Get comprehensive resilience status"""
        with self.lock:
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'circuit_breakers': {
                    name: cb.get_metrics()
                    for name, cb in self.circuit_breakers.items()
                },
                'load_balancers': {
                    name: lb.get_status()
                    for name, lb in self.load_balancers.items()
                },
                'chaos_testing': self.chaos_framework.get_test_status(),
                'auto_scaling': self.auto_scaling.get_status()
            }

class AutoScalingManager:
    """Enterprise auto-scaling manager"""
    
    def __init__(self):
        self.scaling_policies: Dict[str, Dict[str, Any]] = {}
        self.scaling_history: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
        self.logger = logging.getLogger("auto_scaling")
        
        # Initialize default scaling policies
        self._init_default_policies()
        
        # Start background processor
        threading.Thread(target=self._scaling_monitor, daemon=True).start()
    
    def _init_default_policies(self):
        """Initialize default auto-scaling policies"""
        self.scaling_policies = {
            'api_server': {
                'min_instances': 2,
                'max_instances': 10,
                'target_cpu': 70,
                'target_memory': 80,
                'scale_up_threshold': 85,
                'scale_down_threshold': 30,
                'scale_up_cooldown': 300,
                'scale_down_cooldown': 600,
                'current_instances': 2
            },
            'ai_service': {
                'min_instances': 2,
                'max_instances': 8,
                'target_cpu': 75,
                'target_memory': 85,
                'scale_up_threshold': 90,
                'scale_down_threshold': 25,
                'scale_up_cooldown': 300,
                'scale_down_cooldown': 600,
                'current_instances': 2
            },
            'local_engine': {
                'min_instances': 1,
                'max_instances': 5,
                'target_cpu': 60,
                'target_memory': 70,
                'scale_up_threshold': 80,
                'scale_down_threshold': 20,
                'scale_up_cooldown': 300,
                'scale_down_cooldown': 600,
                'current_instances': 1
            }
        }
    
    def _scaling_monitor(self):
        """Background scaling monitor"""
        while True:
            time.sleep(60)  # Check every minute
            
            with self.lock:
                current_time = time.time()
                
                for service_name, policy in self.scaling_policies.items():
                    # In production, get actual metrics from monitoring system
                    # For now, simulate metrics
                    cpu_usage = random.uniform(20, 90)
                    memory_usage = random.uniform(30, 85)
                    
                    # Check if scaling is needed
                    should_scale_up = (
                        cpu_usage > policy['scale_up_threshold'] or
                        memory_usage > policy['scale_up_threshold']
                    )
                    
                    should_scale_down = (
                        cpu_usage < policy['scale_down_threshold'] and
                        memory_usage < policy['scale_down_threshold']
                    )
                    
                    if should_scale_up and policy['current_instances'] < policy['max_instances']:
                        self._scale_up(service_name, policy)
                    elif should_scale_down and policy['current_instances'] > policy['min_instances']:
                        self._scale_down(service_name, policy)
    
    def _scale_up(self, service_name: str, policy: Dict[str, Any]):
        """Scale up service"""
        old_instances = policy['current_instances']
        policy['current_instances'] += 1
        
        scaling_event = {
            'service': service_name,
            'action': 'scale_up',
            'old_instances': old_instances,
            'new_instances': policy['current_instances'],
            'timestamp': datetime.utcnow().isoformat(),
            'reason': 'High resource usage'
        }
        
        self.scaling_history.append(scaling_event)
        self.logger.info(f"Scaled up {service_name} from {old_instances} to {policy['current_instances']} instances")
    
    def _scale_down(self, service_name: str, policy: Dict[str, Any]):
        """Scale down service"""
        old_instances = policy['current_instances']
        policy['current_instances'] -= 1
        
        scaling_event = {
            'service': service_name,
            'action': 'scale_down',
            'old_instances': old_instances,
            'new_instances': policy['current_instances'],
            'timestamp': datetime.utcnow().isoformat(),
            'reason': 'Low resource usage'
        }
        
        self.scaling_history.append(scaling_event)
        self.logger.info(f"Scaled down {service_name} from {old_instances} to {policy['current_instances']} instances")
    
    def get_status(self) -> Dict[str, Any]:
        """Get auto-scaling status"""
        with self.lock:
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'scaling_policies': {
                    service: {
                        'current_instances': policy['current_instances'],
                        'min_instances': policy['min_instances'],
                        'max_instances': policy['max_instances'],
                        'scale_up_threshold': policy['scale_up_threshold'],
                        'scale_down_threshold': policy['scale_down_threshold']
                    }
                    for service, policy in self.scaling_policies.items()
                },
                'scaling_history_count': len(self.scaling_history),
                'recent_scaling': self.scaling_history[-10:] if self.scaling_history else []
            }

# Global resilience manager
resilience_manager = ResilienceManager()
