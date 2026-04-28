"""
🔐 Firewall Guard - mTLS Service Mesh & Supply Chain Security
Enterprise-grade service-to-service authentication and supply chain security
"""

import ssl
import hashlib
import time
import json
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import requests
import yaml

class ServiceMeshManager:
    """Enterprise mTLS service mesh manager"""
    
    def __init__(self, config_path: str = "service_mesh_config.yaml"):
        self.config_path = config_path
        self.services = {}
        self.certificates = {}
        self.connections = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
        
        # Load configuration
        self._load_config()
        
        # Initialize certificate authority
        self._init_certificate_authority()
        
        # Start background processors
        self._start_background_processors()
    
    def _load_config(self):
        """Load service mesh configuration"""
        config_path = Path(self.config_path)
        
        if not config_path.exists():
            # Create default configuration
            default_config = {
                "certificate_authority": {
                    "ca_name": "Firewall Guard CA",
                    "ca_cert_path": "certs/ca.crt",
                    "ca_key_path": "certs/ca.key",
                    "validity_days": 365
                },
                "services": {
                    "api_server": {
                        "common_name": "api.firewall-guard.local",
                        "ip_address": "127.0.0.1",
                        "port": 5000,
                        "domains": ["api.firewall-guard.local", "localhost", "127.0.0.1"]
                    },
                    "ai_service": {
                        "common_name": "ai.firewall-guard.local",
                        "ip_address": "127.0.0.1",
                        "port": 6001,
                        "domains": ["ai.firewall-guard.local", "localhost", "127.0.0.1"]
                    },
                    "local_engine": {
                        "common_name": "engine.firewall-guard.local",
                        "ip_address": "127.0.0.1",
                        "port": 7000,
                        "domains": ["engine.firewall-guard.local", "localhost", "127.0.0.1"]
                    }
                },
                "certificate_rotation": {
                    "rotation_interval_days": 30,
                    "warning_days": 7,
                    "auto_rotate": True
                }
            }
            
            with open(config_path, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)
        
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
    
    def _init_certificate_authority(self):
        """Initialize certificate authority"""
        ca_config = self.config.get('certificate_authority', {})
        
        certs_dir = Path("certs")
        certs_dir.mkdir(exist_ok=True)
        
        ca_cert_path = certs_dir / ca_config["ca_cert_path"]
        ca_key_path = certs_dir / ca_key_path]
        
        # Check if CA already exists
        if ca_cert_path.exists() and ca_key_path.exists():
            # Load existing CA
            with open(ca_cert_path, 'rb') as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
            with open(ca_key_path, 'rb') as f:
                ca_key = serialization.load_pem_private_key(f.read())
            
            self.certificates['ca'] = ca_cert
            self.certificates['ca_key'] = ca_key
        else:
            # Create new CA
            ca_key = x509.generate_private_key(
                algorithm=hashes.SHA256(),
                public_exponent=65537
            )
            
            subject = x509.Name([
                x509.NameAttribute(x509.NameOID.COMMON_NAME, ca_config["ca_name"]),
                x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_NAME, "Firewall Guard"),
                x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT, "Security"),
                x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US")
            ])
            
            ca_cert = x509.CertificateBuilder(
                subject_name=subject,
                issuer_name=subject,
                public_key=ca_key.public_key(),
                serial_number=x509.random_serial_number(),
                not_valid_before=datetime.utcnow(),
                not_valid_after=datetime.utcnow() + timedelta(days=ca_config["validity_days"]),
                extensions=[
                    x509.BasicConstraints(ca=True, ca=True),
                    x509.KeyUsage(
                        digital_signature=True,
                        cert_sign=True,
                        crl_sign=True,
                        key_cert_sign=True
                    ),
                    x509.SubjectKeyIdentifier(
                        method=x509.SubjectKeyIdentifier.HASH_SHA256,
                        issuer=subject
                    ),
                    x509.AuthorityKeyIdentifier(
                        keyid="ca:1",
                        authority_key_identifier=x509.AuthorityKeyIdentifier.KEY_IDENTIFIER
                    )
                ]
            ).sign(ca_key, default_backend())
            
            # Save CA certificates
            with open(ca_cert_path, 'wb') as f:
                f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
            with open(ca_key_path, 'wb') as f:
                f.write(ca_key.private_bytes(serialization.Encoding.PEM))
            
            self.certificates['ca'] = ca_cert
            self.certificates['ca_key'] = ca_key
        
        self.logger.info("Certificate Authority initialized")
    
    def generate_service_certificate(self, service_name: str, tenant_id: str = "default") -> Tuple[str, str]:
        """Generate certificate for service"""
        service_config = self.config['services'].get(service_name)
        if not service_config:
            raise ValueError(f"Service {service_name} not found in configuration")
        
        # Generate private key
        private_key = x509.generate_private_key(
            algorithm=hashes.SHA256(),
            public_exponent=65537
        )
        
        # Create certificate
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, service_config["common_name"]),
            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_NAME, "Firewall Guard"),
            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT, "Security"),
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.NameOID.UNIT, service_name.upper()),
            x509.NameAttribute(x509.NameOID.DC_IDENTIFIER, tenant_id)
        ])
        
        cert = x509.CertificateBuilder(
            subject_name=subject,
            issuer_name=self.certificates['ca'].subject,
            public_key=private_key.public_key(),
            serial_number=x509.random_serial_number(),
            not_valid_before=datetime.utcnow(),
            not_valid_after=datetime.utcnow() + timedelta(days=90),
            extensions=[
                x509.BasicConstraints(ca=False),
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_agreement=True,
                    server_auth=True,
                    client_auth=True
                ),
                x509.ExtendedKeyUsage(
                    serverAuth=True,
                    clientAuth=True
                ),
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(service_config["common_name"]),
                        x509.IPAddress(service_config["ip_address"]),
                        *[x509.DNSName(domain) for domain in service_config["domains"]]
                    ]
                ),
                x509.SubjectKeyIdentifier(
                    method=x509.SubjectKeyIdentifier.HASH_SHA256,
                    issuer=self.certificates['ca'].subject
                ),
                x509.AuthorityKeyIdentifier(
                    keyid=f"service:{service_name}",
                    authority_key_identifier=x509.AuthorityKeyIdentifier.KEY_IDENTIFIER
                )
            ]
        ).sign(self.certificates['ca_key'], default_backend())
        
        # Save certificates
        certs_dir = Path("certs")
        service_dir = certs_dir / service_name
        service_dir.mkdir(exist_ok=True)
        
        cert_path = service_dir / "server.crt"
        key_path = service_dir / "server.key"
        
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, 'wb') as f:
            f.write(private_key.private_bytes(serialization.Encoding.PEM))
        
        self.certificates[service_name] = cert
        self.certificates[f"{service_name}_key"] = private_key
        
        return str(cert_path), str(key_path)
    
    def verify_certificate(self, cert_path: str, service_name: str) -> bool:
        """Verify service certificate against CA"""
        try:
            cert = x509.load_pem_x509_certificate(open(cert_path, 'rb').read())
            
            # Check if certificate is valid
            if cert.issuer != self.certificates['ca'].subject:
                return False
            
            # Check if certificate is not expired
            if datetime.utcnow() > cert.not_valid_after:
                return False
            
            # Check if service name matches
            service_config = self.config['services'].get(service_name)
            if service_config:
                if cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value != service_config["common_name"]:
                    return False
            
            # Verify certificate chain
            try:
                cert.verify(
                    issuer=self.certificates['ca'],
                    key=None,
                    default_backend=default_backend()
                )
                return True
            except Exception:
                return False
                
        except Exception as e:
            self.logger.error(f"Certificate verification failed for {cert_path}: {e}")
            return False
    
    def create_secure_connection(self, service_name: str, target_service: str) -> bool:
        """Create secure mTLS connection between services"""
        try:
            # Get certificates
            cert_path = self.certificates.get(f"{service_name}_cert")
            key_path = self.certificates.get(f"{service_name}_key")
            target_cert_path = self.certificates.get(f"{target_service}_cert")
            
            if not all([cert_path, key_path, target_cert_path]):
                self.logger.error(f"Missing certificates for {service_name} -> {target_service}")
                return False
            
            # Create SSL context
            context = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH,
                cafile=str(self.certificates['ca'].public_bytes(serialization.Encoding.PEM))
            
            # Load certificates
            context.load_cert_chain(cert_path)
            context.load_verify_locations(target_cert_path)
            context.load_verify_locations(cert_path)
            
            # Load private key
            context.load_private_key(key_path)
            
            # Store connection
            connection_id = f"{service_name}_to_{target_service}"
            self.connections[connection_id] = {
                'source_service': service_name,
                'target_service': target_service,
                'ssl_context': context,
                'created_at': datetime.utcnow().toISOString(),
                'last_used': datetime.utcnow().isoformat()
            }
            
            self.logger.info(f"Created secure connection: {service_name} -> {target_service}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create secure connection {service_name} -> {target_service}: {e}")
            return False
    
    def rotate_certificates(self):
        """Rotate all service certificates"""
        self.logger.info("Starting certificate rotation")
        
        for service_name in self.config['services'].keys():
            try:
                # Generate new certificate
                cert_path, key_path = self.generate_service_certificate(service_name)
                
                # Update connection contexts
                self._update_connection_contexts(service_name)
                
                self.logger.info(f"Rotated certificate for service: {service_name}")
                
            except Exception as e:
                self.logger.error(f"Failed to rotate certificate for {service_name}: {e}")
    
    def _update_connection_contexts(self, service_name: str):
        """Update SSL contexts for all connections involving service"""
        for connection_id, connection in self.connections.items():
            if connection['source_service'] == service_name or connection['target_service'] == service_name:
                # Recreate SSL context
                cert_path = self.certificates.get(f"{service_name}_cert")
                key_path = self.certificates.get(f"{service_name}_key")
                target_cert_path = self.certificates.get(f"{connection['target_service']}_cert")
                
                if all([cert_path, key_path, target_cert_path]):
                    context = ssl.create_default_context(
                        ssl.Purpose.SERVER_AUTH,
                        cafile=str(self.certificates['ca'].public_bytes(serialization.Encoding.PEM))
                    
                    context.load_cert_chain(cert_path)
                    context.load_verify_locations(target_cert_path)
                    context.load_verify_locations(cert_path)
                    context.load_private_key(key_path)
                    
                    connection['ssl_context'] = context
                    connection['last_used'] = datetime.utcnow().isoformat()
    
    def _start_background_processors(self):
        """Start background processors"""
        threading.Thread(target=self._certificate_rotation_processor, daemon=True).start()
        threading.Thread.target=self._connection_health_checker, daemon=True).start()
    
    def _certificate_rotation_processor(self):
        """Background certificate rotation processor"""
        rotation_interval = self.config.get('certificate_rotation', {}).get('rotation_interval_days', 30) * 24 * 3600  # Convert days to seconds
        
        while True:
            time.sleep(rotation_interval)
            
            self.rotate_certificates()
    
    def _connection_health_checker(self):
        """Background connection health checker"""
        while True:
            time.sleep(300)  # Check every 5 minutes
            
            with self.lock:
                for connection_id, connection in self.connections.items():
                    try:
                        # Test connection health
                        context = connection['ssl_context']
                        
                        # Create test socket
                        import socket
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(5)
                        
                        try:
                            sock.connect((connection['target_service'], self.config['services'][connection['target_service']]['port']))
                            sock.close()
                            connection['status'] = 'healthy'
                        except:
                            connection['status'] = 'unhealthy'
                        
                        connection['last_checked'] = datetime.utcnow().isoformat()
                        
                    except Exception as e:
                        connection['status'] = 'error'
                        self.logger.error(f"Health check failed for {connection_id}: {e}")
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get service mesh status"""
        with self.lock:
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'services': list(self.config['services'].keys()),
                'connections': {
                    conn_id: {
                        'status': conn['status'],
                        'source_service': conn['source_service'],
                        'target_service': conn['target_service'],
                        'last_used': conn['last_used'],
                        'created_at': conn['created_at']
                    }
                    for conn_id, conn in self.connections.items()
                },
                'certificate_authority': {
                    'ca_name': self.certificates['ca'].subject.common_name,
                    'valid_until': self.certificates['ca'].not_valid_after.isoformat(),
                    'certificates_issued': len(self.certificates) - 1  # Excluding CA
                }
            }

class SupplyChainSecurity:
    """Enterprise supply chain security and SBOM management"""
    
    def __init__(self):
        self.sbom_data = {}
        self.dependency_scanner = DependencyScanner()
        self.code_signing = CodeSigningManager()
        self.pipeline_security = PipelineSecurityManager()
        self.lock = threading.Lock()
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        
        # Start background processors
        self._start_background_processors()
    
    def _start_background_processors(self):
        """Start background processors"""
        threading.Thread(target=self._dependency_scanner.scan_dependencies, daemon=True).start()
        threading.Thread(target=self._pipeline_security.monitor_pipeline, daemon=True).start()
    
    def generate_sbom(self, component_name: str, version: str) -> Dict[str, Any]:
        """Generate Software Bill of Materials (SBOM)"""
        sbom = {
            'component_name': component_name,
            'version': version,
            'timestamp': datetime.utcnow().isoformat(),
            'supplier': 'Firewall Guard',
            'supplier_type': 'internal',
            'supplier_url': 'https://firewall-guard.local',
            'components': [],
            'dependencies': [],
            'services': [],
            'data': [],
            'tools': [],
            'licenses': [],
            'copyright': f"Firewall Guard {version} © 2024",
            'hash': self._calculate_component_hash(component_name, version)
        }
        
        # Add dependencies
        dependencies = self.dependency_scanner.get_component_dependencies(component_name)
        sbom['dependencies'] = dependencies
        
        # Add services
        services = self.pipeline_security.get_component_services(component_name)
        sbom['services'] = services
        
        # Add tools
        tools = self.pipeline_security.get_component_tools(component_name)
        sbom['tools'] = tools
        
        # Add data files
        data_files = self.pipeline_security.get_component_data_files(component_name)
        sbom['data'] = data_files
        
        # Add licenses
        licenses = self.pipeline_security.get_component_licenses(component_name)
        sbom['licenses'] = licenses
        
        with self.lock:
            self.sbom_data[f"{component_name}:{version}"] = sbom
        
        return sbom
    
    def _calculate_component_hash(self, component_name: str, version: str) -> str:
        """Calculate component hash for SBOM"""
        hash_input = f"{component_name}:{version}:{datetime.utcnow().isoformat()}"
        return hashlib.sha256(hash_input.encode()).hexdigest()
    
    def verify_component_integrity(self, component_name: str, version: str, expected_hash: str) -> bool:
        """Verify component integrity against SBOM"""
        sbom_key = f"{component_name}:{version}"
        
        with self.lock:
            if sbom_key not in self.sbom_data:
                return False
            
            sbom = self.sbom_data[sbom_key]
            return sbom['hash'] == expected_hash
    
    def export_sbom(self, format: str = "json") -> str:
        """Export SBOM in specified format"""
        with self.lock:
            if format.lower() == "json":
                return json.dumps(self.sbom_data, indent=2, default=str)
            elif format.lower() == "yaml":
                return yaml.dump({"sbom": self.sbom_data}, default_flow_style=False)
            else:
                raise ValueError(f"Unsupported format: {format}")
    
    def get_vulnerability_report(self) -> Dict[str, Any]:
        """Get vulnerability report from dependency scanner"""
        return self.dependency_scanner.get_vulnerability_report()
    
    def get_pipeline_security_status(self) -> Dict[str, Any]:
        """Get pipeline security status"""
        return self.pipeline_security.get_security_status()

class DependencyScanner:
    """Enterprise dependency vulnerability scanner"""
    
    def __init__(self):
        self.dependencies = {}
        self.vulnerabilities = []
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
    
    def scan_dependencies(self):
        """Scan all dependencies for vulnerabilities"""
        self.logger.info("Starting dependency vulnerability scan")
        
        # In production, this would scan:
        # - Python packages (pip-audit)
        # - Node.js packages (npm audit)
        # - Container images (trivy, grype)
        # - Binary files (strings, signatures)
        
        # Simulate vulnerability detection
        simulated_vulnerabilities = [
            {
                'package': 'requests',
                'version': '2.25.1',
                'severity': 'medium',
                'cve': 'CVE-2023-32681',
                'description': 'Requests library vulnerable to potential DoS',
                'affected_versions': ['2.25.0', '2.25.1'],
                'recommendation': 'Update to version 2.26.0 or later'
            },
            {
                'package': 'flask',
                'version': '2.0.1',
                'severity': 'low',
                'cve': None,
                'description': 'Flask web framework',
                'affected_versions': ['2.0.1'],
                'recommendation': 'Monitor for security updates'
            },
            {
                'package': 'cryptography',
                'version': '3.4.8',
                'severity': 'low',
                'cve': None,
                'description': 'Cryptography library',
                'affected_versions': ['3.4.8'],
                'recommendation': 'Keep updated'
            }
        ]
        
        with self.lock:
            self.vulnerabilities = simulated_vulnerabilities
            self.dependencies['python'] = simulated_vulnerabilities
    
    def get_component_dependencies(self, component_name: str) -> List[Dict[str, Any]]:
        """Get dependencies for component"""
        # In production, this would analyze import statements and package files
        return self.dependencies.get('python', [])
    
    def get_vulnerability_report(self) -> Dict[str, Any]:
        """Get vulnerability report"""
        with self.lock:
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities),
                'by_severity': {
                    'critical': len([v for v in self.vulnerabilities if v['severity'] == 'critical']),
                    'high': len([v for v in self.vulnerabilities if v['severity'] == 'high']),
                    'medium': len([v for v in self.vulnerabilities if v['severity'] == 'medium']),
                    'low': len([v for v in self.vulnerabilities if v['severity'] == 'low'])
                },
                'vulnerabilities': self.vulnerabilities
            }

class CodeSigningManager:
    """Enterprise code signing and verification"""
    
    def __init__(self):
        self.signing_key = None
        self.signing_cert = None
        self.signed_files = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
        
        # Initialize code signing
        self._init_code_signing()
    
    def _init_code_signing(self):
        """Initialize code signing infrastructure"""
        certs_dir = Path("code_signing")
        certs_dir.mkdir(exist_ok=True)
        
        key_path = certs_dir / "signing.key"
        cert_path = certs_dir / "signing.crt"
        
        if key_path.exists() and cert_path.exists():
            # Load existing signing key and certificate
            with open(key_path, 'rb') as f:
                self.signing_key = serialization.load_pem_private_key(f.read())
            with open(cert_path, 'rb') as f:
                self.signing_cert = x509.load_pem_x509_certificate(f.read())
        else:
            # Generate new signing key and certificate
            self.signing_key = x509.generate_private_key(
                algorithm=hashes.SHA256(),
                public_exponent=65537
            )
            
            subject = x509.Name([
                x509.NameAttribute(x509.NameOID.COMMON_NAME, "Firewall Guard Code Signing"),
                x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_NAME, "Firewall Guard"),
                x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT, "Security"),
                x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US")
            ])
            
            cert = x509 CertificateBuilder(
                subject_name=subject,
                issuer_name=subject,
                public_key=self.signing_key.public_key(),
                serial_number=x509.random_serial_number(),
                not_valid_before=datetime.utcnow(),
                not_valid_after=datetime.utcnow() + timedelta(days=365),
                extensions=[
                    x509.BasicConstraints(ca=False),
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=True,
                        code_signing=True
                    )
                ]
            ).sign(self.signing_key, default_backend())
            
            # Save certificates
            with open(key_path, 'wb') as f:
                f.write(self.signing_key.private_bytes(serialization.Encoding.PEM))
            with open(cert_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            self.logger.info("Code signing infrastructure initialized")
    
    def sign_file(self, file_path: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Sign file with digital signature"""
        try:
            # Read file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Create signature
            signature = self.signing_key.sign(
                file_content,
                signatures.PKCS7_SHA256(
                    encoding=serialization.Encoding.DER,
                    signature_algorithm=hashes.SHA256
                )
            )
            
            # Create signed file
            signed_content = file_content + signature
            
            # Write signed file
            with open(file_path, 'wb') as f:
                f.write(signed_content)
            
            # Store signing information
            file_hash = hashlib.sha256(file_content).hexdigest()
            
            with self.lock:
                self.signed_files[file_path] = {
                    'file_path': file_path,
                    'signature': signature.hex(),
                    'file_hash': file_hash,
                    'metadata': metadata or {},
                    'signed_at': datetime.utcnow().isoformat(),
                    'verified': True
                }
            
            self.logger.info(f"Signed file: {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to sign file {file_path}: {e}")
            return False
    
    def verify_signature(self, file_path: str) -> bool:
        """Verify digital signature of file"""
        try:
            with self.lock:
                if file_path not in self.signed_files:
                    return False
                
                signed_file_info = self.signed_file_info = self.signed_files[file_path]
                
                # Read signed file
                with open(file_path, 'rb') as f:
                    signed_content = f.read()
                
                # Extract signature
                signature_size = self.signing_key.public_key().key_size // 8
                signature = signed_content[-signature_size:]
                file_content = signed_content[:-signature_size]
                
                # Verify signature
                try:
                    self.signing_key.verify(
                        file_content,
                        signature,
                        signatures.PKCS7_SHA256(
                            encoding=serialization.Encoding.DER,
                            signature_algorithm=hashes.SHA256
                        )
                    )
                    
                    # Verify file hash
                    current_hash = hashlib.sha256(file_content).hexdigest()
                    if current_hash != signed_file_info['file_hash']:
                        self.logger.warning(f"File hash mismatch for {file_path}")
                        return False
                    
                    return True
                    
                except Exception as e:
                    self.logger.error(f"Signature verification failed for {file_path}: {e}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Failed to verify signature for {file_path}: {e}")
            return False
    
    def get_signed_files_status(self) -> Dict[str, Any]:
        """Get status of all signed files"""
        with self.lock:
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'total_signed_files': len(self.signed_files),
                'signed_files': {
                    file_path: {
                        'verified': info['verified'],
                        'signed_at': info['signed_at'],
                        'metadata': info['metadata']
                    }
                    for file_path, info in self.signed_files.items()
                }
            }

class PipelineSecurityManager:
    """Enterprise CI/CDR pipeline security manager"""
    
    def __init__(self):
        self.pipeline_config = self._init_pipeline_config()
        self.security_policies = self._init_security_policies()
        self.security_status = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
        
        # Start background processors
        threading.Thread(target=self._security_monitor, daemon=True).start()
    
    def _init_pipeline_config(self) -> Dict[str, Any]:
        """Initialize pipeline configuration"""
        return {
            'ci_cd_tools': {
                'github_actions': {
                    'enabled': True,
                    'required_checks': ['code_scan', 'dependency_check', 'security_scan'],
                    'blocked_actions': ['push_to_main', 'merge_to_main', 'delete_protected_branches']
                },
                'jenkins': {
                    'enabled': True,
                    'required_plugins': ['dependency-check', 'sonarqube', 'security-scan'],
                    'blocked_plugins': ['insecure-plugin']
                },
                'gitlab_ci': {
                    'secret_detection': True,
                    'security_scanning': True,
                    'dependency_scanning': True,
                    'code_analysis': True
                }
            },
            'security_policies': {
                'code_scanning': {
                    'enabled': True,
                    'tools': ['sonarqube', 'codeql', 'bandit', 'eslint', 'pylint'],
                    'fail_threshold': 'high',
                    'block_merge': True
                },
                'dependency_scanning': {
                    'allowed_sources': ['pypi', 'npm', 'maven', 'gradle'],
                    'blocked_packages': ['known-malicious', 'vulnerable-package'],
                    'auto_update': True,
                    'vulnerability_threshold': 'medium'
                },
                'secret_detection': {
                    'enabled': True,
                    'patterns': ['password', 'key', 'token', 'secret', 'credential'],
                    'block_commit': True,
                    'alert_admin': True
                },
                'code_signing': {
                    'enabled': True,
                    'required_for': ['production', 'staging'],
                    'verify_signatures': True,
                    'block_unsigned': True
                }
            }
        }
    
    def _init_security_policies(self) -> Dict[str, Any]:
        """Initialize security policies"""
        return {
            'code_scanning': {
                'high_severity_issues': ['sql_injection', 'xss', 'command_injection', 'path_traversal'],
                'medium_severity_issues': ['hardcoded_credentials', 'weak_encryption', 'debug_code'],
                'low_severity_issues': 'unused_variables', 'code_style_issues'
            },
            'dependency_scanning': {
                'critical_vulnerabilities': ['cve_critical', 'remote_code_execution', 'privilege_escalation'],
                'high_vulnerabilities': ['sql_injection', 'xss', 'command_injection'],
                'medium_vulnerabilities': ['authentication_bypass', 'information_disclosure'],
                'low_vulnerabilities': 'outdated_dependencies'
            },
            'secret_detection': {
                'patterns': [
                    r'password\s*=\s*["\'][^"]*["\']',
                    r'api[_\s]*=\s*["\'][^"]*["\']',
                    r'token\s*=\s*["\'][^"]*["\']',
                    'key\s*=\s*["\'][^"]*["\']',
                    'secret\s*=\s*["\'][^"]*["\']'
                ]
            }
        }
    
    def get_component_services(self, component_name: str) -> List[str]:
        """Get services associated with component"""
        # In production, this would analyze pipeline configuration files
        return []
    
    def get_component_tools(self, component_name: str) -> List[str]:
        """Get tools used by component"""
        # In production, this would analyze build files and dependencies
        return []
    
    def get_component_data_files(self, component_name: str) -> List[str]:
        """Get data files associated with component"""
        # In production, this would scan file system
        return []
    
    def get_component_licenses(self, component_name: str) -> List[str]:
        """Get licenses for component"""
        # In production, this would analyze license files
        return []
    
    def _security_monitor(self):
        """Background security monitor"""
        while True:
            time.sleep(300)  # Check every 5 minutes
            
            with self.lock:
                # Monitor pipeline security
                self.security_status = {
                    'timestamp': datetime.utcnow().toISOString(),
                    'ci_cd_tools': {},
                    'security_policies': {},
                    'issues_detected': [],
                    'last_scan': datetime.utcnow().isoformat()
                }
                
                # Check CI/CD tools status
                for tool_name, tool_config in self.pipeline_config['ci_cd_tools'].items():
                    if tool_config.get('enabled', False):
                        self.security_status['ci_cd_tools'][tool_name] = {
                            'status': 'operational',
                            'last_check': datetime.utcnow().isoformat(),
                            'issues': []
                        }
                
                # Check security policies
                for policy_name, policy_config in self.security_policies.items():
                    if policy_config.get('enabled', False):
                        self.security_status['security_policies'][policy_name] = {
                            'status': 'operational',
                            'last_check': datetime.utcnow().isoformat(),
                            'issues': []
                        }
                
                self.logger.info("Security monitoring completed")

# Global instances
service_mesh = ServiceMeshManager()
supply_chain = SupplyChainSecurity()
