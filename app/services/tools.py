import subprocess
import json
import asyncio
import tempfile
import os
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class SecurityTool:
    """Base class for security tools"""
    
    def __init__(self, name: str):
        self.name = name
    
    async def run_command(self, cmd: List[str], timeout: int = 300) -> str:
        """Run a command asynchronously with timeout"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )
            
            if process.returncode != 0:
                logger.error(f"{self.name} failed: {stderr.decode()}")
                return ""
            
            return stdout.decode()
        except asyncio.TimeoutError:
            logger.error(f"{self.name} timed out")
            return ""
        except Exception as e:
            logger.error(f"{self.name} error: {str(e)}")
            return ""

class SubdomainEnumerator(SecurityTool):
    """Subdomain enumeration using multiple tools"""
    
    def __init__(self):
        super().__init__("SubdomainEnumerator")
    
    async def enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains using available tools"""
        subdomains = set()
        
        # Try multiple methods
        methods = [
            self._crtsh_lookup,
            self._dns_bruteforce,
            self._certificate_transparency
        ]
        
        for method in methods:
            try:
                results = await method(domain)
                subdomains.update(results)
            except Exception as e:
                logger.error(f"Subdomain enumeration method failed: {e}")
        
        return list(subdomains)
    
    async def _crtsh_lookup(self, domain: str) -> List[str]:
        """Use crt.sh for certificate transparency lookup"""
        import aiohttp
        subdomains = []
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        for cert in data:
                            name = cert.get('name_value', '')
                            if name and domain in name:
                                subdomains.append(name.strip())
        except Exception as e:
            logger.error(f"crt.sh lookup failed: {e}")
        
        return subdomains
    
    async def _dns_bruteforce(self, domain: str) -> List[str]:
        """Simple DNS bruteforce with common subdomains"""
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'app', 'mobile', 'secure', 'vpn', 'remote'
        ]
        
        subdomains = []
        for sub in common_subs:
            subdomain = f"{sub}.{domain}"
            try:
                # Simple DNS resolution check
                import socket
                socket.gethostbyname(subdomain)
                subdomains.append(subdomain)
            except socket.gaierror:
                pass
        
        return subdomains
    
    async def _certificate_transparency(self, domain: str) -> List[str]:
        """Additional certificate transparency sources"""
        # Placeholder for additional CT log sources
        return []

class PortScanner(SecurityTool):
    """Port scanning functionality"""
    
    def __init__(self):
        super().__init__("PortScanner")
    
    async def scan_ports(self, targets: List[str]) -> Dict[str, Any]:
        """Scan ports on target hosts"""
        results = {}
        
        # Common ports to scan
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 6379, 27017]
        
        for target in targets:
            target_results = await self._scan_target_ports(target, common_ports)
            if target_results:
                results[target] = target_results
        
        return results
    
    async def _scan_target_ports(self, target: str, ports: List[int]) -> Dict[str, Any]:
        """Scan specific ports on a target"""
        import socket
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    service = self._identify_service(port)
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'state': 'open'
                    })
            except Exception:
                pass
        
        return {
            'target': target,
            'open_ports': open_ports,
            'scan_time': 'now'
        }
    
    def _identify_service(self, port: int) -> str:
        """Identify common services by port"""
        services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 993: 'imaps', 995: 'pop3s',
            3306: 'mysql', 5432: 'postgresql', 6379: 'redis',
            27017: 'mongodb'
        }
        return services.get(port, 'unknown')

class VulnerabilityScanner(SecurityTool):
    """Vulnerability scanning functionality"""
    
    def __init__(self):
        super().__init__("VulnerabilityScanner")
    
    async def scan_vulnerabilities(self, targets: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan for vulnerabilities on targets"""
        vulnerabilities = []
        
        for target, port_info in targets.items():
            target_vulns = await self._scan_target_vulnerabilities(target, port_info)
            vulnerabilities.extend(target_vulns)
        
        return vulnerabilities
    
    async def _scan_target_vulnerabilities(self, target: str, port_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan vulnerabilities on a specific target"""
        vulnerabilities = []
        
        # Check for common web vulnerabilities
        for port_data in port_info.get('open_ports', []):
            port = port_data['port']
            service = port_data['service']
            
            if service in ['http', 'https']:
                web_vulns = await self._scan_web_vulnerabilities(target, port)
                vulnerabilities.extend(web_vulns)
        
        return vulnerabilities
    
    async def _scan_web_vulnerabilities(self, target: str, port: int) -> List[Dict[str, Any]]:
        """Scan web-specific vulnerabilities"""
        vulnerabilities = []
        
        # Basic HTTP security headers check
        try:
            import aiohttp
            protocol = 'https' if port == 443 else 'http'
            url = f"{protocol}://{target}:{port}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    headers = response.headers
                    
                    # Check for missing security headers
                    security_headers = {
                        'X-Frame-Options': 'Clickjacking protection missing',
                        'X-Content-Type-Options': 'MIME type sniffing protection missing',
                        'X-XSS-Protection': 'XSS protection missing',
                        'Strict-Transport-Security': 'HSTS missing',
                        'Content-Security-Policy': 'CSP missing'
                    }
                    
                    for header, description in security_headers.items():
                        if header not in headers:
                            vulnerabilities.append({
                                'target': target,
                                'port': port,
                                'vulnerability_type': 'Missing Security Header',
                                'severity': 'Medium',
                                'description': description,
                                'tool': 'HeaderScanner'
                            })
        
        except Exception as e:
            logger.error(f"Web vulnerability scan failed for {target}:{port}: {e}")
        
        return vulnerabilities