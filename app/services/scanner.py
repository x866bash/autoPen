import asyncio
import logging
from typing import Dict, Any, List
from datetime import datetime
from .tools import SubdomainEnumerator, PortScanner, VulnerabilityScanner

logger = logging.getLogger(__name__)

class ScanOrchestrator:
    """Main orchestrator for the scanning pipeline"""
    
    def __init__(self):
        self.subdomain_enumerator = SubdomainEnumerator()
        self.port_scanner = PortScanner()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.scan_status = {}
    
    async def run_full_scan(self, scan_id: int, target_domain: str) -> Dict[str, Any]:
        """Run a complete scanning pipeline"""
        try:
            self._update_scan_status(scan_id, "running", 0, "Starting scan", "Initializing...")
            
            # Phase 1: Subdomain Enumeration
            self._update_scan_status(scan_id, "running", 10, "subdomain_enum", "Enumerating subdomains...")
            subdomains = await self.subdomain_enumerator.enumerate_subdomains(target_domain)
            
            # Add the main domain to the list
            all_targets = [target_domain] + subdomains
            all_targets = list(set(all_targets))  # Remove duplicates
            
            self._update_scan_status(scan_id, "running", 30, "subdomain_enum", f"Found {len(all_targets)} targets")
            
            # Phase 2: Port Scanning
            self._update_scan_status(scan_id, "running", 40, "port_scan", "Scanning ports...")
            port_results = await self.port_scanner.scan_ports(all_targets)
            
            self._update_scan_status(scan_id, "running", 70, "port_scan", f"Scanned {len(port_results)} targets")
            
            # Phase 3: Vulnerability Scanning
            self._update_scan_status(scan_id, "running", 80, "vuln_scan", "Scanning vulnerabilities...")
            vulnerabilities = await self.vulnerability_scanner.scan_vulnerabilities(port_results)
            
            self._update_scan_status(scan_id, "running", 95, "vuln_scan", f"Found {len(vulnerabilities)} potential issues")
            
            # Compile results
            results = {
                'target_domain': target_domain,
                'scan_completed_at': datetime.utcnow().isoformat(),
                'summary': {
                    'total_subdomains': len(subdomains),
                    'total_targets': len(all_targets),
                    'targets_with_open_ports': len(port_results),
                    'total_vulnerabilities': len(vulnerabilities)
                },
                'subdomains': subdomains,
                'port_scan_results': port_results,
                'vulnerabilities': vulnerabilities
            }
            
            self._update_scan_status(scan_id, "completed", 100, "completed", "Scan completed successfully")
            
            return results
            
        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            logger.error(error_msg)
            self._update_scan_status(scan_id, "failed", 0, "error", error_msg)
            raise
    
    async def run_subdomain_scan(self, scan_id: int, target_domain: str) -> Dict[str, Any]:
        """Run only subdomain enumeration"""
        try:
            self._update_scan_status(scan_id, "running", 0, "subdomain_enum", "Starting subdomain enumeration...")
            
            subdomains = await self.subdomain_enumerator.enumerate_subdomains(target_domain)
            
            results = {
                'target_domain': target_domain,
                'scan_completed_at': datetime.utcnow().isoformat(),
                'subdomains': subdomains,
                'total_found': len(subdomains)
            }
            
            self._update_scan_status(scan_id, "completed", 100, "completed", f"Found {len(subdomains)} subdomains")
            
            return results
            
        except Exception as e:
            error_msg = f"Subdomain scan failed: {str(e)}"
            logger.error(error_msg)
            self._update_scan_status(scan_id, "failed", 0, "error", error_msg)
            raise
    
    async def run_port_scan(self, scan_id: int, target_domain: str) -> Dict[str, Any]:
        """Run only port scanning"""
        try:
            self._update_scan_status(scan_id, "running", 0, "port_scan", "Starting port scan...")
            
            port_results = await self.port_scanner.scan_ports([target_domain])
            
            results = {
                'target_domain': target_domain,
                'scan_completed_at': datetime.utcnow().isoformat(),
                'port_scan_results': port_results
            }
            
            self._update_scan_status(scan_id, "completed", 100, "completed", "Port scan completed")
            
            return results
            
        except Exception as e:
            error_msg = f"Port scan failed: {str(e)}"
            logger.error(error_msg)
            self._update_scan_status(scan_id, "failed", 0, "error", error_msg)
            raise
    
    async def run_vulnerability_scan(self, scan_id: int, target_domain: str) -> Dict[str, Any]:
        """Run only vulnerability scanning"""
        try:
            self._update_scan_status(scan_id, "running", 0, "vuln_scan", "Starting vulnerability scan...")
            
            # First need to do a quick port scan
            port_results = await self.port_scanner.scan_ports([target_domain])
            vulnerabilities = await self.vulnerability_scanner.scan_vulnerabilities(port_results)
            
            results = {
                'target_domain': target_domain,
                'scan_completed_at': datetime.utcnow().isoformat(),
                'vulnerabilities': vulnerabilities,
                'total_vulnerabilities': len(vulnerabilities)
            }
            
            self._update_scan_status(scan_id, "completed", 100, "completed", f"Found {len(vulnerabilities)} vulnerabilities")
            
            return results
            
        except Exception as e:
            error_msg = f"Vulnerability scan failed: {str(e)}"
            logger.error(error_msg)
            self._update_scan_status(scan_id, "failed", 0, "error", error_msg)
            raise
    
    def _update_scan_status(self, scan_id: int, status: str, progress: int, phase: str, message: str):
        """Update scan status for real-time tracking"""
        self.scan_status[scan_id] = {
            'status': status,
            'progress': progress,
            'current_phase': phase,
            'message': message,
            'updated_at': datetime.utcnow().isoformat()
        }
    
    def get_scan_status(self, scan_id: int) -> Dict[str, Any]:
        """Get current scan status"""
        return self.scan_status.get(scan_id, {
            'status': 'unknown',
            'progress': 0,
            'current_phase': 'unknown',
            'message': 'Scan status not found'
        })

# Global orchestrator instance
scan_orchestrator = ScanOrchestrator()