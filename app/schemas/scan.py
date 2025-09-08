from pydantic import BaseModel, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime

class ScanCreate(BaseModel):
    target_domain: str
    scan_type: str = "full"  # full, subdomain, port, vuln
    
    @field_validator('target_domain')
    @classmethod
    def validate_domain(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Domain cannot be empty')
        return v.strip().lower()
    
    @field_validator('scan_type')
    @classmethod
    def validate_scan_type(cls, v):
        allowed_types = ['full', 'subdomain', 'port', 'vuln']
        if v not in allowed_types:
            raise ValueError(f'Scan type must be one of: {allowed_types}')
        return v

class ScanResponse(BaseModel):
    id: int
    target_domain: str
    scan_type: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime]
    results: Optional[Dict[str, Any]]
    error_message: Optional[str]
    
    class Config:
        from_attributes = True

class ScanStatus(BaseModel):
    scan_id: int
    status: str
    progress: int  # 0-100
    current_phase: str
    message: str

class VulnerabilityResult(BaseModel):
    tool_name: str
    target: str
    vulnerability_type: Optional[str]
    severity: Optional[str]
    description: Optional[str]
    raw_output: Optional[str]