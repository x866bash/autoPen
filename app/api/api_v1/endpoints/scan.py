from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List
import asyncio
from app.schemas.scan import ScanCreate, ScanResponse, ScanStatus
from app.services.scanner import scan_orchestrator
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

# In-memory storage for demo (in production, use a proper database)
scans_db = {}
scan_counter = 0

@router.post("/scans", response_model=ScanResponse)
async def create_scan(scan_request: ScanCreate, background_tasks: BackgroundTasks):
    """Create and start a new security scan"""
    global scan_counter
    scan_counter += 1
    scan_id = scan_counter
    
    # Create scan record
    scan_record = {
        'id': scan_id,
        'target_domain': scan_request.target_domain,
        'scan_type': scan_request.scan_type,
        'status': 'pending',
        'created_at': '2024-01-01T00:00:00',
        'completed_at': None,
        'results': None,
        'error_message': None
    }
    
    scans_db[scan_id] = scan_record
    
    # Start scan in background
    background_tasks.add_task(run_scan_background, scan_id, scan_request)
    
    return ScanResponse(**scan_record)

@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int):
    """Get scan details by ID"""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return ScanResponse(**scans_db[scan_id])

@router.get("/scans/{scan_id}/status", response_model=ScanStatus)
async def get_scan_status(scan_id: int):
    """Get real-time scan status"""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    status_info = scan_orchestrator.get_scan_status(scan_id)
    
    return ScanStatus(
        scan_id=scan_id,
        status=status_info.get('status', 'unknown'),
        progress=status_info.get('progress', 0),
        current_phase=status_info.get('current_phase', 'unknown'),
        message=status_info.get('message', 'No status available')
    )

@router.get("/scans", response_model=List[ScanResponse])
async def list_scans():
    """List all scans"""
    return [ScanResponse(**scan) for scan in scans_db.values()]

@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: int):
    """Delete a scan"""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    del scans_db[scan_id]
    return {"message": "Scan deleted successfully"}

async def run_scan_background(scan_id: int, scan_request: ScanCreate):
    """Background task to run the actual scan"""
    try:
        # Update scan status to running
        scans_db[scan_id]['status'] = 'running'
        
        # Run appropriate scan type
        if scan_request.scan_type == 'full':
            results = await scan_orchestrator.run_full_scan(scan_id, scan_request.target_domain)
        elif scan_request.scan_type == 'subdomain':
            results = await scan_orchestrator.run_subdomain_scan(scan_id, scan_request.target_domain)
        elif scan_request.scan_type == 'port':
            results = await scan_orchestrator.run_port_scan(scan_id, scan_request.target_domain)
        elif scan_request.scan_type == 'vuln':
            results = await scan_orchestrator.run_vulnerability_scan(scan_id, scan_request.target_domain)
        else:
            raise ValueError(f"Unknown scan type: {scan_request.scan_type}")
        
        # Update scan record with results
        scans_db[scan_id].update({
            'status': 'completed',
            'completed_at': '2024-01-01T00:00:00',
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {str(e)}")
        scans_db[scan_id].update({
            'status': 'failed',
            'error_message': str(e)
        })