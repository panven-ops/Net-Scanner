import asyncio
from models import ScanRequest, ScanResult
from checks.nmap_scanner import run_nmap_scan


async def analyze(request: ScanRequest):

    result = await asyncio.to_thread(run_nmap_scan, request.target)

    return result
