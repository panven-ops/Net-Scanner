from pydantic import BaseModel

class ScanRequest(BaseModel):
    target: str

class PortInfo(BaseModel):
    port: int
    state: str
    service: str
    risk: str

class ScanResult(BaseModel):
    target: str
    ip: str
    is_up: bool
    ports: list[PortInfo]
    total_score: int
    verdict: str
    error: str = ""
