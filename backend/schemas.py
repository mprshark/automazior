from pydantic import BaseModel

class ScanRequest(BaseModel):
    domain: str
