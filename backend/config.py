import os


class Config:
    SCAN_MODE = os.getenv("AUTOMAZIOR_SCAN_MODE", "standard")
    MAX_WORKERS = int(os.getenv("AUTOMAZIOR_MAX_WORKERS", 5))
    ENABLE_NMAP = os.getenv("AUTOMAZIOR_ENABLE_NMAP", "true").lower() == "true"
    NMAP_TIMEOUT = int(os.getenv("AUTOMAZIOR_NMAP_TIMEOUT", 60))


config = Config()

