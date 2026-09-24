"""Registro de sensores disponibles."""
from xdr.collectors.auth import AuthLogCollector
from xdr.collectors.files import FileIntegrityCollector, MalwareScanCollector, RansomwareCollector
from xdr.collectors.network import NetworkCollector
from xdr.collectors.persistence import PersistenceCollector
from xdr.collectors.posture import PostureCollector
from xdr.collectors.process import ProcessCollector
from xdr.collectors.system import AccountCollector, DeviceCollector, KernelCollector, ResourceCollector

REGISTRY = {
    "process": ProcessCollector,
    "network": NetworkCollector,
    "fim": FileIntegrityCollector,
    "malware_scan": MalwareScanCollector,
    "ransomware": RansomwareCollector,
    "auth": AuthLogCollector,
    "persistence": PersistenceCollector,
    "accounts": AccountCollector,
    "kernel": KernelCollector,
    "devices": DeviceCollector,
    "resources": ResourceCollector,
    "posture": PostureCollector,
}

__all__ = ["REGISTRY"]
