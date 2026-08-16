from scans.scanners.placeholders.placeholder_scanner import PlaceholderScanner
from scans.scanners.placeholders.not_implemented_scanner import NotImplementedScanner
from scans.scanners.network.network_recon import NetworkReconScanner

class ScannerRegistry:
    # Registrations map keys to their execution implementations
    _registry = {
        'web_security_headers_test': PlaceholderScanner,
        'sast_test': PlaceholderScanner,
        'network_recon': NetworkReconScanner,
        'network_recon_test': NetworkReconScanner,
    }

    @classmethod
    def register(cls, key, scanner_class):
        cls._registry[key] = scanner_class

    @classmethod
    def get_scanner(cls, key, context):
        scanner_class = cls._registry.get(key)
        if scanner_class:
            return scanner_class(context)
        # Fallback to not implemented skip engine
        return NotImplementedScanner(context)
