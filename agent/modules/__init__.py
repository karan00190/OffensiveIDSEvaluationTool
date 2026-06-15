# agent/modules/__init__.py
# Makes the modules/ folder a Python package.
# Exports both DGA and Exfiltration modules.

from .dga_module   import DGARunner, DGAGenerator, DGAReporter
from .exfil_module import TransferEngine, PayloadGenerator, ChunkManager

__all__ = [
    'DGARunner', 'DGAGenerator', 'DGAReporter',
    'TransferEngine', 'PayloadGenerator', 'ChunkManager',
]