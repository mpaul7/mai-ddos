"""Base class for packet extractors."""
from abc import ABC, abstractmethod
import pandas as pd

class BaseExtractor(ABC):
    """Abstract base class for packet extractors."""
    
    @abstractmethod
    def extract(self, pcap_file: str) -> pd.DataFrame:
        """Extract features from a PCAP file.
        
        Args:
            pcap_file: Path to the PCAP file
            
        Returns:
            pd.DataFrame: Extracted features
        """
        pass 