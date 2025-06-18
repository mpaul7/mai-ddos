from typing import Dict, Any
import pandas as pd

from .pyshark_extractor import PySharkExtractor

class PCAPExtract:
    """Main class for parsing from PCAP packet data"""
    
    def __init__(self):
        self.extractors = {
            'pyshark': PySharkExtractor(),
        }

    
    def extract_data(self, pcap_file: str) -> pd.DataFrame:
        """Extract packet metadata from pcap file using multiple extractors
        
        Args:
            pcap_file: Path to pcap file
            
        Returns:
            pd.DataFrame: Combined features from all extractors
        """
        df_pyshark = self.extractors['pyshark'].extract(pcap_file)
        
        return df_pyshark 