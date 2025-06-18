"""Core functionality for DDoS detection."""
import pandas as pd
import pyshark
from .extractors.packet_extraction import PCAPExtract

def extract_data(pcap_path):
    """Extract relevant features from a PCAP file.
    
    Args:
        pcap_path: Path to the PCAP file
        
    Returns:
        pandas.DataFrame: Extracted features
    """
    extractor = PCAPExtract()
    df = extractor.extract_data(pcap_path)
    
    return df