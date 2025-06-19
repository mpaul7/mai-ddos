

from .extractors.packet_extraction import PCAPExtract
from .bucketize.bucketize import Bucketize

def extract_data(pcap_path):
    """Extract relevant features from a PCAP file.
    
    Args:
        pcap_path: Path to the PCAP file
        
    Returns:
        pandas.DataFrame: Extracted features
    """
    # extract the data
    extractor = PCAPExtract()
    df = extractor.extract_data(pcap_path)
    
    # bucketize the data
    bucketizer = Bucketize(df)
    df = bucketizer.bucketize()
    
    return df

