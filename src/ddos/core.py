

from .extractors.packet_extraction import PCAPExtract
from .bucketize.bucketize import Bucketize
from .bucketize.aggregator import Aggregator
from .utils.common import ip_swap

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

    def correct_dns_direction(row):
        if row['dport'] != 53:
            # Swap IPs
            row['sip'], row['dip'] = row['dip'], row['sip']
            # Swap ports
            row['sport'], row['dport'] = row['dport'], row['sport']
            # Swap forward/backward packet & byte values
            row['fwd_packets'], row['bwd_packets'] = row['bwd_packets'], row['fwd_packets']
            row['fwd_bytes'], row['bwd_bytes'] = row['bwd_bytes'], row['fwd_bytes']
        return row

# Apply the correction
    df = df.apply(correct_dns_direction, axis=1)
    # df = ip_swap(df)
    
    # bucketize the data
    bucketizer = Bucketize(df)
    df_bucketized = bucketizer.bucketize()

    # aggregate the data
    aggregator = Aggregator(df_bucketized)
    df_aggregated = aggregator.aggregate()
    print(df_aggregated.columns)
    
    return  df_bucketized, df_aggregated
