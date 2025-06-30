

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
    df.to_csv('df.csv', index=False)

    def correct_dns_direction(row):
        if row['dport'] != 53:
            return {
                'sip': row['dip'],
                'sport': row['dport'],
                'dip': row['sip'],
                'dport': row['sport'],
                'protocol': row['protocol'],
                'fwd_packets': row['bwd_packets'],
                'bwd_packets': row['fwd_packets'],
                'fwd_bytes': row['bwd_bytes'],
                'bwd_bytes': row['fwd_bytes']
            }
        return row


# Apply the correction
    # df = df.apply(correct_dns_direction, axis=1, result_type='expand')

    df = ip_swap(df)
    
    # bucketize the data
    bucketizer = Bucketize(df)
    df_bucketized = bucketizer.bucketize()

    # aggregate the data
    aggregator = Aggregator(df_bucketized)
    df_aggregated = aggregator.aggregate()
    print(df_aggregated.columns)
    
    return  df, df_bucketized, df_aggregated
