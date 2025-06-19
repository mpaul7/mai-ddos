import pandas as pd
import socket

pyshark_columns = [ 'bucket', 'time_difference_seconds', 'first_timestamp', 'last_timestamp',  
                    'sip', 'sport', 'dip', 'dport', 'protocol', 
                    'fwd_packets', 'bwd_packets', 'total_packets',
                    'fwd_bytes', 'bwd_bytes', 'total_bytes', 
                    'total_dns_queries', 'total_dns_responses', 
                    # 'dns_query', 'dns_answer', 'dns_rcode', 
                    'dns_rcode_name',
                    'first_timestamp', 'last_timestamp', 'flow_duration',
                    'dns_delay_avg', 'dns_delay_min', 'dns_delay_max', 'dns_query_response_delays', 
                    'dpending_queries', 'dns_query_response_pairs', 'dns_unmatched_queries',
                    'total_unmatched_queries'
                    ]

aggregated_columns = [ 'bucket', 
# 'first_timestamp_min', 'last_timestamp_max', 
'source_ip_count', 'source_ip_unique', 'desination_ip_unique', 'dns_query_response_pairs', 'dns_query_response_count', 'dns_flow_duration',
 'dns_query_response_delays_agg', 'dns_fwd_bytes', 'dns_bwd_bytes', 'dns_fwd_packets', 'dns_bwd_packets'
# 'destination_ip_count', 
                    #   'source_port_count', 'destination_port_count', 'protocol_count', 
                    #   'fwd_packets_count', 'bwd_packets_count', 
                    #   'total_packets_count', 'fwd_bytes_count', 'bwd_bytes_count', 'total_bytes_count', 'total_dns_queries_count', 
                    #   'total_dns_responses_count', 'dns_query_count', 'dns_answer_count', 'dns_rcode_count', 'dns_rcode_name_count', 
                    #   'dns_delay_avg_count', 'dns_delay_min_count', 'dns_delay_max_count', 'dpending_queries_count', 
                    #   'dns_query_response_pairs_count', 'dns_unmatched_queries_count', 'total_unmatched_queries_count'
                      ]

# DNS RCODE mapping
DNS_RCODE_MAP = {
        0: "NoError",
        1: "FormErr",
        2: "ServFail",
        3: "NXDomain",
        4: "NotImp",
        5: "Refused",
        6: "YXDomain",
        7: "YXRRSet",
        8: "NXRRSet",
        9: "NotAuth",
        10: "NotZone",
        11: "DSOTYPENI",
        # 12-15 are reserved
    }

def ip_swap(df: pd.DataFrame)->pd.DataFrame:
    """
    Swap if the sip is public and the dip is private,
    or if both addresses have the same privacy levels, swap if the sip is well known
    """
    def in_classA_private(ip):
        return ((ip & 0xFF000000) == 0x0A000000)

    def in_classB_private(ip):
        return ((ip & 0xFFF00000) == 0xAC100000)

    def in_classC_private(ip):
        return ((ip & 0xFFFF0000) == 0xC0A80000)

    def in_private(ip):
        return in_classA_private(ip) or in_classB_private(ip) or in_classC_private(ip)

    WELL_KNOWN_PORTS = [1311, 5986, 8243, 8333, 8531, 8888, 9443, 5985, 8000, 8008, 8080, 8243, 8403, 8530, 8887, 9080,
                        16080]

    # method to check if the port is wellknown
    def is_wellknown(port):
        return ((port < 1024) | (port in WELL_KNOWN_PORTS))

    # method to convert ip address to bytes then to int
    def convert_to_int(ip):
        try:
            ip_bin = socket.inet_pton(socket.AF_INET, ip)
            ip_int = int.from_bytes(ip_bin, byteorder='big')
            return ip_int
        except socket.error:
            return False  # Handle invalid IP addresses

    # IP comparison columns
    df['sip_int'] = df.sip.apply(convert_to_int)
    df['dip_int'] = df.dip.apply(convert_to_int)

    # swap if the sip is public and the dip is private
    swap_ind = df.loc[(df['sip_int'].apply(in_private) == False) & (df['dip_int'].apply(in_private) == True)].index
    # or if both addresses have the same privacy levels, swap if the sip is well known
    swap_ind = swap_ind.append(df.loc[(df['sip_int'].apply(in_private) == df['dip_int'].apply(in_private)) & (
                df.sport.apply(is_wellknown) == True)].index)

    # swap the column name for the rows that meet the above criteria
    df_ip_swapped = df.loc[swap_ind].rename(columns={'sip': 'dip', 'sport': 'dport', 'dip': 'sip', 'dport': 'sport'})
    # replace the data needs to be updated with swapped ip
    df.loc[swap_ind] = df_ip_swapped

    df.drop(columns=['sip_int', 'dip_int'], inplace=True)

    return df