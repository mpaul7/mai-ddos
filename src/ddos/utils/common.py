pyshark_columns = [ 'bucket', 'time_difference_seconds', 'first_timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 
                    'fwd_packets', 'bwd_packets', 'total_packets',
                    'fwd_bytes', 'bwd_bytes', 'total_bytes', 
                    'total_dns_queries', 'total_dns_responses', 
                    'dns_query', 'dns_answer', 'dns_rcode', 'dns_rcode_name',
                    'first_timestamp', 'last_timestamp', 'flow_duration',
                    'dns_delay_avg', 'dns_delay_min', 'dns_delay_max', 'dns_query_response_delays', 
                    'dpending_queries', 'dns_query_response_pairs', 'dns_unmatched_queries',
                    'total_unmatched_queries'
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