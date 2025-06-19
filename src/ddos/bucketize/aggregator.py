

class Aggregator:
    def __init__(self, df):
        self.df = df

    def aggregate(self):
        df = self.df.copy()
        df = df.groupby('bucket').agg(
            source_ip_count=('sip', 'size'),
            source_ip_unique=('sip', 'nunique'),
            desination_ip_unique=('dip', 'nunique'),
            dns_query_response_pairs=('dns_query_response_pairs', 'size'),
            dns_query_response_delays_agg=('dns_query_response_delays', lambda x: sum(x, [])),
            dns_flow_duration=('flow_duration', lambda x: x.tolist()),
            dns_fwd_bytes=('fwd_bytes', lambda x: x.tolist()),
            dns_bwd_bytes=('bwd_bytes', lambda x: x.tolist()),
            dns_fwd_packets=('fwd_packets', lambda x: x.tolist()),
            dns_bwd_packets=('bwd_packets', lambda x: x.tolist()),

            
        ).reset_index()

        df['dns_query_response_count'] = df['dns_query_response_delays_agg'].apply(lambda x: len(x))

        return df