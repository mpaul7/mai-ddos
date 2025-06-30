import pandas as pd

class Aggregator:
    def __init__(self, df):
        self.df = df

    def aggregate(self):
        df = self.df.copy()

        # Add conversation pair as a tuple column
        df['conversation_pair'] = list(zip(df['sip'], df['dip']))

        # Group by bucket and aggregate
        df_agg = df.groupby('bucket').agg(
            source_ip_count=('sip', 'size'),
            source_ip_unique=('sip', 'nunique'),
            desination_ip_unique=('dip', 'nunique'),
            dns_flows_count=('dns_query_response_pairs', 'size'),
            dns_query_response_delays_agg=('dns_query_response_delays', lambda x: sum(x, [])),
            dns_flow_duration=('flow_duration', lambda x: x.tolist()),
            dns_fwd_bytes=('fwd_bytes', lambda x: x.tolist()),
            dns_bwd_bytes=('bwd_bytes', lambda x: x.tolist()),
            dns_fwd_packets=('fwd_packets', lambda x: x.tolist()),
            dns_bwd_packets=('bwd_packets', lambda x: x.tolist()),
            conversation_counts=('conversation_pair', lambda x: pd.Series(x).value_counts().to_dict())
        ).reset_index()

        df_agg['dns_query_response_count'] = df_agg['dns_query_response_delays_agg'].apply(lambda x: len(x))

        return df_agg