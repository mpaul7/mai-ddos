import pandas as pd


class Bucketize:
    def __init__(self, df):
        self.df = df


    def bucketize(self):
        
        df = self.df.sort_values(by='first_timestamp', ascending=True)
        
        df['time_difference_seconds'] = df['first_timestamp'] - df['first_timestamp'].iloc[0]
        
        max_time = df['time_difference_seconds'].max()
        
        bins = list(range(0, int(max_time) + 30, 30))
        
        df['bucket'] = pd.cut(
            df['time_difference_seconds'], 
            bins=bins, 
            labels=range(len(bins)-1),
            right=True
        )
        
        return df