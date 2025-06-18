"""PyShark-based packet extraction for DNS analysis."""
import pyshark
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, Any, Tuple
from ..utils.common import DNS_RCODE_MAP
from ..utils.logger import setup_logger
from .base_extractor import BaseExtractor

# Configure logging
logger = setup_logger(__name__)

class PySharkExtractor(BaseExtractor):
    """Extracts DNS flow features using PyShark"""
    
    def _get_flow_key(self, sip: str, sport: str, dip: str, dport: str, protocol: str) -> Tuple[str, str]:
        """Generate forward and backward flow keys.
        
        Args:
            sip: Source IP
            sport: Source port
            dip: Destination IP
            dport: Destination port
            protocol: Protocol number
            
        Returns:
            Tuple[str, str]: Forward and backward flow keys
        """
        forward = f"{sip}:{sport}-{dip}:{dport}-{protocol}"
        backward = f"{dip}:{dport}-{sip}:{sport}-{protocol}"
        return forward, backward
    
    def _init_flow_stats(self, timestamp: datetime) -> Dict[str, Any]:
        """Initialize flow statistics.
        
        Args:
            timestamp: Packet timestamp
            
        Returns:
            Dict[str, Any]: Initial flow statistics
        """
        return {
            'src_ip': '',
            'src_port': '',
            'dst_ip': '',
            'dst_port': '',
            'protocol': '',
            'first_timestamp': timestamp,
            'last_timestamp': timestamp,
            'fwd_packets': 0,
            'bwd_packets': 0,
            'fwd_bytes': 0,
            'bwd_bytes': 0,
            'total_packets': 0,
            'total_bytes': 0,
            'flow_duration': 0,
            'total_dns_queries': 0,
            'total_dns_responses': 0,
            'dns_query': '',
            'dns_answer': '',
            'dns_rcode': [],
            'dns_rcode_name': [],
            'dns_query_response_delays': [],
            'dpending_queries': [],
            'dns_unmatched_queries': [],
            'total_unmatched_queries': 0,
            'dns_delay_avg': 0.0,
            'dns_delay_min': 0.0,
            'dns_delay_max': 0.0,
            'dns_query_response_pairs': []
        }
    
    def _extract_dns_flow(self, pcap_file: str) -> Dict[str, Any]:
        """Extract DNS flow features from a packet."""
        # logger.info(f"Starting DNS flow extraction from: {pcap_file}")
        pcap = pyshark.FileCapture(pcap_file)
        flows = {}
        packet_count = 0

        for pkt in pcap:
            try:
                packet_count += 1
                if packet_count % 1000 == 0:
                    logger.debug(f"Processed {packet_count} packets")

                if not hasattr(pkt, 'ip'):
                    continue

                sip = pkt.ip.src
                dip = pkt.ip.dst
                protocol = pkt.ip.proto
                timestamp = datetime.fromtimestamp(float(pkt.sniff_timestamp))
                pkt_length = int(pkt.length)

                if protocol != '17' or not hasattr(pkt, 'udp'):
                    continue

                sport = pkt.udp.srcport
                dport = pkt.udp.dstport

                if sport != '53' and dport != '53':
                    continue

                fwd_key, bwd_key = self._get_flow_key(sip, sport, dip, dport, protocol)

                if fwd_key in flows:
                    flow_key = fwd_key
                    is_forward = True
                elif bwd_key in flows:
                    flow_key = bwd_key
                    is_forward = False
                else:
                    flow_key = fwd_key
                    is_forward = True
                    flows[flow_key] = self._init_flow_stats(timestamp)
                    flows[flow_key].update({
                        'src_ip': sip,
                        'src_port': sport,
                        'dst_ip': dip,
                        'dst_port': dport,
                        'protocol': protocol
                    })
                    logger.debug(f"Created new flow: {flow_key}")

                flow = flows[flow_key]
                flow['last_timestamp'] = max(flow['last_timestamp'], timestamp)

                if is_forward:
                    flow['fwd_packets'] += 1
                    flow['fwd_bytes'] += pkt_length
                else:
                    flow['bwd_packets'] += 1
                    flow['bwd_bytes'] += pkt_length

                flow['total_packets'] = flow['fwd_packets'] + flow['bwd_packets']
                flow['total_bytes'] = flow['fwd_bytes'] + flow['bwd_bytes']

                if hasattr(pkt, 'dns') and hasattr(pkt.dns, 'flags'):
                    dns_flags = getattr(pkt.dns, 'flags', '0x0000')
                    dns_flags_int = int(dns_flags, 16)
                    is_response = (dns_flags_int & 0x8000) != 0

                    rcode = getattr(pkt.dns, 'rcode', '0')
                    rcode_text = DNS_RCODE_MAP.get(int(rcode), 'Unknown')
                    flow['dns_rcode_name'].append(f'{rcode}_{rcode_text}')
                    flow['dns_rcode'].append(rcode)

                    if not is_response:  # DNS query
                        flow['total_dns_queries'] += 1
                        if not flow['dns_query'] and hasattr(pkt.dns, 'qry_name'):
                            flow['dns_query'] = pkt.dns.qry_name
                        if hasattr(pkt.dns, 'id'):
                            flow['dpending_queries'].append({
                                'id': pkt.dns.id,
                                'query_time': timestamp
                            })

                    else:  # DNS response
                        flow['total_dns_responses'] += 1
                        if not flow['dns_answer']:
                            qry_type = getattr(pkt.dns, 'qry_type', '0')
                            if qry_type == '1' and hasattr(pkt.dns, 'a'):
                                flow['dns_answer'] = pkt.dns.a
                            elif qry_type == '28' and hasattr(pkt.dns, 'aaaa'):
                                flow['dns_answer'] = pkt.dns.aaaa
                            elif qry_type == '5' and hasattr(pkt.dns, 'cname'):
                                flow['dns_answer'] = pkt.dns.cname

                        if hasattr(pkt.dns, 'id'):
                            matching_query = next(
                                (q for q in flow['dpending_queries'] if q['id'] == pkt.dns.id),
                                None
                            )
                            if matching_query:
                                delay = (timestamp - matching_query['query_time']).total_seconds()
                                flow['dns_query_response_delays'].append(delay)
                                flow['dns_query_response_pairs'].append({
                                    'id': pkt.dns.id,
                                    'query_time': matching_query['query_time'].isoformat(),
                                    'response_time': timestamp.isoformat(),
                                    'delay': round(delay, 6)
                                })
                                flow['dpending_queries'].remove(matching_query)

            except Exception as e:
                logger.error(f"Error processing packet {packet_count}: {str(e)}")
                continue

        # logger.info(f"Completed DNS flow extraction. Processed {packet_count} packets, found {len(flows)} flows")
        return flows
    
    def extract(self, pcap_file: str) -> pd.DataFrame:
        """Extract DNS flow features from a PCAP file.
        
        Args:
            pcap_file: Path to the PCAP file
            
        Returns:
            pd.DataFrame: Extracted DNS flow features
        """
        # logger.info(f"Starting feature extraction from PCAP file: {pcap_file}")
        flows = self._extract_dns_flow(pcap_file)
        
        # Convert flows to DataFrame
        df = pd.DataFrame.from_dict(flows, orient='index')
        
        if len(df) == 0:
            logger.warning("No DNS flows found in the PCAP file")
            # Return empty DataFrame with correct columns if no flows found
            return pd.DataFrame(columns=[
                'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
                'first_timestamp', 'last_timestamp', 'fwd_packets', 'bwd_packets',
                'fwd_bytes', 'bwd_bytes', 'total_packets', 'total_bytes',
                'flow_duration', 'total_dns_queries', 'total_dns_responses',
                'dns_query', 'dns_answer', 'dns_rcode', 'dns_rcode_name',
                'dns_delay_avg', 'dns_delay_min', 'dns_delay_max',
                'dns_query_response_delays', 'dpending_queries', 'dns_query_response_pairs', 'dns_unmatched_queries', 'total_unmatched_queries'
            ])
        
        # Convert timestamps to Unix timestamps (seconds since epoch)
        df['first_timestamp'] = pd.to_datetime(df['first_timestamp']).astype(np.int64) // 1000  # Convert nanoseconds to microseconds
        df['last_timestamp'] = pd.to_datetime(df['last_timestamp']).astype(np.int64) // 1000  # Convert nanoseconds to microseconds
        
        # Calculate total packets and bytes
        df['total_packets'] = df['fwd_packets'] + df['bwd_packets']
        df['total_bytes'] = df['fwd_bytes'] + df['bwd_bytes']
        
        # Calculate flow duration in seconds
        df['flow_duration'] = (df['last_timestamp'] - df['first_timestamp']) / 10**6
        
        return df
    