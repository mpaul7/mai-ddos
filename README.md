# DNS Traffic Analysis Tool

## Description

A Python-based DNS traffic analysis tool that processes PCAP files to extract and analyze DNS flow features. The tool provides detailed insights into DNS traffic patterns by analyzing query-response pairs, timing statistics, and flow characteristics.

Key Features:
- DNS flow extraction using PyShark
- Bidirectional flow tracking
- Query-response pair matching
- Response time analysis
- Comprehensive DNS feature extraction
- CSV output format for further analysis

## Setup and Installation

### Prerequisites
- Python 3.8 or higher
- tshark/Wireshark (for packet capture analysis)
- pip (Python package installer)

### Python Virtual Environment Setup

1. Create a new virtual environment:
```bash
# Using venv
python -m venv venv
source venv/bin/activate

```

2. Install the package in development mode:
```bash
# Install required dependencies
pip install -r requirements.txt

# Install the package in editable mode
pip install -e .
```

### Installation Verification
To verify the installation:
```bash
python -m ddos --help
```


## Usage

### Basic Usage
```bash
# Analyze a PCAP file
python -m ddos analyze input.pcap output.csv

# Enable verbose logging
python -m ddos analyze -v input.pcap output.csv
```

### Output Description

The tool generates a CSV file containing the following DNS flow features:

#### Flow Identification
- `src_ip`: Source IP address
- `src_port`: Source port number
- `dst_ip`: Destination IP address
- `dst_port`: Destination port number
- `protocol`: Protocol number (UDP=17)

#### Timing Information
- `first_timestamp`: First packet timestamp (microseconds since epoch)
- `last_timestamp`: Last packet timestamp (microseconds since epoch)
- `flow_duration`: Flow duration in seconds

#### Packet Statistics
- `fwd_packets`: Number of forward direction packets
- `bwd_packets`: Number of backward direction packets
- `total_packets`: Total number of packets in the flow
- `fwd_bytes`: Number of bytes in forward direction
- `bwd_bytes`: Number of bytes in backward direction
- `total_bytes`: Total number of bytes in the flow

#### DNS-Specific Features
- `total_dns_queries`: Total number of DNS queries
- `total_dns_responses`: Total number of DNS responses
- `dns_query`: DNS query name
- `dns_answer`: DNS response answer
- `dns_rcode`: DNS response codes
- `dns_rcode_name`: DNS response code names
- `dns_delay_avg`: Average query-response delay (seconds)
- `dns_delay_min`: Minimum query-response delay (seconds)
- `dns_delay_max`: Maximum query-response delay (seconds)
- `total_unmatched_queries`: Number of queries without matching responses

