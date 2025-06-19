"""Command line interface for DDoS detection."""
import click
import os
from pathlib import Path
import logging
from .core import extract_data
from .utils.common import pyshark_columns
from .utils.logger import setup_logger

# Configure logging
logger = setup_logger(__name__)


@click.group()
def cli():
    """DDoS detection tool for analyzing network traffic."""
    pass


@cli.command(name='analyze')
@click.argument('pcap', type=click.Path(exists=True))
@click.argument('output', type=click.Path())
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
def ddos_analyze(pcap, output, verbose):
    """Analyze a PCAP file for DDoS attacks.
    
    Args:
        pcap: Path to the PCAP file to analyze
        output: Path to save the analysis results
        verbose: Enable verbose logging
    """
    if verbose:
        logger.setLevel(logging.DEBUG)
        
    logger.info(f"Starting PCAP file: {pcap}")
    logger.debug(f"Output will be saved to: {output}")
    
    df = extract_data(pcap)
    logger.info(f"Found  {len(df)} DNS flows")
    
    # Ensure output directory exists
    output_path = Path(output)
    if output_path.is_dir():
        # If output is a directory, create a filename based on the input pcap
        pcap_name = Path(pcap).stem
        output_path = output_path / f"{pcap_name}_dns_flows.csv"
        logger.debug(f"Output is a directory, will save to: {output_path}")
    
    # Create parent directories if they don't exist
    output_path.parent.mkdir(parents=True, exist_ok=True)
    logger.debug(f"Ensured output directory exists: {output_path.parent}")
    
    logger.info(f"Saving results to: {output_path}")
    df.to_csv(output_path, index=False, columns=pyshark_columns)
