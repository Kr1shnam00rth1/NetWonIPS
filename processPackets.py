"""
    Module to capture packets on a specified interface and extract details from each.
"""

from scapy.all import sniff
import matchRules

def ProcessPackets(packet):

    source_ip=
    destination_ip=
    source_port=
    destination_port=


def StartSniffing():

    """Function to Sniffs packets and sends each to the process_packet function."""  
    
    sniff(iface="wlo1",prn=ProcessPackets)
