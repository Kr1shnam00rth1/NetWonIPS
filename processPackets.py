"""
    Module to capture packets on a specified interface and extract details from each.
"""
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest
#import storeLogs
#import matchRules

def GetUrl(packet):

    """Funtion to Extract the URL from an HTTP request packet."""

    if packet.haslayer(HTTPRequest):
        return packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
    return None

def ProcessPackets(packet):

    """Function to Extract key parameter from a packet"""
    
    packet_info = {
        'protocol': None,
        'source_ip': None,
        'destination_ip': None,
        'source_port': None,
        'destination_port': None,
        'flags': None,
        'icode': None,
        'itype': None,
        'payload': None,
        'url': None,
        'time': None,
    }
    if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP) or packet.haslayer(ICMP)):
        
        packet_info['source_ip'] = packet[IP].src
        packet_info['destination_ip'] = packet[IP].dst
    
        if packet.haslayer(TCP):
            packet_info['protocol'] = 'tcp'
            packet_info['source_port'] = packet[TCP].sport
            packet_info['destination_port'] = packet[TCP].dport
            packet_info['flags'] = packet[TCP].flags

        elif packet.haslayer(UDP):
            packet_info['protocol'] = 'udp'
            packet_info['source_port'] = packet[UDP].sport
            packet_info['destination_port'] = packet[UDP].dport

        elif packet.haslayer(ICMP):
            packet_info['protocol'] = 'icmp'
            packet_info['icode'] = packet[ICMP].code
            packet_info['itype'] = packet[ICMP].type
    
        packet_info['payload'] = bytes(packet.payload)
        packet_info['time'] = packet.time
    
        if packet.haslayer(HTTPRequest):
            packet_info['url'] = GetUrl(packet)
        print(packet_info)
        return
        #storeLogs.TrafficLogs(packet_info)
        #matchRules.MatchRules(packet_info)

def StartSniffing():

    """Function to Sniffs packets and sends each to the process_packet function."""  
    
    sniff(iface="wlo1",prn=ProcessPackets,count=2)

StartSniffing()