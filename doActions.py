"""
    Module to check and Block IPs based if they matched with corresponding snort rule
"""
import subprocess

def IsIncommingBlocked(ip):
    
    """ Function to check does IP already blocked or not"""
    
    try:
        
        result = subprocess.run(['sudo', 'iptables', '-L', 'INPUT', '-v', '-n'], capture_output=True, text=True, check=True)
        if ip in result.stdout:
            return True
        return False
    except subprocess.CalledProcessError as e:
        print(f"Failed to check iptables rules. Error: {e}")
        return False

def IsOutgoingBlocked(ip):
    
    """ Function to check does IP already blocked or not"""
    
    try:
        
        result = subprocess.run(['sudo', 'iptables', '-L', 'OUTPUT', '-v', '-n'], capture_output=True, text=True, check=True)
        if ip in result.stdout:
            return True
        return False
    except subprocess.CalledProcessError as e:
        print(f"Failed to check iptables rules. Error: {e}")
        return False

def IncommingIpBlock(ip):

    """ Function to bloack ip"""
    
    if IsIncommingBlocked(ip):
        return 0
    else:
        try:
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            print(f"IP address {ip} has been blocked check logs.")
            return 1
            
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP address {ip}. Error: {e}")


def OutgoingIpBlock(ip):

    """ Function to bloack ip"""
    
    if IsOutgoingBlocked(ip):
        return 0
    else:
        try:
            subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-s', ip, '-j', 'DROP'], check=True)
            print(f"IP address {ip} has been blocked check logs.")
            return 1
            
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP address {ip}. Error: {e}")
