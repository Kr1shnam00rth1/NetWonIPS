"""
    Module to check and Block IPs based if they matched with corresponding snort rule
"""
import subprocess

def IsBlocked(ip):
    
    """ Function to check does IP already blocked or not"""
    
    try:
        
        result = subprocess.run(['sudo', 'iptables', '-L', 'INPUT', '-v', '-n'], capture_output=True, text=True, check=True)
        if ip in result.stdout:
            return True
        return False
    except subprocess.CalledProcessError as e:
        print(f"Failed to check iptables rules. Error: {e}")
        return False

def BlockIP(ip):

    """ Function to bloack ip"""
    
    if IsBlocked(ip):
        return 0
    else:
        try:
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            print(f"IP address {ip} has been blocked.")
            return 1
            
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP address {ip}. Error: {e}")
