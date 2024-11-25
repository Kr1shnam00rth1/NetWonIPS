import subprocess

def IsBlocked(ip):

    """Check if the given IP address is already blocked in iptables."""
    
    try:
        result = subprocess.run(['sudo', 'iptables', '-L', 'INPUT', '-v', '-n'], 
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
        
        if ip in result.stdout:
            return True
        else:
            return False
    except subprocess.CalledProcessError as e:
        print(f"Failed to check iptables rules. Error: {e}")
        return False

def DropIP(ip):

    """Function to block a packet from a certain IP address."""
    
    if IsBlocked(ip):
        print(f"IP address {ip} is already blocked.")
        return 0
    else:
        try:
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            print(f"Successfully blocked IP address {ip}.")
            return 1
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP address {ip}. Error: {e}")
