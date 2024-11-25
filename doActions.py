import subprocess
 
def BlockIP(ip):

    """ Function to Drop a Packet from Certian IP address"""
    try:
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],check=True)
        print(f"Successfully blocked IP address {ip}.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to block IP address {ip}. Error: {e}")