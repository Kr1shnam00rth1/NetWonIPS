import subprocess
 
def BlockIP(ip):
    try:
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],check=True)
        print(f"IP address {ip} has been blocked.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to block IP address {ip}. Error: {e}")