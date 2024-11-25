import subprocess
 
def BlockIP(ip):
    try:
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to block IP address {ip}. Error: {e}")