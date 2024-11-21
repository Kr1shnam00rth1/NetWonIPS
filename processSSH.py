import datetime
import doActions
import makeLogs
import time

ip_failed_count = {}
threshold_time = 5 * 60
threshold_count = 5

def CheckTimeDifference(start_time, current_time):

    """Function to Check if the time difference between the first packet and the current packet is within the threshold."""
    
    start_time = datetime.datetime.strptime(start_time, '%H:%M:%S')
    current_time = datetime.datetime.strptime(current_time, '%H:%M:%S')

    start_time = start_time.replace(tzinfo=datetime.timezone.utc)
    current_time = current_time.replace(tzinfo=datetime.timezone.utc)

    difference_time = (current_time - start_time).total_seconds()
    return 1 if difference_time < threshold_time else 0

def MonitorSSHLogs():

    """Function to Monitor the SSH logs to detect failed login attempts, and block IPs exceeding the threshold count within the threshold time."""
    
    file = open("/var/log/auth.log")
    file.seek(0,2)
    while True:
        for line in file.readlines():
            line = line.strip().split(" ")
            if 'Failed' in line and len(line) == 14:
                ip = line[10]
                timestamp = line[2]
                if ip not in ip_failed_count:
                    ip_failed_count[ip] = [1, timestamp]
                else:
                    temporary = ip_failed_count[ip]
                    if temporary[0] > threshold_count:
                        current_time = datetime.datetime.now().strftime('%H:%M:%S')
                        start_time = temporary[1]
                        result = CheckTimeDifference(start_time, current_time)

                        if result == 1:
                            doActions.BlockIP(ip)
                            makeLogs.Attacklogs(f'SSH Bruteforce IP {ip} Blocked',None)
                            ip_failed_count.pop(ip)
                            ip=None
                        else:
                            ip_failed_count[ip] = [1, timestamp]
                    else:
                        failed_count = ip_failed_count[ip][0]
                        ip_failed_count[ip] = [failed_count + 1, timestamp]
    file.close()
0