"""
    Module to Detect FTP Brute Force Attack
"""
import datetime
import doActions
import storeLogs
import time
import re

ip_failed_count = {}
threshold_time = 5 * 60  
threshold_count = 5

def CheckTimeDifference(start_time, current_time):

    """Function to check if the time difference between the first packet and the current packet is within the threshold."""
    
    s_hour, s_min, s_second = map(int, start_time.split(":"))
    c_hour, c_min, c_second = map(int, current_time.split(":"))
    start_time = s_hour * 3600 + s_min * 60 + s_second
    current_time = c_hour * 3600 + c_min * 60 + c_second
    difference_time = (current_time - start_time)
    if difference_time < threshold_time:
        return 1
    return 0
    
def MonitorFTPLogs():
    """Function to monitor the FTP logs to detect failed login attempts and block IPs exceeding the threshold count within the threshold time."""
    
    file = open("/var/log/vsftpd.log",mode="r")
    file.seek(0, 2)
    failed_login_pattern = re.compile(r'FAIL LOGIN: Client "(\d+\.\d+\.\d+\.\d+)"')
    timestamp_regex = r"(\d{2}:\d{2}:\d{2})"  
    
    while True:
        line = file.readline()
        if line:
            line = line.strip()
            
            if 'FAIL LOGIN' in line:
                match = failed_login_pattern.search(line)
                
                if match:
                    ip = match.group(1)
                    time_match = re.search(timestamp_regex, line)
                
                    if time_match:
                        timestamp = time_match.group(1)  

                        if ip not in ip_failed_count:
                            ip_failed_count[ip] = [1, timestamp]
                        else:
                            temporary = ip_failed_count[ip]
                            if temporary[0] >= threshold_count:
                                current_time = datetime.datetime.now().strftime('%H:%M:%S')
                                start_time = temporary[1]
                                result = CheckTimeDifference(start_time, current_time)

                                if result == 1:
                                    doActions.BlockIP(ip)
                                    storeLogs.AttackLogs(f'FTP Bruteforce IP {ip} Blocked', None)
                                    ip_failed_count.pop(ip)
                                    
                                else:
                                    ip_failed_count[ip] = [1, timestamp]  
                            else:
                                failed_count = ip_failed_count[ip][0]
                                ip_failed_count[ip] = [failed_count + 1, timestamp]
        
    file.close()

