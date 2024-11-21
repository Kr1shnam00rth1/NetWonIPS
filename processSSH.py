import datetime
import doActions

ip_failed_count={}
threshold_time=5*60


def CheckTimeDifference(start_time, current_time):
    start_time = datetime.datetime.strptime(start_time, '%H:%M:%S')
    current_time = datetime.datetime.strptime(current_time, '%H:%M:%S')
    
    start_time = start_time.replace(tzinfo=datetime.timezone.utc)
    current_time = current_time.replace(tzinfo=datetime.timezone.utc)
    
    difference_time = (current_time - start_time).total_seconds()
    return 1 if difference_time < threshold_time else 0

def MonitorSSHLogs():
    file =open("/var/log/auth.log")
    while True:
        for line in reversed(file.readlines()):
            line=line.strip().split(" ")
            if 'Failed' in line and len(line)==14:
                ip=line[10]
                timestamp=line[2]
                if ip not in ip_failed_count:
                    ip_failed_count[ip]=[1,timestamp]
                else:
                    temporary=ip_failed_count[ip]
                    if temporary[0]>5:
                        current_time=datetime.datetime.now().strftime('%H:%M:%S')
                        start_time=temporary[1]
                        result=CheckTimeDifference(start_time,current_time)
                
                        if result == 1:
                            doActions.BlockIP(ip)
                            ip_failed_count.pop(ip)
                        else:
                            ip_failed_count[ip]=[1,timestamp]
                    else:
                        failed_count=ip_failed_count[ip][0]
                        ip_failed_count[ip]=[failed_count+1,timestamp]
    file.close()

MonitorSSHLogs()