import threading
import processSSH

t1=threading.Thread(target=processSSH.MonitorSSHLogs)
t1.start()