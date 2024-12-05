from threading import Thread
import time
import os
import processSSH
import processFTP
import processPackets

def display_banner():
    banner = r"""
  ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ███╗   ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗████╗  ██║
  ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██╔██╗ ██║
  ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██║╚██╗██║
  ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║ ╚████║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═══╝

  ┌───────────────────────────────────────────────────────┐
  │          NetWon Intrusion Prevention System           │
  ├───────────────────────────────────────────────────────┤
  │   Developed by  :  Krishnamoorthi P L                 │
  │   Purpose       :  Detects and mitigates network      │
  │                    intrusions in real-time.           │
  │                                                       │
  │   Features      : - Snort rule-based detection.       │
  │                   - SSH & FTP brute force detection.  │
  │                   - Alerts, blocking, and logging.    │
  │                   - Flexible custom rule support.     │
  │                                                       │
  │   Note          :  Designed for learning and          │
  │                    experimentation in cybersecurity.  │
  └───────────────────────────────────────────────────────┘
"""
    print(banner)
    print("NetWon IPS started monitoring !!!")

if __name__ == "__main__":

    display_banner()
    time.sleep(2)
    os.system('clear')
    
    ssh_thread = Thread(target=processSSH.MonitorSSHLogs)
    ssh_thread.daemon = True
  
    
    ftp_thread =Thread(target=processFTP.MonitorFTPLogs)
    ftp_thread.daemon = True
  

    packets_thread=Thread(target=processPackets.StartSniffing)
    packets_thread.daemon = True


    ssh_thread.start()
    ftp_thread.start()
    packets_thread.start()


    
    os.system('clear')
    
    ssh_thread.join()
    ftp_thread.join()
    packets_thread.join()
