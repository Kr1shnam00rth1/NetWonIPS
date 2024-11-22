from threading import Thread
import time
import os
import processSSH
#import processFTP

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

def clear_terminal():
        os.system('clear')

if __name__ == "__main__":
    display_banner()
    time.sleep(10)
    clear_terminal()
    
    #ssh_thread = Thread(target=processSSH.MonitorSSHLogs)
    #ftp_thread =Thread(target=processFTP.MonitorFTPLogs)

    #ssh_thread.start()
    #ftp_thread.start()

    #ssh_thread.join()
    #ftp_thread.join()
