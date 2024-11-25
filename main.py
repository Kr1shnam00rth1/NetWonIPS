"""
    Main Module Entry point; coordinates all modules.
"""

from threading import Thread
import time
import os
import processSSH
import processFTP
import processPackets

def display_banner():

    """Module to Display Banner Information"""

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

if __name__ == "__main__":
     
    """Main Code to invoke all the modules, to run a separate threads"""
    
    display_banner()
    time.sleep(2)
    os.system('clear')
    
    ssh_thread = Thread(target=processSSH.MonitorSSHLogs)
    print("SSH Monitoring Started")

    ftp_thread =Thread(target=processFTP.MonitorFTPLogs)
    print("FTP Monitoring Started")
    
    packets_thread= Thread(target=processPackets.StartSniffing)
    print("Packet Processing for Snort Rule Matching Stated")
    
    time.sleep(2)
    os.system('clear')
    
    ssh_thread.start()
    ftp_thread.start()
    packets_thread.start()
    
    ssh_thread.join()
    ftp_thread.join()
    packets_thread.join()
