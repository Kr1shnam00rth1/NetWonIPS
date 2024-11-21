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

          ──────────────────────────────────────────
          NetWon Intrusion Prevention System (IPS)
          ──────────────────────────────────────────
            Developed by: Krishnamoorthi P L
            Version: 1.0
            Description: A simple IPS built with Snort rules for learning purposes.
                         Not intended for industrial use.
          ──────────────────────────────────────────
          "Because in security, the net always wins!"
          ──────────────────────────────────────────
"""
    print(banner)

def clear_terminal():
        os.system('clear')

if __name__ == "__main__":
    display_banner()
    time.sleep(10)
    clear_terminal()
    
    ssh_thread = Thread(target=processSSH.MonitorSSHLogs)
    #ftp_thread =Thread(target=processFTP.MonitorFTPLogs)

    ssh_thread.start()
    #ftp_thread.start()

    ssh_thread.join()
    #ftp_thread.join()
