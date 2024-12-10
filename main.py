import time
import os
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
  │   Features      : - Rule-based detection.             │
  │                   - Dynamic Filtering                 │
  │                   - Enhanced logging mechanism        │
  │   Note          :  Designed for learning and          │
  │                    experimentation in cybersecurity.  │
  └───────────────────────────────────────────────────────┘
"""
    print(banner)
    time.sleep(3)
    os.system("clear")
    print("NetWon IPS rule engine started monitoring !!!")

if __name__ == "__main__":

  display_banner()
  
  processPackets.StartSniffing()