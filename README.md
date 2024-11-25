## Network Intrusion Prevention System

### Overview

+ Developed a Network Intrusion Prevention System (NIPS) using Python, utilizing Scapy for real-time packet inspection, implementing Snort rules for threat detection, and configuring IPTables for dynamic packet filtering.  
+ Designed and implemented modules to detect SSH and FTP brute-force login attempts, using rate-limiting techniques and detailed logging for attack and traffic data, enabling continuous monitoring and automated reporting.
       
### Project Structure

+ ```main.py``` : Entry point; coordinates all modules.
+ ```processPackets.py``` : Processes raw network packets to extract key attributes.
+ ```processFTP.py``` : Monitors FTP traffic for brute force attacks.
+ ```processSSH.py``` : Monitors SSH traffic for brute force attacks.
+ ```matchRules.py``` : Matches packet attributes with Snort rules and triggers actions via ```doActions.py```.
+ ```doActions.py``` : Executes corresponding actions based on detected threats.
+ ```storeLogs.py``` : Stores appropriate logs for various attacks.
+ ```snortRules.txt``` : Contains Snort rules for threat detection.
+ ```attackLogs.csv``` : Stores logs of detected attacks.
+ ```trafficLogs.csv``` : Stores logs of analyzed network traffic.

### Usage

```sh
pip install scapy
sudo apt install iptables
git clone https://github.com/Kr1shnam00rth1/NetWonIPS
cd NetWonIPS
sudo python3 main.py
```
+ To add a new Snort rule with specific conditions, include it in the rule.txt file and write the matching code for the condition in the matchRule.py file.

### Reference

+ [Snort Rules](https://docs.snort.org/start/rules)
  
