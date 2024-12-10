## Network Intrusion Prevention System

### Description

+ Developed a Network Intrusion Prevention System (NIPS) in Python, utilizing Scapy for real-time packet analysis and custom rule enforcement for threat detection, alongside IPTables for dynamic packet filtering.
+ Implemented comprehensive logging mechanisms to capture attack details and network traffic data, enhancing visibility and enabling in-depth analysis of security events.
  
### Project Structure

+ ```main.py``` : Entry point; coordinates all modules.
+ ```processPackets.py``` : Processes raw network packets to extract key attributes.
+ ```matchRules.py``` : Matches packet attributes with Snort rules and triggers actions via ```doActions.py```.
+ ```doActions.py``` : Executes corresponding actions based on detected threats.
+ ```storeLogs.py``` : Stores appropriate logs for various attacks.
+ ```snortRules.txt``` : Contains Snort rules for threat detection.
+ ```attackLogs.csv``` : Stores logs of detected attacks.
+ ```trafficLogs.csv``` : Stores logs of analyzed network traffic.

### Usage

+ To add any more snort rules with the different condition add the rule to ```snortRules.txt``` and add corresponding condition matching code in ```matchRules.py```.
  
```sh
  sudo apt install iptables
  pip install scapy
  git clone https://github.com/Kr1shnam00rth1/NetWonIPS/
  cd NetWonIPS
  sudo python3 main.py
```

