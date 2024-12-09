## Network Intrusion Prevention System

### Description

+ Developed a Network Intrusion Prevention System (NIPS) using Python, used Scapy for real-time packet inspection, implemented custom Snort rules for threat detection, and leveraged IPTables for dynamic packet filtering.  
+ Implemented comprehensive logging and automated reporting for attack and traffic data, enhancing real-time monitoring, threat detection, and proactive network defense.

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
### References

+ [Snort Guide](https://docs.snort.org/rules/options/general/)
