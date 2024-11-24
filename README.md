## Network Intrusion Prevention System

### Description

+ Developed a Network Intrusion Prevention System using Python, utilizing Scapy for real-time packet inspection, implementing Snort rules for threat detection, and used IPTables for dynamic packet blocking.

+ Created specialized modules to detect SSH and FTP brute-force login attempts through rate-limiting techniques and detailed logging mechanisms for attack and traffic data, facilitating continuous monitoring and reporting.
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