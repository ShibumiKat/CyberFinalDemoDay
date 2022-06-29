# Blue Team: Summary of Operations

## Table of Contents
- Network Topology
- Description of Targets
- Monitoring the Targets
- Patterns of Traffic & Behavior
- Suggestions for Going Further
## Network Topology

![Image](/24-Final-Project/FinalProject-NetworkDiagram_io_V1.jpg)

Notes:

- For the details of, and methodology to retrieve the information in this topology, refer to the [Readme.md](/24-Final-Project/Readme.md)
- The topology is also provided in [.jpg](/24-Final-Project/FinalProject-NetworkDiagram_io_V1.jpg) and [.pdf](/24-Final-Project/FinalProject-NetworkDiagram_io_V1.drawio.pdf) files for easy reference while reading the analyses documents.

The following table is a summary of the machines that were identified on the network (for more detail i.e. **OS and OS Versions**, see the Topology above):

![](/24-Final-Project/ImagesProject/2-01.jpg)

### Description of Targets

The target of this attack was: `Target 1` (`192.168.1.110`) and `Target 2 (192.168.1.115)`.

Target 1 & 2 are Apache web servers and has SSH enabled, so ports 80 and 22 are possible ports of entry for attackers. As such, the following alerts have been implemented:

### Monitoring the Targets

Traffic to these services should be carefully monitored. To this end, we have implemented the alerts below:

**Method to Create Alerts**
1.  Access Kibana at `192.168.1.100:5601`

2. Click on **Management** > **License Management** and enable the Kibana Premium Free Trial.

3. Click **Management** > **Watcher** > **Create Alert** > **Create Threshold Alert**

4. Implement three the alerts.

#### Alert 1: **Excessive HTTP Errors (Responce Codes)**

**Note: the value 400 below does not relate to the HTTP Response Code `400`, but it is a threshold of 400! It applies to the count of traffic at a rate of > 400 responses every 5 minutes, which will trigger this Alert. For example, 500 GETs of / at the server will fire the alert even though the only response code is `200`**

- **Metric**: `Packetbeat:` http.response.status_code > 400
- **Threshold**: `grouped http response status codes COUNT above 400 every 5 minutes`  
  - **`When count() GROUPED OVER top5 ‘http.response.status_code’ is above 400 for the last 5 minutes`**
- **Vulnerability Mitigated**:  
  - Denial of Service
  - Brute Force Attacks
  - Suspicious activity
- **Reliability**: This alert will not generate an excessive amount of false positives identifying brute force attacks. **`Medium`**

![](/24-Final-Project/ImagesProject/2-03.jpg)

#### Alert 2: **HTTP Request Size Monitor**

- **Metric**: `Packetbeat:` http.request.bytes
- **Threshold**: The sum of the requested bytes is over 3500 in 1 minute
  - **`When sum() of http.request.bytes OVER all documents is ABOVE 3500 for the LAST 1 minute`**
- **Vulnerability Mitigated**: By controlling the number of http request sizes through a filter, protection is enabled to detect or prevent DDOS attacks for IPS/IDS.
- **Reliability**: No, this alert doesn't generate an excessive amount of false positives because DDOS attacks submit requests within seconds, not within minutes. **`Medium`** 

![](/24-Final-Project/ImagesProject/2-04.jpg)

#### Alert 3: **CPU Usage Monitor**

- **Metric**: `Metricbeat:` system.process.cpu.total.pct
- **Threshold**: The maximum cpu total percentage is over .5 in 5 minutes  
  - **`WHEN max() OF system.process.cpu.total.pct OVER all documents IS ABOVE 0.5 FOR THE LAST 5 minutes`**  
- **Vulnerability Mitigated**: Controlling the CPU usage percentage at 50%, it will trigger a memory alert only if the CPU remains at or above 50% consistently for 5 minutes. Virus or Malware
- **Reliability**: Yes, this alert can generate a lot of false positives due to CPU spikes occurring when specific integrations are initiated at the start of processing. **`High`** 

![](/24-Final-Project/ImagesProject/2-05.jpg)

#### Viewing Logs Messages  

There are a few way to to view these log messages and their associated data options. 

- First, you can see when alerts are firing directly from the Watcher screen.
All 3 Alerts are implemented, and functioning as expected as can be seen from the Watcher Statistics

![](/24-Final-Project/ImagesProject/2-02.jpg)

- To view network traffic associated with these messages, we need to create a new `Index Pattern`:

- Click on **Management > Index Patterns** and click on the button for `Create Index Pattern`.
   
   ![](images/IndexPatterns.png)
   ![](images/CreateIndex.png)

- Make sure to turn on the toggle button labeled `Include System Indices` on the top right corner.

    ![](images/includeIndices.png)

- Create the pattern `.watcher-history-*`.

   ![](images/defineWatcherPattern.png)

![](/24-Final-Project/ImagesProject/2-06.jpg)

- After you have this new index pattern, you can search through it using the `Discovery` page.
   ![](images/discovery.png)

- Enter `result.condition.met` in as search filter to see all the traffic from your alerts.

   ![](images/discovery-filter.png)
   
   ![](images/alert-traffic.png)
### Suggestions for Going Further (Optional)

- Each alert above pertains to a specific vulnerability/exploit. Recall that alerts only detect malicious behavior, but do not stop it. For each vulnerability/exploit identified by the alerts above, the following patches should mitigate against the exploits.

- Vulnerability 1: Weak Passwords
  - **Patch**: Enforce password policy (complexity, MFA, expiry, etc.)
  - **Why It Works**: Brute force attacks in this exercise would be next to impossible.
- Vulnerability 2: Python Privelege Escalation
  - **Patch**: Kibana can be configured to monitor for this attack and Steven's privileges can be revoked.
  - **Why It Works**: Attacks can be detected and Steven must enter a password before obtaining sudo privileges.
- Vulnerability 3: SQL Data Breaches
  - **Patch**: Restrict Access to certain key tables
  - **Why It Works**: Key tables will be inaccessible when users with dodgy security practices are compromised.
- Vulnerability 4: Alert 1: DoS Denial of Service/Brute Force Attacks
  - **Patch**: Block IP addresses, and install firewall
  - **Why It Works**: IP addresses are blocked so they cannot bruteforce or DoS you and a firewall will further harden the network
- Vulnerability 5: Alert 2: DoS Denial of Service/Brute Force Attacks
  - **Patch**: Block IP addresses, and install firewall
  - **Why It Works**: IP addresses are blocked so they cannot bruteforce or DoS you and a firewall will further harden the network
- Vulnerability 6: Alert 3: Malware on System/Suspicious activity i.e. extraction of large amount of data or deleting / encrypting system
  - **Patch**: Patch software and antivirus
  - **Why It Works**: Patched systems and software limits attack vectors. Antivirus stops an attack by quarantining malware/stopping it from operating

