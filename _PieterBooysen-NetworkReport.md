# Network Forensic Analysis Report

## Overview

This report is from the Security Engineering Team of X-CORP, supporting the SOC infrastructure. The SOC analysts have noticed some discrepancies with alerting in the Kibana system and the Security Engineering team investigated.

Yesterday, the team confirmed that newly created alerts are working. Live traffic was monitored on the wire to detect any abnormalities that aren't reflected in the alerting system.

This report is the findings for review by both the SOC manager and the Engineering Manager with appropriate analysis.

## Methodology

- Kali VM used for Analysis-* The following Commans were used to start and stop the WireShark Capture
- Open a terminal window and run the command `systemctl start sniff`. 
    - This command uses `tcpreplay` to replay PCAPs in `/opt/pcaps` onto Kali’s `eth0` interface. 
- Launch Wireshark and capture traffic on the `eth0` interface.
- After 15 minutes have passed, run the command `systemctl stop sniff` to stop the `tcpreplay`. 
  - Please note that replaying the PCAPs will use up the CPU memory. You will need to stop this service in order to avoid performance issues with your virtual machine. 
- Save the capture to file. (**This is an important step**.)
- Profile users' behavior from their packet data.

If you are unable to find some of the solutions, it is possible you did not allow Wireshark to capture traffic for long enough. To save time, feel free to use the following PCAP file below to answer the questions:
  
  - [PCAP](https://drive.google.com/file/d/1ggMVl1t_DZfw1WB93FO6hMLe5Ffqz40F/view?usp=sharing) 
  - If copy and paste is not available on the VM, use `curl` to download the file with this alternate URL: [http://tinyurl.com/yaajh8o8](http://tinyurl.com/yaajh8o8).
    - For example: `curl -L -o pcap.pcap http://tinyurl.com/yaajh8o8`

**Note:** You will be dealing with live malware in this activity. Please make sure all work is done on Azure machines. 

![Image](/24-Final-Project//ImagesProject/3-01.jpg)

## Time Thieves 
At least two users on the network have been wasting time on YouTube. Usually, IT wouldn't pay much mind to this behavior, but it seems these people have created their own web server on the corporate network. So far, Security knows the following about these time thieves:
● They have set up an Active Directory network.
● They are constantly watching videos on YouTube.
● Their IP addresses are somewhere in the range 10.6.12.0/24.

1. Domain name of the users' custom site

Domain Name: 		    `frank-n-ted-dc.frank-n-ted.com`
WireShark Filter:		`ip.addr == 10.6.12.0/24`

![Image](/24-Final-Project//ImagesProject/3-02.jpg)

2. What is the IP address of the Domain Controller (DC) of the AD network?

Domain Controller:      `10.6.12.12`
WireShark Filter:		`ip.addr == 10.6.12.0/24`
(and also refer to the previous screenshot)

![Image](/24-Final-Project//ImagesProject/3-03.jpg)

3. What is the name of the malware downloaded to the 10.6.12.203 machine?
   - Once you have found the file, export it to your Kali machine's desktop.

Filename: 	        `june11.dll`
WireShark Filter:	`ip.addr == 10.6.12.0/24 and http.request.method == GET`

![Image](/24-Final-Project//ImagesProject/3-04.jpg)

4. Upload the file to [VirusTotal.com](https://www.virustotal.com/gui/). 

- `Wireshark//File//Export Objects//HTTP > filter: june11`
- Upload file to VirusTotal.com

![Image](/24-Final-Project//ImagesProject/3-05.jpg)
![Image](/24-Final-Project//ImagesProject/3-06.jpg)

Malware Characteristics

![Image](/24-Final-Project//ImagesProject/3-07.jpg)

5. What kind of malware is this classified as?

The malware goes by different names but maltiverse.com classify it as **Trojan**

![Image](/24-Final-Project//ImagesProject/3-08.jpg)

![Image](/24-Final-Project//ImagesProject/3-09.jpg)

---

## Vulnerable Windows Machine

The Security team received reports of an infected Windows host on the network. They know the following:
- Machines in the network live in the range `172.16.4.0/24`.
- The domain mind-hammer.net is associated with the infected computer.
- The DC for this network lives at `172.16.4.4` and is named Mind-Hammer-DC.
- The network has standard gateway and broadcast addresses.

Inspect your traffic to answer the following questions in your network report:

1. Find the following information about the infected Windows machine:

- Host name: `ROTTERDAM-PC`
- IP address: `172.16.4.205`
- MAC address: `00:59:07:b0:63:a4`
- Wireshark Filter: `ip.addr == 172.16.4.0/24`

![Image](/24-Final-Project//ImagesProject/3-10.jpg)

2. What is the username of the Windows user whose computer is infected?

- Username: `matthijs.devries`
- Wireshark Filter: `ip.src==172.16.4.205 && kerberos.CNameString`

![Image](/24-Final-Project//ImagesProject/3-11.jpg)

3. What are the IP addresses used in the actual infection traffic?

- 3 IP addresses involved with the majority of network traffic:
    - `172.16.4.205`
    - `185.243.115.84`
    - `166.62.11.64`
- WireShark Filter: `ip.src==172.16.4.205`
- Finding the IP addresses:
    - Click on the Statistics Tab
    - Select the Conversation
    - Select the IPv4
    - Sort Packets high to low
    - Select function "Limit to Display Filter"

![Image](/24-Final-Project//ImagesProject/3-12.jpg)

With examples of the infected traffic being:

![Image](/24-Final-Project//ImagesProject/3-13.jpg)

4. As a bonus, retrieve the desktop background of the Windows host.

Using the Object Export/HTTP, and going through the gif and jpg images, we found the desktop image.

![Image](/24-Final-Project//ImagesProject/3-14.jpg)

![Image](/24-Final-Project//ImagesProject/3-15.jpg)

---

## Illegal Downloads

IT was informed that some users are torrenting on the network. The Security team does not forbid the use of torrents for legitimate purposes, such as downloading operating systems. However, they have a strict policy against copyright infringement.

IT shared the following about the torrent activity:

- The machines using torrents live in the range `10.0.0.0/24` and are clients of an AD domain.
- The DC of this domain lives at `10.0.0.2` and is named DogOfTheYear-DC.
- The DC is associated with the domain dogoftheyear.net.

Your task is to isolate torrent traffic and answer the following questions in your Network Report:

1. Find the following information about the machine with IP address `10.0.0.201`:

- MAC address: `00:16:17:18:66:c8`
- Windows username: `elmer.blanco`
- OS version: `Windows NT 10.0`

WireShark Filters
- Wireshark Filter for MAC Address: ip.addr == 10.0.0.201 && dhcp

![Image](/24-Final-Project//ImagesProject/3-16.jpg)

- WireShark Filter for Username: ip.addr == 10.0.0.201 && kerberos.CNameString

![Image](/24-Final-Project//ImagesProject/3-17.jpg)

- Wireshark Filter for OS Type and Version: ip.addr == 10.0.0.201 && http.request/method == GET

![Image](/24-Final-Project//ImagesProject/3-18.jpg)

2. Which torrent file did the user download?

- Wireshark Filter for finding Torrent File: ip.addr == 10.0.0.201 && http.request/method == GET

First, set up WireShark to resolve the IP Addresses:

![Image](/24-Final-Project//ImagesProject/3-19.jpg)

Once teh files.publicdomaintorrents.com Destination is found, look for the btdownload information, which shows that the file downloaded is

**Betty_Boop_Rhythm_on_the_Reservation.avi.torrent**

![Image](/24-Final-Project//ImagesProject/3-20.jpg)

The file can be further researched, and a summary can be found here:

http://www.publicdomaintorrents.info/grabs/bettybooprythmonthereservationgrab.jpg


![Image](/24-Final-Project//ImagesProject/3-21.jpg)
