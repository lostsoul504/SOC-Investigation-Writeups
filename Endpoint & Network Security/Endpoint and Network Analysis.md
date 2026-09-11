 ## Lab: [Network & AD Basics Capstone]

---


> [!ABSTRACT] Executive Summary
> **What Happened:** On December 1, 2025, Corp detected suspicious outbound traffic from its public web server. Minutes later, alerts flagged unauthorized scheduled tasks, unusual PowerShell activity, and lateral movement toward the internal network. The attacker leveraged a web upload vulnerability on WEB01, established persistence through malicious scheduled tasks, then pivoted to DC01, where sensitive data was compressed and exfiltrated to an external host.


**Incident Scope**:
- **Identities:** `sholloway` (Domain User Account compromised via OS credential dumping).
- **Endpoints:** `WEB01` (Public Web Server; initial access point), `DC01` (Domain Controller; targeted for lateral movement and data exfiltration).
- **Network:** `10[.]10[.]3[.]16` (WEB01 internal IP), `10[.]10[.]11[.]16` (DC01 internal IP)



---


 ## Tools & Environments Used

* Wireshark (Network Traffic Analysis)
* Event Log Explorer (For viewing and filtering Windows event logs)


---


 ## Critical Indicators of Compromise (IOCs)

#### Network & Identity Indicators

| **Type**   | **Indicator / Value** | **Context / Mapping**                                                           |
| ---------- | --------------------- | ------------------------------------------------------------------------------- |
| IP Address | `54[.]93[.]195[.]233` | Command & Control (C2) server and port scanning source.                         |

#### Malicious URLs

| **Source IP**         | **Staging / Delivery URL**                                    |
| --------------------- | ------------------------------------------------------------- |
| `54[.]93[.]195[.]233` | `hxxp[://]54[.]93[.]195[.]233:8888/mimikatz/x64/mimikatz.exe` |
| `54[.]93[.]195[.]233` | `hxxp[://]54[.]93[.]195[.]233:8888/OneDrlvee.exe`             |
| `54[.]93[.]195[.]233` | `http[://]54[.]93[.]195[.]233:8888/PsExec64.exe`              |

#### Host-Based Indicators

**Host-Based Indicators**

- **File:** `20251201_191319_3e04bcce_Checker.php`
    - **Artifact Type:** Web Shell
    - **Context:** Initial payload uploaded to `C:\xampp\htdocs\helpdesk\uploads\` to execute reconnaissance and system commands (T1190).

- **File:** `m.exe`
    - **Artifact Type:** Credential Dumper (Mimikatz)
    - **Context:** Downloaded to `C:\Windows\Temp\` and executed to extract LSASS memory credentials into `creds.txt` (T1003.001).

- **File:** `OneDrlvee.exe`
    - **Artifact Type:** Reverse Shell Binary
    - **Context:** Typosquatted payload downloaded to `C:\Windows\Temp\` and executed to open a persistent reverse connection to the C2 over port 3324 (T1036.005).

- **File:** `PsExec64.exe`
    - **Artifact Type:** Remote Execution Tool
    - **Context:** Legitimate Sysinternals tool staged in `C:\Windows\Temp\` and used to laterally move to the Domain Controller via SMB (T1570).

- **File:** `WinUpdate.ps1`
    - **Artifact Type:** Malicious PowerShell Script
    - **Context:** Leveraged via a scheduled task for persistent execution and direct C2 exfiltration (T1562.001).


---


 ## MITRE ATT&CK Mapping

| **Tactic**          | **Technique**                                                           | **ID**                | **Description**                                                                                                                                 |
| ------------------- | ----------------------------------------------------------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Reconnaissance      | Active Scanning: Scanning IP Blocks                                     | T1595.001             | The attacker initiated TCP SYN port scans targeting the public web server (WEB01).                                                              |
| Initial Access      | Exploit Public-Facing Application                                       | T1190                 | A PHP web shell (`20251201_191319_3e04bcce_Checker.php`) was successfully uploaded via a vulnerability in the `/helpdesk/upload.php` directory. |
| Credential Access   | Credentials in Files: Local Credentials                                 | T1552.001 / T1005     | The attacker utilized the web shell to access `C:\xampp\htdocs\backup\db_connections.txt` and capture plaintext database credentials.           |
| Command and Control | Ingress Tool Transfer / Exploit Public-Facing Application               | T1005 / T1036.008     | `mimikatz.exe` was downloaded and renamed to `m.exe` via PowerShell utilizing the C2 IP on port 8888.                                           |
| Credential Access   | OS Credential Dumping: LSASS Memory                                     | T1003.001 / T1560     | `m.exe` was executed to dump plaintext credentials and NTLM hashes from memory and archive the output to `C:\Windows\Temp\creds.txt`.           |
| Defense Evasion     | Ingress Tool Transfer / Masquerading: Match Legitimate Name or Location | T1105 / T1036.005     | A typosquatted reverse shell payload (`OneDrlvee.exe`) was pulled from the C2 server and saved in the local Temp directory.                     |
| Command and Control | Ingress Tool Transfer                                                   | T1105                 | The legitimate Microsoft tool `PsExec64.exe` was downloaded from the attacker's staging server.                                                 |
| Execution           | Reverse Shell Execution / Non-Application Layer Protocol                | T1159 / T1071         | `OneDrlvee.exe` was executed with a PowerShell parameter to open a reverse shell back to C2 IP `54[.]93[.]195[.]233` on port 3324.              |
| Lateral Movement    | Lateral Tool Transfer / Remote Services: SMB/Windows Admin Shares       | T1570 / T1021.002     | The attacker leveraged compromised user credentials (`sholloway`) and `PsExec64.exe` to move laterally to DC01 (`10[.]10[.]11[.]16`).           |
| Persistence         | Scheduled Task/Job: Scheduled Task                                      | T1053.005 / T1562.001 | Created an hourly scheduled task ("WindowsUpdate") operating as SYSTEM to execute `WinUpdate.ps1`.                                              |
| Exfiltration        | Application Layer Protocol / Exfiltration Over C2 Channel               | T1071.001 / T1041     | `WinUpdate.ps1` was executed, sending continuous HTTP POST requests to exfiltrate compressed database information to the C2.                    |


---


 ## Investigation Methodology & Walkthrough

 ### Step 1: Determining Reconnaissance

First, we analyze the Pcap for the web server **WEB01** that we have been provided for port scans by opening it in Wireshark. For TCP port scanning, it can be detected by going to `Statistics -> Conversations` and viewing all the TCP connections. Also, sort the connections in ascending order of **Relative Start**.


![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/44c6f931e0202fb6797dfc2d10ed2950_MD5.png]]



Here, we notice that a single IP address `54[.]93[.]195[.]233` has initiated a large number of TCP connections towards the host in a very short time frame as well as the different port numbers targeted and the no. of total packets per connection indicates a TCP SYN scan.

Now, we need to determine if any open ports were discovered at all. For this we need to see if the web server with the IP address `10[.]10[.]3[.]16` sent any TCP packets with SYN and ACK flags set to 1 to the malicious IP we discovered above. The Wireshark filter to do this is as follows:

```plaintext
ip.dst == 54.93.195.233 && ip.src == 10.10.3.16 && tcp.flags.syn == 1 && tcp.flags.ack == 1
```


![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/6ea24824708a2fc82b35a421cec3415a_MD5.png]]



We can see that the web-server has returned TCP packets with the SYN and ACK flags set to 1 to the port scanning IP address from port 80, thus determining that port 80 was open and was accepting connections.



 ### Step 2: Determining Initial Access

After determining a successful recon attempt for port 80, we can assume that the attacker has targeted the website, since it is a common attack vector for initial access. One of the most common methods is checking for file uploads. We can do this by filtering HTTP POST requests from the port scanning IP identified earlier.

```plaintext
ip.src == 54.93.195.233 && ip.dst == 10.10.3.16 && http.request.method == POST
```


![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/cbdfa3d1b85bc5de4a35d5ebb67f5114_MD5.png]]


We can see that there was a POST request at the web directory `/helpdesk/upload.php` at **2025-12-01 18:13:19 UTC**. So, we follow the HTTP stream via right-clicking on it and going to `Follows -> HTTP Stream`.


![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/36255633432a4823d5b831c5fa7d84f1_MD5.png]]



We can determine from here that a file named `20251201_191319_3e04bcce_Checker.php` was uploaded to the web-server successfully. The metadata before the file name likely is appended by the server itself to prevent file-name collisions.


This uploaded file could be many things, but the most likely uploaded files on web-servers are usually web-shells, so we need to determine if any commands were executed via the webshell, and this can be done by filtering GET requests from the port scanning IP containing `?c=`, which is used for providing commands to the web-shell to execute.

```plaintext
ip.src == 54.93.195.233 && ip.dst == 10.10.3.16 && http.request.method == GET && http.request.uri contains "?c="
```


![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/b4f9e55847d69bf77b93bf963a8dc970_MD5.png]]



Here, we can that multiple commands have been executed, for system reconnaisance. Now, we have also been provided with the disk image of **WEB01**, so we can view its Sysmon logs to determine the location of the web-shell on the web-server. We have used Event Log Explorer to open the sysmon logs at `C\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%254Operational.evtx`. And by filtering for Event Id 1 (process creation) and with the timestamp for the upload of the web shell `2025-12-01 18:13:19` to filter out relevant logs.


![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/8107053bd977dbe6ac44fd0c46e02c6d_MD5.png]]



After filtering we have vastly reduced the no. of target logs to search through, we go through the logs description to find the location of the web-shell


![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/3585a4081ad6e72e59467bc2163e6e43_MD5.png]]



We can see from the log description that the first reconnaissance command **whoami** from the HTTP logs has been run via `Cmd.exe` process spawned by the web shell located at `C:\xampp\htdocs\helpdesk\uploads\`.



 ### Step 3: Determining Discovery & Credential Access

Now we add this directory to the filter so that we have further precision in the Event Id 1 logs.


![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/d49b01bb8b3213984a76600549fc8b72_MD5.png]]



So, now we have full view of the commands executed by the web-shell without URL encoding, so we can determine what commands were executed. We can see various discovery techniques here, for system owner, system itself, domain itself, remote system, file & directory, and finally we can see that the attacker has accessed the `db_connections.txt`, which may contain hardcoded database credentials. Upon matching the command in the `WEB01.pcap` file, we have


![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/371ba5249ed557d33d9a88623186b83e_MD5.png]]



We can see that the credentials were stored in unencrypted way, which was successfully gathered by the attacker.


![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/71e46e196c3bbba8f6e12a9b9fd747a9_MD5.png]]


Further scrolling down the logs, we have a commands that downloaded **Mimikatz** tool from the malicious IP via port 8888 and renamed to `m.exe`, which is used to extract credentials straight from the Windows memory.


![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/8064198f28d6e1bae40698e766337874_MD5.png]]



When filtering for Event Id 10, we can see that the file `m.exe` has accessed `lsass.exe`, which stores NTLM hashes, Kerberos tickets, plaintext passwords, etc. And correlating with the Event Id 11 to determine if there are any dropped files containing credentials.


![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/0e958f7ebeb9af0d4dd00aa1ba5c8959_MD5.png]]



We can see that there is a `creds.txt` file created, which will now we correlate with HTTP logs with the filter.

```plaintext
ip.src == 54.93.195.233 && ip.dst == 10.10.3.16 && http.request.method == GET && http.request.uri contains "creds.txt"
```


![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/c03658ede78f93ac45b16fa48b50b466_MD5.png]]



From the HTTP body, we can see that the credentials for user account with name **sholloway** has been have been extracted and thus compromised. Now we need to determine what more has been executed on the web server after exporting `creds.txt`.


![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/a36f45a8767b9e62bacfad9828381e06_MD5.png]]



We can see that another file named `OneDrlvee.exe` that has been downloaded, which is typosquatted to look like legitimate service `OneDrive.exe`. And next, we can see that it has connected via port 3324 and executes powershell via the `-e` flag, and with the following commands, it can be determined that the uploaded file is a reverse shell. To further correlate, we can filter for Event Id 3 (network connections) and see if there are any outbound connections via the file to the malicious IP address.


![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/b451277d62d93b05c8ede1764d3232de_MD5.png]]



![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/321b6b701c13de5398278b6440f73299_MD5.png]]



Clearly, we can see that the timestamp `2025-12-01T18:30:17Z` is right after the timestamp for `OneDrlvee.exe` file execution, that is `2025-12-01T18:30:16Z`, further proving that it was a reverse shell.



 ### Step 4: Determining Lateral Movement

Another file that has been downloaded via internet that can viewed via logs that we can see is `PsExec64.exe`, which is a commonly used tool for execution of processes on remote Windows systems, which was then used to laterally move to the domain user credentials of the user account sholloway previously extracted to the IP address `10[.]10[.]11[.]16` at 2025. This can be correlated with the Security logs Event Id 4624 on the Domain Controller **DC01** along with the keyword username sholloway as a filter.


![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/519aac3bfc66679197f9134b5221ee0b_MD5.png]]



From the above Event Id 4624 logs on the **DC01**, we can see that the compromised account first logging at `2025-12-01 18:38:50`, which is right after the timestamp of the `PsExec.exe` execution on the web-server at `2025-12-01 18:30:36`. Apart from that, there is also the supportive evidence of the IP address making the connection `10[.]10[.]3[.]16`, which belong to the web-server **WEB01** and is highly abnormal. Also, LogonType value 3 denotes Network-based login, which matches with the remote login of `PsExec.exe`, also making it highly unusual. Hence, we can confirm that lateral execution to the Domain Controller with IP Address `10[.]10[.]11[.]16` has happened.


 ### Step 5: Determining Persistence & Exfiltration


Now, we must check for signs of persistence among web-server sysmon logs with Event Id 1 and keyword **xampp**.


![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/f240e1f6da047acc0f715cbd67f7590f_MD5.png]]


Now, from the logs, we can see that a scheduled task has been created, which executes the file `WinUpdate.ps1` hourly, along with **Bypass** Execution policy. However, the attacker later realized the mistake that there was no file named `WinUpdate.ps1` at the specified location, so the attacker later downloaded the payload directly from the C2 server `54[.]93[.]195[.]233`, and then executed it again with parameters stating the C2 server IP, path from which exfiltration will take place, and a duration of 300 seconds. To correlate if exfiltration really took place, we need to check for HTTP requests from the web-server's IP address to the C2 IP.

```plaintext
ip.src == 10.10.3.16 && ip.dst == 54.93.195.233 && http.request
```
 

![[09_archives_ccdl1/2_network_and_endpoint_essentials/2.4_capstone_lab/_resources/network_and_ad_basics_capstone_lab/2a9c10b6e7226ec33b0b97207b50af0c_MD5.png]]



From the network traffic and temporal co-relation between the Exfiltration command execution `01-12-2025  18:33:47` and the first POST request to the malicious IP `54.93.195.233` at `01-12-2025  18:33:48`, we can see that the exfiltration command worked successfully. Also, the JSON file was exfiltrated containing stolen data. The command also sends requests to C2 IP continuously over 5 minutes, as was the parameter passed in the command.


---

 ## Recommendations & Remediation

---

Based on the forensic artifacts discovered in the memory dump and network logs, the following actions are recommended to contain and eradicate the threat:


 ### Immediate Containment Actions
 
- **Host Isolation:** Network-isolate the affected web server **WEB01** (IP: `10[.]10[.]3[.]16`) and Domain Controller **DC01** (IP: `10[.]10[.]11[.]16`) immediately using the EDR console to prevent further lateral movement and data exfiltration.

- **Process Termination:** Terminate the rogue reverse shell (`OneDrlvee.exe`), active PowerShell instances, and any `PsExec64.exe` processes originating from `C:\Windows\Temp\` on the live hosts if they are still running.

- **Network Blocking:** Implement a block rule at the perimeter firewall and web proxy for the malicious command-and-control (C2) IP address `54[.]93[.]195[.]233` to cut off any remaining communication across all ports.


 ### Eradication & Recovery
 
- **Artifact Removal:** Locate and securely delete the malicious web shell (`20251201_191319_3e04bcce_Checker.php`) at `C:\xampp\htdocs\helpdesk\uploads\`, as well as all malicious binaries/outputs staged in `C:\Windows\Temp\` (`m.exe`, `creds.txt`, `OneDrlvee.exe`, `PsExec64.exe`, and `WinUpdate.ps1`).

- **Persistence Cleanup:** Investigate the Task Scheduler for the persistence mechanism named `WindowsUpdate` that points to the malicious PowerShell script and delete it.

- **Credential Rotation:** Because OS credential dumping (Mimikatz) occurred and the `sholloway` account was leveraged for lateral movement, treat all user and service credentials actively logged into this machine during the compromise as compromised. Force a password reset for the affected user accounts immediately.

- **Re-imaging:** Due to the severity of remote code execution as SYSTEM and lateral movement to a Domain Controller, full re-imaging of the **WEB01** workstation is recommended after extracting necessary disk artifacts.


 ### Post-Incident Review (Lessons Learned)

- **Defense Gap Identified:** The malware was able to establish an initial foothold due to an insecure file upload vulnerability in the `/helpdesk/upload.php` directory, and the intrusion was further escalated due to sensitive plaintext credentials stored in `db_connections.txt`.

- **Strategic Recommendation:** Implement strict input validation for public-facing file uploads, ensure sensitive files are encrypted and stored outside web roots, and deploy AppLocker policies to restrict execution from `C:\Windows\Temp\` directories to prevent initial access payloads from running.

