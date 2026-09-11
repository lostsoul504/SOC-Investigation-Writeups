 ## Lab: [Phishing & Email Security Capstone]

---


> [!ABSTRACT] Executive Summary
> **What Happened:** An attacker initiated a spearphishing campaign targeting the organization with a malicious email that masqueraded as an automated Microsoft account security alert. The campaign utilized diverse document-based initial access vectors—including external OLE object relationships, encrypted archives leveraging default passwords, and VBA stomped macros—to bypass traditional security controls and execute malicious PowerShell commands designed to download secondary payloads.


**Incident Scope**:
* **Identities:** 1 Targeted Corporate Account (`bob@cyberdefenders.org`).
* **Endpoints:** 1 Victim Host Workstation.
* **Network:** External Email Gateway (inbound delivery) and Perimeter Firewall (outbound traffic to 2 distinct C2 domains).


---


 ## Tools & Environments Used

* VS Code (text editor for raw .eml file)
* oletools (attachment analysis of office files)
* msoffcrypto-crack.py (for password-cracking & decryption)
* lnkinfo (for analysis of `.lnk` files)


---


 ## Critical Indicators of Compromise (IOCs)
#### Network & Identity Indicators

|**Type**|**Indicator / Value**|**Context / Mapping**|
|---|---|---|
|**Domain**|`rncrosoft[.]com`|Typosquatted sender domain used in spoofed Microsoft alert (`sample1`)|
|**Domain**|`www-cbsl-gov-lk.dwnlld[.]info`|Typosquatted hosting infrastructure for external OLE payload (`sample2`)|
|**Domain**|`0b3l1sk[.]me`|C2 staging domain hosting secondary binaries (`sample3`)|
|**Domain**|`tafrihafashion[.]com`|External hosting domain serving obfuscated staging script (`sample4`)|
|**IPv4**|`89[.]144[.]5[.]13`|Inbound source IP sending malicious email (`spf=fail`)|
|**Email (Sender)**|`no-reply[@]rncrosoft[.]com`|Attacker email masquerading as Microsoft security alert|
|**Email (Target)**|`bob[@]cyberdefenders[.]org`|Targeted internal corporate mailbox|


#### Malicious URLs

| **Source Domain**               | **Staging / Delivery URL**                                       |
| ------------------------------- | ---------------------------------------------------------------- |
| `www-cbsl-gov-lk.dwnlld[.]info` | `hxxps[://]www-cbsl-gov-lk.dwnlld[.]info/6cc2e6e0/Profile[.]rtf` |
| `0b3l1sk[.]me`                  | `hxxps[://]0b3l1sk[.]me/a`                                       |
| `tafrihafashion[.]com`          | `hxxp[://]tafrihafashion[.]com/boondle[.]txt`                    |


#### Host-Based Indicators

- **File:** `sample1.eml`
    - **Artifact Type:** Raw Email File
    - **Context:** Initial spear-phishing lure spoofing Microsoft account unusual sign-in activity (`T1566.001`).

- **File:** `sample2.docx`
    - **Artifact Type:** Malicious Office Document (OpenXML)
    - **Context:** Contains external OLE relationship pointing to `Profile.rtf` via typosquatted domain to stage payload on document open.

- **File:** `sample3`
    - **Artifact Type:** Malicious Office Document (OLE2)
    - **Context:** Leverages VBA Stomping (`T1564`) and `URLDownloadToFileA` to download `a.exe` from `0b3l1sk[.]me`.

- **File:** `OneDriveUpdateService.exe`
    - **Artifact Type:** Staged Malicious PE Binary
    - **Context:** Masquerades as legitimate OneDrive binary; dropped directly into the user's Startup folder for persistence (`T1547.001`, `T1036.005`).

- **File:** `sample4`
    - **Artifact Type:** Encrypted Office Document (OLE2)
    - **Context:** Uses default `VelvetSweatshop` encryption key to evade static perimeter filters (`T1027.002`). Unpacks embedded archive containing a shortcut payload.

- **File:** `RECH17321732.lnk`
    - **Artifact Type:** Malicious Windows Shortcut File
    - **Context:** Spoofs icon path to `mspaint.exe`; executes hidden `powershell.exe` command to download and invoke `boondle.txt` (`T1059.001`).


---


 ## MITRE ATT&CK Mapping

| Tactic                       | Technique                                                             | ID        | Description                                                                                                                                                                                      |
| ---------------------------- | --------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Initial Access (TA0001)      | Phishing: Spearphishing Attachment                                    | T1566.001 | Attacker sent `sample1.eml` with highly targeted masquerading headers to deliver malicious file payloads.                                                                                        |
| Execution (TA0002)           | User Execution: Malicious File                                        | T1204.002 | Requires the user to open `sample2`, `sample3`, or `sample4` to initiate the execution chain.                                                                                                    |
|                              | Command and Scripting Interpreter: PowerShell                         | T1059.001 | `sample4` utilizes an embedded `.lnk` file to silently call `powershell.exe` to pull code from the internet.                                                                                     |
| Persistence (TA0003)         | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 | `sample3` utilizes VBA macros to target the local user's Windows `"Startup"` folder to drop `OneDriveUpdateService.exe`.                                                                         |
| Defense Evasion (TA0005)     | Obfuscated Files or Information: Software Packing                     | T1027.002 | `sample4` relied on OLE container encryption via the default `VelvetSweatshop` password to hide internal artifacts from static perimeter scanners.                                               |
|                              | Hide Artifacts: VBA Stomping                                          | T1564     | `sample3` contains distinct traces of VBA Stomping, where the source code and P-code diverge to evade analysis tools.                                                                            |
|                              | Masquerading: Match Legitimate Name or Location                       | T1036.005 | The downloaded binary in `sample3` mimics `OneDriveUpdateService.exe`, and the shortcut file in `sample4` spoofs its icon location to point to `paint.exe`.                                      |
| Command and Control (TA0011) | Ingress Tool Transfer                                                 | T1105     | Both `sample3` (via `URLDownloadToFileA`) and `sample4` (via `Invoke-WebRequest`) reach out to external domains (`0b3l1sk[.]me` and `tafrihafashion[.]com`) to download malicious staging files. |



---


 ## Investigation Methodology & Walkthrough

 ### Step 1: Analyzing raw sample1.eml file

First, we analyze the raw `sample1.eml` file by opening it in VS Code. Then we find out the basic information about the sender, subject, no. of recipients, timestamp of the sending time of email, value of return-path header, authentication-results header, value of reply-to header.
For no. of recipients, we can check the *cc* or *bcc* headers, but since there aren't any, we can determine that there was only 1 recipient.


![]_resources/phishing_and_email_security_capstone_lab/49f1cc8929ac93ae9c96037ec195d6d0_MD5.png



 ### Step 2: Analyzing the sample2 file

To generate a hash of the file sample2 in linux, we can simply use the command `sha256sum filename` to check for it in threat intel. We check the properties of the sample2 file by right-clicking on the icon and clicking of properties option, and determine that it is an ole-based file. Thus, we can use Oletools for further analysis of the sample2 file. Using oleid first, we get the basic information about the file first.

![]_resources/phishing_and_email_security_capstone_lab/c15ea99f62ec7ff9d809bac7c9a3cede_MD5.png|
![]_resources/phishing_and_email_security_capstone_lab/c15ea99f62ec7ff9d809bac7c9a3cede_MD5.png



We can see that sample2 is an MS Word file with .docx extension, along with confirmation that there are no VBA macros present in the file. However, it does contain External Relationships, more specifically oleObject and hyperlink, which attempts to pull the said objects into the target system as soon as the file is opened.


![]_resources/phishing_and_email_security_capstone_lab/9463a66c67c44ae62bb711fea34ba7dc_MD5.png



We can see that there is an *oleObject* that is linked with a suspicious link `https[:]//www.cbsl.gov.lk.dwnlld.info/6cc2e6e0/Profile.rtf`, which contains a typosquatted domain with a classic fake download domain "*dwnlld* "domain. 



 ### Step 3: Analyzing the sample3 file

From the properties of the file, we can see that it is a OLE file, which means that it can be analyzed using Oletools. Upon using the oleid on the file, we get the basic info about the file.


![]_resources/phishing_and_email_security_capstone_lab/60876d1eb535cb971fe4f9d7ae67d838_MD5.png



As we can see that the file contains VBA macros, but no suspicious files were detected by oleid. But just for further confirmation, we check the file with olevba tool, which yields the following result.


![]_resources/phishing_and_email_security_capstone_lab/6a8d836884023371a3e61eac65245d57_MD5.png


![]_resources/phishing_and_email_security_capstone_lab/428d32fc0ebb6b205fac65ede1e5b7d9_MD5.png



Upon using olevba tool on sample3, we get a whole bunch of malicious indicators like a URL `https[:]//0b3l1sk.me/a`, and executables a.exe and `OneDriveUpdateService.exe` along with the VBA P-code itself. Also, there are traces of VBA Stomping, which is a common defense evasion/anti-analysis technique.


 ### Step 4: Analyzing the sample4 file

Just like above files, first we check the properties of the sample4 file, and notice that it is an OLE 2 file, so we run oleid on it.


![]_resources/phishing_and_email_security_capstone_lab/01ef64c6fcdc39548277afc1b9edc060_MD5.png



As we can see, there are no surface malicious indicators, but the file format is unrecognized and it is also encrypted, which is unusual and can be grounds for further analysis. So, we can use msoffcrypto-crack.py script to crack its password.


![]_resources/phishing_and_email_security_capstone_lab/323aef67a44690d9e6b1f2e2260ffefd_MD5.png


We can see that the password has been found to be VelvetSweatshop, and after cracking it, we get a decrypted file.


![]_resources/phishing_and_email_security_capstone_lab/755c2f547a59edfa67b9e60106311aee_MD5.png


As we can see from its basic properties that it is a ZIP file. Newer Office documents are essentially zip archives of a collection of XML files, so we can use Oletools for analysis here.


![]_resources/phishing_and_email_security_capstone_lab/321c045526cee8c19476179c666f0a95_MD5.png



We can see that the file is a MS Word document, and there are no particular malicious indicators. However, we should still not rely on a single tool and run further investigation. We can extract the Doc file's components into another directory as well as list the files extracted.


![]_resources/phishing_and_email_security_capstone_lab/a6cdefd31f83b40822a054a92e7eba7b_MD5.png



We can see now that there is a highly suspicious `.bin` in the the **/word/embeddings/** sub-directory inside. After extracting it and computing its hash, we can match it against threat intel.  And since it was inside an Office Word document, we can use Oletools, specifically oleobj against it.


![]_resources/phishing_and_email_security_capstone_lab/eb895f6879e00643244b745d5dcdaa02_MD5.png



We can now see that another `.zip` file has been extracted by **oleobj**. Now, compute its hash to check for threat intel, and unzip it for further analysis.


![]_resources/phishing_and_email_security_capstone_lab/ac5fa437afb983550d00c75626365dda_MD5.png


Now, we can see a `.lnk` file, which is highly suspicious. We can use **lnkinfo** for further analysis.


![]_resources/phishing_and_email_security_capstone_lab/a19d405a5e7cc73b09720519bc12bf3c_MD5.png



We can immediately see the signs of powershell execution, remote file download, defense evasion and social engineering, along with the exact the URL where the file was downloaded from.


---

 ## Recommendations & Remediation

---

Based on the phishing artifacts and malicious payloads discovered during this investigation, the following actions are recommended to contain and eradicate the threat:


 ### 1. Immediate Containment Actions

- **Email Gateway Purge:** Run an immediate search-and-purge query across the email gateway for any incoming messages from the domain `rncrosoft[.]com` or containing the subject line `Microsoft account unusual signin activity` to prevent further user interaction.

- **Network Perimeter Blocking:** Implement strict block rules at the perimeter firewall, secure web gateway (SWG), and internal DNS servers for the following malicious domains:
    - `www-cbsl-gov-lk.dwnlld[.]info`
    - `0b3l1sk[.]me`
    - `tafrihafashion[.]com`

- **Host Isolation:** Cross-reference proxy and DNS logs to identify any internal assets communicating with the malicious domains listed above, and immediately isolate those endpoints from the network.


 ### 2. Eradication & Recovery

- **Persistence Cleanup:** Scan user profiles across the fleet for the presence of the malicious shortcut file `RECH17321732.lnk` and any instances of `OneDriveUpdateService.exe` residing within the local Windows Startup directories, ensuring their secure deletion.

- **Credential Rotation:** Because the initial phishing wave targeted corporate email accounts (e.g., `bob@cyberdefenders.org`), enforce an immediate password reset and session revocation for any users who interacted with or opened attachments from these emails.

- **Endpoint Re-imaging:** For any asset where file execution (`OneDriveUpdateService.exe` or the PowerShell script contents from `boondle.txt`) is confirmed by EDR logs, pull forensic images for deep analysis and perform a clean system re-build.


 ### 3. Post-Incident Review (Lessons Learned)

- **Email Security Gateway:** Gateway allowed a hard **SPF Failure** (`spf=fail`) from `89.144.5.13` to reach the inbox due to passive enforcement configurations.

- **Inspection Blindspot:** Static scanners were blinded by `sample4` because it used the default Microsoft `VelvetSweatshop` encryption wrapper, hiding the embedded `.lnk` payload.

- **Attachment Security:** Inbound documents lacked macro and external link sanitization, enabling raw execution of **VBA Stomping** and external OLE object pulls.

- **Endpoint Hardening:** Lack of folder-path restrictions allowed malware to write directly to the Windows `Startup` directory and execute script code from user-writable space.


