# eCDFP Cheat Sheet

## Recovering Disk / MBR

**Lab Link:** [Recovering Disk / MBR](https://my.ine.com/CyberSecurity/courses/225b7429-bd2e-433e-9168-318d861e97cf/digital-forensics-file-disk-analysis/lab/917d247c-e2f7-4f71-ab53-dd3a211a121f)

**Tools:**  
- HEX Workshop  
- FTK Imager / Disk Editor  

**Location:** N/A (From an image file)  
**Syntax:** GUI / Hex editor  

**Notes:**  
- To fix an MBR if the Signature is missing, correct the MBR by replacing tampered bytes (prime example: MBR Signature `0x55aa`).
- If something else is corrupted in the MBR, use ChatGPT, but be careful not to go down a rabbit hole.

---

## Finding Hidden Partitions

**Lab Link:** [Finding Hidden Partitions](https://my.ine.com/CyberSecurity/courses/225b7429-bd2e-433e-9168-318d861e97cf/digital-forensics-file-disk-analysis/lab/7499f53e-db30-444c-b3b0-138c2bd2e774)

**Tool:**  
- Autopsy / Disk Editor  

**Location:** Based off disk image file  
**Syntax:** GUI - Instructions  

**Notes:**  
- Load the image into Autopsy and check the evidence tree for drives marked as `[Unallocated]`, especially gaps between partitions.
- Suspects may alter partition signatures or file systems; check for key files within each drive.

### Observations

| Task                            | Key Observations                                    | Tools & Methods            |
|----------------------------------|-----------------------------------------------------|----------------------------|
| Identifying Disk Partitions      | Check for primary, extended, logical partitions      | Autopsy, FTK Imager        |
| Detecting Partition Gaps         | Gaps may indicate manual modification               | Autopsy, Hex editor        |
| Checking File System Mismatch    | Partition type vs. actual file system mismatch      | Autopsy                    |
| Correcting MBR Partition Entries | Modified types prevent OS detection                 | Hex editor                 |
| Recovering Hidden Data           | Data in unallocated/hidden partitions               | Photorec, Foremost         |
| Analyzing Unallocated Space      | Hidden/deleted files in slack space                 | Bulk Extractor, Bstrings   |
| Detecting Malicious Modifications| Suspicious edits to MBR, GPT, partition table       | Autopsy                    |

---

## Search For Hidden Files

**Tool:** FTK Imager, Autopsy (for deeper searches)

**Syntax:** GUI - Instructions

### Search Methods

| Search Type           | Method                                    | Shortcut / Steps                                      |
|-----------------------|-------------------------------------------|-------------------------------------------------------|
| File Browsing         | Expand evidence tree and navigate folders  | File > Add Evidence Item → Expand partitions          |
| Search by File Name   | Use Find tool (Ctrl + F)                   | File > Find → Enter name → Click Find Next            |
| Search by Extension   | Sort by file type in file list             | View > File List → Sort by Extension                  |
| Keyword Search        | Search within file contents                | File > Find → Enter keyword → Select Text or Hex      |
| Search by File Sig.   | Uses hash values to ID file types          | File > Export File Hash List → Compare hashes         |
| Search Deleted Files  | Browse $Recycle.Bin or unallocated space   | Deleted Files folder in FTK Imager                    |
| File Filters          | Pre-set filters (images, docs)             | View > Filter → Select Documents, Pictures, etc.      |
| Sort by Metadata      | Organize by date, size, attributes         | View > File List → Sort columns (Date, Size, etc.)    |

---

## Recover and Analyze Registry

**Lab Link:** [Registry Lab](https://my.ine.com/CyberSecurity/courses/cd60ce4a-1b83-48c4-8d38-7e6bfeab4a1e/digital-forensics-system-network-forensics/lab/674ba4a3-d32c-402a-9daa-d4f2e1914560)

**Tool:** Registry Explorer  
**Location:** C:\Windows\System32\*  

**Common Registry Files:**  
- NTUSER.Dat  
- SAM  
- SYSTEM  
- SOFTWARE  
- SECURITY  

**Syntax:** GUI

**Notes:**  
- Load Offline Hive and open the SYSTEM file.
- Check for active Registry Control Set: look for the Current Value to identify the control set.

### Useful Registry Locations

| Category                  | Registry Location & Key                                                      |
|---------------------------|------------------------------------------------------------------------------|
| Computer Name             | SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName             |
| OS Information            | SOFTWARE\Microsoft\Windows NT\CurrentVersion                                 |
| Install Date              | SOFTWARE\Microsoft\Windows NT\CurrentVersion\InstallDate                     |
| Registered Owner          | SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOwner                 |
| System Root Directory     | SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot                      |
| Last Shutdown Time        | SYSTEM\ControlSet001\Control\Windows\ShutdownTime                            |
| Time Zone                 | SYSTEM\CurrentControlSet\Control\TimeZoneInformation\TimeZoneKeyName         |
| DST Active?               | SYSTEM\CurrentControlSet\Control\TimeZoneInformation\DynamicDaylightTimeDisabled|
| Last Logged-in User       | SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\LastLoggedOnUser |
| Number of Users           | SAM\SAM\Domains\Account\Users                                                |
| User SID and RID          | SAM\SAM\Domains\Account\Users\{User SID}                                     |
| User Profile Creation     | SAM\SAM\Domains\Account\Users\{User SID}\CreatedTime                         |
| Last Logon Time           | SAM\SAM\Domains\Account\Users\{User SID}\LastLogon                           |
| Logon Count               | SAM\SAM\Domains\Account\Users\{User SID}\LogonCount                          |
| Password Hint             | SAM\SAM\Domains\Account\Users\{User SID}\PasswordHint                        |
| Network Interface GUID    | SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\ProfileGuid|
| IP Address Assigned       | SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\DhcpIPAddress |
| DHCP Name Server          | SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\DhcpNameServer |
| Default Gateway           | SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\DhcpDefaultGateway |
| DHCP Lease Times          | SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\LeaseObtained / LeaseExpires |
| Firewall / RDP Status     | SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\GloballyOpenPorts |
| Installed Applications    | SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths                          |
| Suspicious RATs           | SOFTWARE\Microsoft\Windows\CurrentVersion\Run / RunOnce                      |
| Startup Applications      | SOFTWARE\Microsoft\Windows\CurrentVersion\Run / RunOnce                      |
| Opened Documents (Recent) | NTUSER.DAT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU |
| Last Opened File          | NTUSER.DAT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs     |
| Last Used Applications    | NTUSER.DAT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist     |
| Mounted Devices           | SYSTEM\MountedDevices                                                        |
| UserAssist Entries Count  | NTUSER.DAT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist     |
| UserAssist Encoding Type  | NTUSER.DAT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist     |
| Most Executed Software    | NTUSER.DAT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist     |
| Chrome Usage Count        | NTUSER.DAT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\F4E57C4B-2036-3D9F |
| Chrome Last Access Time   | NTUSER.DAT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\F4E57C4B-2036-3D9F |

---

## Recover and Analyze Recycle Bin

**Lab Link:** [Recycle Bin Lab](https://my.ine.com/CyberSecurity/courses/cd60ce4a-1b83-48c4-8d38-7e6bfeab4a1e/digital-forensics-system-network-forensics/lab/af74b04c-80f3-4cf8-ba97-9351a03069db)

**Tools:**  
- FTK Imager  
- rifiuti-vista.exe

**Location:** D:\$RECYCLE.BIN\S-1-5-21-[SID]\

**Syntax:** GUI

**Notes:**  
- Mount the image file with FTK Imager as a drive, then use rifiuti-vista.exe to analyze the bin:  
  ```
  rifiuti-vista.exe D:\$RECYCLE.BIN\S-1-5-21-[SID]\
  ```
- For $Ixxxxx files: original filename and path at byte offset 0x18.
- For $Rxxxxx files: try to find the matching $Ixxxxx file, otherwise inspect metadata.

---

## Recover USB Disk Traces

**Lab Link:** [USB Disk Lab](https://my.ine.com/CyberSecurity/courses/cd60ce4a-1b83-48c4-8d38-7e6bfeab4a1e/digital-forensics-system-network-forensics/lab/68b767cc-a1b3-4c25-b831-3bedf6a20397)

**Tool:** Regripped  
**Location / Files:** C:\Windows\System32\*  
**Registry Locations:**  
- SYSTEM\CurrentControlSet\Enum\USBSTOR (metadata of disks)
- NTUSER.DAT\Microsoft\Windows\CurrentVersion\Explorer\MountPoints (users accessed and mounted disks)

**Notes:**  
- Search for MountedDevices and MountPoints2 in registry hives.

---

## Analyze Windows Artifacts

### Searches

**Lab Link:** [Searches Lab](https://my.ine.com/CyberSecurity/courses/cd60ce4a-1b83-48c4-8d38-7e6bfeab4a1e/digital-forensics-system-network-forensics/lab/dc2f77c5-d52b-4550-a584-46c1a6670a7d)

**Tool:** lecmd.exe  
**Location:**  
- `%USERPROFILE%\AppData\Local\Microsoft\Windows\ConnectedSearch\History`  
- `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\`  

**Syntax:**  
```shell
.\LECmd.exe -d %USERPROFILE%\AppData\Local\Microsoft\Windows\ConnectedSearch\History
```

**Notes:**  
- `_site` files are websites visited, `_txt` files are search queries.
- lnk files in Recent show opened docs/folders.

---

### Shell Bags (UsrClass.dat)

**Tool:** shellbagsexplorer.exe  
**Location:** `%USERPROFILE%\AppData\Local\Microsoft\Windows\usrclass.dat`  
**Syntax (CLI):**  
```shell
SBECmd.exe -d "%USERPROFILE%\AppData\Local\Microsoft\Windows\usrclass.dat" --csv Results\
```

**Notes:**  
- Drag and drop usrclass.dat into Shellbags Explorer.
- Check for accessed folders, control panel, downloads, libraries, etc.

---

### Prefetch Files

**Tool:** WinPrefetchView  
**Location:** `%windir%\prefetch`  
**Syntax:** GUI  
- Analyze different prefetch directories: Options → Advanced Options → Path of Evidence

**Notes:**  
- Hash value is in the exe name (e.g., zenmap.exe-[hashvalue].pf).

---

### Thumbnails / Cache

**Tool:** thumbcache_viewer  
**Location:** `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer`  
**Syntax:** GUI

**Notes:**  
- Open multiple db files at once; manually browse for evidence.

---

### Jump List

**Tool:** JumpListExplorer  
**Location:**  
- `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations`  
- `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`  
**Syntax:** GUI

**Notes:**  
- Double click an item to get its full path.
- Created/modified dates help with timelines.

---

### User Libraries

**Tool:** Notepad / Hex editor  
**Location:** `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Libraries`  
**Syntax:** GUI

**Notes:**  
- Library files are XML; reveal directories users included in their libraries.

---

## Analyze Network Attacks

**Lab Link:** [Network Attack Lab](https://my.ine.com/CyberSecurity/courses/cd60ce4a/digital-forensics-system-network-forensics)  
**Tool:** Wireshark  
**Syntax:** GUI / Query-based

### Network Attacks

| Attack Type           | Detection Method                                  | Key Indicators                           | Wireshark Filters                          |
|-----------------------|---------------------------------------------------|------------------------------------------|---------------------------------------------|
| MAC Flooding          | Excessive random MAC addresses                    | High volume, unknown MACs                | `eth.addr` high variation                   |
| ARP Poisoning         | ARP replies without requests, conflicting MACs    | Gateway MAC conflicts                    | `arp`, `arp.opcode == 2`                    |
| SYN Flood (DoS)       | Excessive SYN, no ACK                             | Unfinished TCP handshakes                | `tcp.flags.syn == 1 && tcp.flags.ack == 0`  |
| DNS Amplification     | Large responses to small requests                 | Large DNS payloads                       | `dns`, `udp.length > 512`                   |
| ICMP Flood            | Excessive Echo requests                           | Continuous pings                         | `icmp.type == 8`                            |
| DHCP Starvation       | Excessive Discover packets, APIPA addresses       | No assigned IPs                          | `dhcp.option.dhcp_message_type == 1`        |
| Rogue DHCP Server     | Multiple DHCP Offers                              | Conflicting servers                      | `dhcp.option.dhcp_message_type == 2`        |
| MITM                  | ARP/DNS/SSL anomalies                             | Unexpected replies, cert mismatches      | `arp`, `ssl.alert_message`                  |
| Port Scanning         | Sequential attempts on ports                      | SYNs to different ports                  | `tcp.flags.syn == 1 && tcp.flags.ack == 0`  |
| SMB Relay Attack      | NTLM auth over SMB                                | Unexpected auth requests                 | `smb`, `ntlmssp.auth`                       |
| SNMP Enumeration      | Excessive SNMP Get requests                       | Unauthorized UDP 161 queries             | `udp.port == 161`                           |
| Rogue AP (Wi-Fi)      | Duplicate SSIDs, unauthorized BSSIDs              | Unexpected APs                           | `wlan.ssid`                                 |
| Packet Injection      | Unexpected packet types                           | Malformed packets                        | `tcp.analysis.flags`                        |
| Remote Access Backdoor| Unusual outbound traffic                          | Non-standard ports, unknown IPs          | `tcp.port == 6666`, `icmp contains "data"`  |

### Web Attacks

| Attack Type           | Detection Method                                  | Key Indicators                           | Wireshark Filters                          |
|-----------------------|---------------------------------------------------|------------------------------------------|---------------------------------------------|
| SQL Injection         | HTTP logs for SQL commands                        | `' OR 1=1 --`, `UNION SELECT`            | `http.request.uri contains "SELECT"`        |
| Local File Inclusion  | File path traversal attempts                      | `../../etc/passwd`, `%2e%2e%2f`          | `http.request.uri contains "../"`           |
| Remote File Inclusion | External script execution                         | `http://malicious.com/shell.txt`         | `http.request.uri contains "http://"`       |
| Directory Traversal   | Encoded directory traversal patterns              | `/etc/passwd`, `../win.ini`              | `http.request.uri contains "../"`           |
| Cross-Site Scripting  | `<script>` tags, encoded payloads                 | `<script>alert('XSS')`                   | `http.request.uri contains "<script>"`      |
| Command Injection     | Shell command separators                          | `; cat /etc/passwd`, `&& whoami`         | `http.request.uri contains "&&"`            |
| HTTP Header Attacks   | Host/User-Agent/X-Forwarded-For abuse             | Spoofed headers                          | `http.header contains "X-Forwarded-For"`    |
| SYN Flood (DoS)       | High SYN, no ACK                                  | SYN requests only                        | `tcp.flags.syn == 1 && tcp.flags.ack == 0`  |
| DHCP Starvation       | Excessive Discover packets                        | APIPA addresses                          | `dhcp`, `dhcp.option.dhcp_message_type == 1`|
| Brute Force/Cred Stuff| Multiple failed logins                            | Many 401 Unauthorized                    | `http.request.method == "POST"`<br>`http.request.uri contains "login"`|
| Web Shell Detection   | Suspicious PHP uploads / responses                | `cmd.php`, `shell.php`                   | `http.request.uri contains ".php"`          |
| Remote Access Backdoors| Unknown protocol or port usage                   | TCP 6666, unusual ICMP                   | `tcp.port == 6666`, `frame contains "data"` |

---