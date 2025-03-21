---
layout: post
title: "HTB Manager: Walkthrough"
date: 2024-12-07 10:00:00 +0000
categories: [HTB]
tags: [HTB, Password Spraying, MSSQL, ADCS]
image:
  path: https://raw.githubusercontent.com/partyh4t/partyh4t.github.io/refs/heads/main/assets/posts/Headers/HTB.png
---

![image](https://github.com/user-attachments/assets/0cae96c0-39b3-415b-b0a0-0f2a75511f9a)

This machine begins with a password spray on the machine, which is domain joined, giving us access to a domain user with MSSQL access. We utilize our MSSQL access to find a `backup.zip` file within the webroot of a webserver, which contains an old xml file with credentials for another domain user. We can use these credentials to exploit a misconfigured ADCS template, and gain Administrator access to the machine.

## 0) Machine Overview
1. [Scans](#1-scans)
2. [SMB & RPC Enumeration](#2-smb-&-rpc-enumeration)
3. [MSSQL](#3-mssql)
4. [Privilege Escalation](#4-privilege-escalation)



## 1) Scans
```
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds?
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.10.11.236:1433: 
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
```

Enum4Linux:

![image](https://github.com/user-attachments/assets/5d0ac41d-077e-4d60-aa99-38d63950ff85)


## 2) SMB & RPC Enumeration

Couldn't do much with the SMB shares.

![image](https://github.com/user-attachments/assets/083973a2-d3f7-46fd-9899-866695c1cb09)

Lets mess with msrpc and see what we can do.

First, when connecting with a random user, it returns a ACCESS_DENIED.

However, if we try to connect with a blank user:

![image](https://github.com/user-attachments/assets/f7540297-9167-4eb3-84f7-60671c1e2c1e)

This is where things get interesting. If we check what user we currently are:

![image](https://github.com/user-attachments/assets/9cb9a1cf-9293-417c-afdb-d8e8295e0965)

This actually opens a lot of doors for us. One door is try this username with quite a few impacket scripts and see what kind of information we can pull from the domain. _(You could also try `querydispinfo` or `enumdomusers` within rpcclient, however in this case we are denied)_

I started doing some research on what scripts would be of use in situations like this, and one that instantly caught my eye was `lookupsid.py`, which basically brute-forces SID's: _(We could have also used kerbrute with a username list if we wanted to find users)_

![image](https://github.com/user-attachments/assets/7e428da5-3b46-4775-b4f4-438e506394a9)

![image](https://github.com/user-attachments/assets/5d7d58b6-a202-406e-b616-6b7fd940f9a0)

Now we have a list of users that exist within the domain. There's lots we can try now.

I tried seeing if any of the user's were AS-REP Roast-able, but they weren't. So lets try password spraying with CME:

One thing you can always do before you try a more proper password spray, is just use the usernames as the password list:

![image](https://github.com/user-attachments/assets/8dcaf487-8b25-42d6-85ce-c5ec6a007131)

![image](https://github.com/user-attachments/assets/60ac0888-fa64-4db0-8430-c8a2557402db)

Perfect. Lets see what access this can give us now.

Firstly, we can run most commands now through rpcclient:

![image](https://github.com/user-attachments/assets/7841deb3-c34b-45c3-9a64-1654741d8416)

Doesn't give us much through SMB.

Let's try dumping the LDAP Server:

![image](https://github.com/user-attachments/assets/df7bbd3c-ac7a-4a0b-a47d-da23bd0baea9)

`sudo ldapdomaindump 10.10.11.236 -u 'manager.htb\operator' -p 'operator' --no-json --no-grep -o ldap-dump`

Not much there either. 

## 3) MSSQL

Lets try the creds on the MSSQL server: (Be sure to add `-windows-auth` or else it will not work.)
![[Pasted image 20240110193214.png]]

We cant execute `xp_cmdshell` commands just yet. So we'll have to enumerate a bit. 

Apparently, you can read certain files with the `xp_dirtree` command thanks to [this](https://www.sqlservercentral.com/blogs/how-to-use-xp_dirtree-to-list-all-files-in-a-folder) article:

![image](https://github.com/user-attachments/assets/c874154e-708e-4ef4-bb38-2de2103baa4e)

Lets checkout the web-server's file's, usually stored in `C:\inetpub\wwwroot`:

`EXEC master.sys.xp_dirtree 'C:\inetpub\wwwroot',0,1;`
_(We added a 1 at the end as well here to display files, or else it would have just displayed folders)_

Very interestingly, we can find that there's a backup.zip file within the webroot:

![image](https://github.com/user-attachments/assets/d70d6ef8-a13c-43dd-9944-fc920a2e0965)

Which means, if we access that directory through a URL:

![image](https://github.com/user-attachments/assets/3dae5a76-33ef-4fe5-829b-f506801ec86c)

Once we unzip the folder, we can run an `ls -la` and instantly something stands out:

![image](https://github.com/user-attachments/assets/21a1fee6-1f0d-4bb5-82d0-6382577bb052)

![image](https://github.com/user-attachments/assets/a92e1e45-c27f-4bfc-a81d-0b8853d2e6dd)

Credentials. `raven:R4v3nBe5tD3veloP3r!123`

Lets try it on winrm:

![image](https://github.com/user-attachments/assets/8d147423-020e-42f8-930d-e3f749583abb)

## 4) Privilege Escalation

Lets run Bloodhound first:
`bloodhound-python -c all -u raven -p 'R4v3nBe5tD3veloP3r!123' --zip -d manager.htb -ns 10.10.11.236`

Didn't find anything noteworthy. Lets see what AD CS has in store for us.

The article I'm following in this scenario is again, [HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates#a-d-cs-enumeration). It basically shows that we can run tools like `Certipy` or `Certify`, and apparently there are a ton of potential misconfigurations that we can leverage for Privilege Escalation, Persistence, and so on.

For this machine, I'm going to be trying `certipy`, as it can also generate output for BloodHound.

![image](https://github.com/user-attachments/assets/46d8816d-466c-4314-bfaf-f8eaa901d5e1)

You could import it into bloodhound, but it isn't working for me in this case, so i'll resort to manual enumeration alongside HackTricks.

![image](https://github.com/user-attachments/assets/864b1383-74d5-4b58-aa5c-41abb3b0552d)

Seems we have dangerous permission's with the vulnerability being [ESC7](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#vulnerable-certificate-authority-access-control-esc7):

Attack 1 (Which has certain limitations listed in the article, like having to restart the CA service)

![image](https://github.com/user-attachments/assets/4906229c-487c-483a-a8e9-e066c2e191d1)

OR

Attack 2

![image](https://github.com/user-attachments/assets/852db652-eb1f-4dbf-a369-6bec83fb72d3)

Ill be trying Attack 2: ([Certipy's](https://github.com/ly4k/Certipy?tab=readme-ov-file#certificates) README.md shows how to exploit each ESC)

**NOTE: the server seems to reset its settings automatically quite quickly, so we have to be relatively fast and issue the commands in quick succession.**

Adding `raven` as an officer to be able to manage certificates:

![image](https://github.com/user-attachments/assets/11623cee-666e-4b1e-b45d-91d9d6cd9df8)

Enabling the SubCA Template:

![image](https://github.com/user-attachments/assets/972a22bb-d3b4-4e34-b96c-184a55189fbc)

Requesting a certificate based on the SubCA Template, then saving the private key and noting down the request ID. _(`manager.htb` would have worked as well for the `-target`)_

![image](https://github.com/user-attachments/assets/e9db8dbb-3c61-482b-9ef4-0183f052b32e)

Issue the certificate ourselves:

![image](https://github.com/user-attachments/assets/c78a5d56-4276-4539-9f95-86cb4d36461d)

Retrieve the issued certificate:

![image](https://github.com/user-attachments/assets/f4db1a23-55e3-4c8c-8e43-d4d1d9be55ee)

Finally, authenticate:

![image](https://github.com/user-attachments/assets/ee4aaf33-78e2-44f7-b2a2-e2e2b421614f)

If you find this **error** from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)` its because of your local time, you need to synchronize the host with the DC. There are a few options:

- `ntpdate <IP of DC>` - Deprecated as of Ubuntu 16.04
- `rdate -n <IP of DC>`

![image](https://github.com/user-attachments/assets/699c2c14-6b78-4ef1-b5f1-064dd0ca5199)

![image](https://github.com/user-attachments/assets/7d5e04ea-e22e-4639-807d-581d4950f31b)

![image](https://github.com/user-attachments/assets/ae18cb94-53e5-4d6a-872c-f99cbc2ac2c9)

Then if we want to re-enable ntp, just `timeatectl set-ntp on`.

Finally, lets PtH with administrator's hash:

![image](https://github.com/user-attachments/assets/6b732265-63b8-4f22-b371-aa9d2e189f66)

Pwned.

----

