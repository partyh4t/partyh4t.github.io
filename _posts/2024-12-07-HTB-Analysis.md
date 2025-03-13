---
layout: post
title: "HTB Analysis: Walkthrough"
date: 2024-12-07 10:00:00 +0000
categories: [HTB]
tags: [HTB, Active Directory, LDAP Injection, DLL Hijacking]
image:
    path: https://raw.githubusercontent.com/partyh4t/partyh4t.github.io/refs/heads/main/assets/posts/Headers/Analysis.png
---

![image](https://github.com/user-attachments/assets/dfd701f8-8e96-4499-9919-a72adeb44b47)

This machine starts off with a directory fuzzing attack on a web server being hosted on the target. This leads to the identification of an directory that's vulnerable to a LDAP injection attack within the `?name` parameter. This gives access to a users password that we can use to login to a SOC dashboard, which contains a file upload module, allowing us to upload a web shell and gain a foothold onto the system. To escalate privileges, we utilize `winpeas.exe` to identify autologon credentials for a domain user, allowing us to win-rm into the machine. The escalation to root involves a DLL Hijacking misconfiguration on the target pertaining to `snort.exe`.

### 0) Machine Overview
1. [Scans](#1-scans)
2. [Web Enumeration](#2-web-enumeration)
3. [RPC Enumeration](#3-rpc-enumeration)
4. [Web Enumeration (Revisited)](#4-web-enumeration-revisited)
5. [Privilege Escalation 1](#5-privilege-escalation-1)
6. [Privilege Escalation 2](#6-privilege-escalation-2)

### 1) Scans

```
Nmap scan report for 10.10.11.250
Host is up (0.026s latency).
Not shown: 989 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-25 00:11:18Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3306/tcp open  mysql         MySQL (unauthorized)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
33060/tcp open  mysqlx?
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0
Service Info: Host: DC-ANALYSIS; OS: Windows; CPE: cpe:/o:microsoft:windows

```
### 2) Web Enumeration
![image](https://github.com/user-attachments/assets/46e4e6c2-4759-4739-a059-794e679c1367)

Interesting Directories:
`analysis.htb/bat` 403
`internal.analysis.htb/dashboard` 403
`internal.analysis.htb/employees` 404/403?

In this case, there isn't much for us to do, I tried lots of directory bruteforcing, but nothing too interesting popped out, so I decided to look into some other avenues.

### 3) RPC Enumeration

The reason I'm trying this after the web enumeration was because, I had originally exhausted all options except port 80, until I realized this exact command that I had run earlier, hadn't worked originally, but now it did:

![image](https://github.com/user-attachments/assets/00a3f2ce-27c9-44a2-a7ae-3aa4e2dbb8b7)

With us able to connect to msrpc using a null session, we have lots we can mess with.

I first tried lookupsids.py from impacket, but had no luck. Usually one other thing I like doing in these cases is trying kerbrute to see if i can find any usernames:

![image](https://github.com/user-attachments/assets/f7632946-1263-4807-a899-67ec785f38f6)
Indeed we can.
At this point, I had tried tons of things, like bruteforcing multiple services, password spraying, asrep-roasting, but none of it worked. That's when I went back to directory bruteforcing, sensing that there must be something behind those directories in that subdomain.

### 4) Web Enumeration Revisited

Earlier, I had discovered some interesting endpoints like:
`/users, /employees, /dashboard`. One misconception I had was that if the server was IIS, it wouldn't use PHP. I always assumed `nginx/apache = .php`, and `IIS = .asp/aspx` , but I was wrong.

This time i tried my bruteforce with -x php, and discovered many interesting things, the most interesting being this endpoint:

![image](https://github.com/user-attachments/assets/371e2466-d079-498c-90da-001dd3c89bf3)

When I accessed it, it returned: `missing parameter`

Well, lets try fuzzing the parameter:

![image](https://github.com/user-attachments/assets/3438e02d-0589-4821-9f6e-668ffec3946a)

And now if we access that, we're returned with some interesting information.

![image](https://github.com/user-attachments/assets/407f6f64-db4e-4c2d-8ac5-98c099d8b540)

So its clearly pulling lots of information, and we can assume it may even be via LDAP. So I tried providing the names I found earlier through kerbrute. (We also could have fuzzed the endpoint again with a user-list.)
![image](https://github.com/user-attachments/assets/546bcee6-2dad-459a-a0c4-271b3f74bfae)

This is interesting as, its almost as if its taking our input and using it directly performing an LDAP query with it.... What if we could inject our own LDAP query alongside it?

Confirmation it is indeed injectable:

[*(PaylaodsAllTheThings Example Payloads)*](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/LDAP%20Injection/README.md)
[*(Default Attributes)*](https://www.phpldaptools.com/reference/Default-Schema-Attributes/)

![image](https://github.com/user-attachments/assets/9e68e2df-88e7-4ac9-ad56-5b06a32e3784)
![image](https://github.com/user-attachments/assets/8aa17202-4e61-4a20-bf63-0629ec02b85f)

I tried many attributes, especially userPassword, but none really stood out.

So I decided to try fuzzing the description attribute for technician since it was the only one that returned like, a proper response that showed that the query was successful.

We can do that by first putting in random characters before the \*, and seeing what resolves.

We could have written a script for this, but my scripting skills are not up to par at the moment, so I did it manually:
```
ffuf -u '<http://internal.analysis.htb/users/list.php?name=technician>)(description=FUZZ*' -w wordlist2.txt -fs 406
```

Which returned:

![image](https://github.com/user-attachments/assets/d305e5a7-b142-49c0-b63a-2a31f4e89fc7)

In this case, we're looking for 418's in the size.

Then we can just add 9 and do description=9FUZZ* and proceed all the way until:
```
ffuf -u '<http://internal.analysis.htb/users/list.php?name=technician>)(description=97NTtl*4QP96BVFUZZ*' -w wordlist2.txt -fs 406
```

![image](https://github.com/user-attachments/assets/bb2173ee-8bad-482e-9825-a6b5d6096e11)

At this point it only returned some special characters which tend to conflict with the query, so we have to take these 418's with a grain of salt, albeit it one of the characters in the description does actually end up being a *.

I went to check to make sure if I had hit the final character:
`http://internal.analysis.htb/users/list.php?name=technician)(description=97NTtl*4QP96BV` (Exclude `*`)

![image](https://github.com/user-attachments/assets/af0a3aaf-5117-4615-b1e8-69fb9706cb7c)


And as we can see, the query resolved/responded like we expected. Lets go and see if this 97NTtl*4QP96BV password means anything for us.


Trying it on /employees/login.php, which was one of the endpoints I discovered earlier when FUZZing, gives us access to an Admin Dashboard:

![image](https://github.com/user-attachments/assets/1eabee50-761d-46c9-8da5-1c35cfe73d27)

Within the admin panel, there is a file upload section:

![image](https://github.com/user-attachments/assets/a666a1bf-aa8c-44a7-95c2-aeddbab5a595)

So I uploaded pownyshell.php, and headed to /dashboard/uploads/pownyshell.php:

![image](https://github.com/user-attachments/assets/1067dbc1-6eab-4201-93e0-c28d6b1255e9)

Lets leverage this to get a full meterpreter session:

![image](https://github.com/user-attachments/assets/4473b49e-f210-46ba-80c1-87638fa60102)


### 5) Privilege Escalation 1

Did quite a bit of manual enum, but nothing looked too promising at the moment. So I decided to run winPEASx64.exe

Thanks to it, we found some autologon credentials belonging to jdoe, which we can use to win-rm into the machine:
![image](https://github.com/user-attachments/assets/c9773d74-97f2-4349-ac16-7bce9b5ea5e1)

### 6) Privilege Escalation 2

Lets run WinPEAS again, maybe our new user will have some interesting privileges over something:
![image](https://github.com/user-attachments/assets/56c3b751-bef0-4f9e-acce-29ea3c78c69a)

I checked if I had write privileges to the BCTextEncoder directory originally, as maybe i could write my own BCTextEncoder.exe file, but I couldnt.

So I made my own run.bat file that would run nc64.exe:

![image](https://github.com/user-attachments/assets/c99b3ba1-ac4b-4ca9-8727-f2b7e6b35bef)

Once I had it on the machine, we did actually get a call back, but unfortunately it was as jdoe, and not Administrator. Im not exactly sure why thats the case, as it seemed that it was going to be run by Administrator. Nevertheless, I had one more thing to check:

![image](https://github.com/user-attachments/assets/b9345b00-6e59-4435-be6f-e0bf96d0017c)

Seems theres a snort.exe service that run's occasionally, and we have write privileges to most of the Snort directory. DLL Hijacking it is.

Now it wasn't that simple originally, as I assumed I could either just write one of the DLL's in the bin directory into the previous directory, hoping it would execute it instead of the one in `/bin`:

![image](https://github.com/user-attachments/assets/95dbc7c9-6b68-44cb-98dc-c02253c70ebe)

So I named it `wpcap.dll`, and tried running the executable myself, and also waiting to see if it would ever call back to listener. It didn't. Eventually I decided to actually do my due-diligence and look through some of the directories in Snort and read some documentation. That's where I found out that any DLL's placed within the `C:\\Snort\\lib\\snort_dynamicpreprocessor` would get executed:

![image](https://github.com/user-attachments/assets/3c3fe12e-6ba3-4d6d-bb7e-845b07c4c286)

So I did just that, placed test.dll within the directory, and sure enough within a few minutes, I got a call back:

![image](https://github.com/user-attachments/assets/fc123d8b-bb2a-4832-a233-051123573cbb)

![image](https://github.com/user-attachments/assets/4bc584ca-2e72-4daf-8ad8-27bcb315cdb1)


*One thing to take away from this priv-esc is that its always worth checking where certain files may be stored, and reading documentation to find how an executable may be calling certain DLL's.*












