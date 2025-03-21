---
layout: post
title: "HTB Visual: Walkthrough"
date: 2024-11-28 10:00:00 +0000
categories: [HTB]
tags: [HTB, CVE, Sudo, Port Forwarding]
image:
  path: https://raw.githubusercontent.com/partyh4t/partyh4t.github.io/refs/heads/main/assets/posts/Headers/HTB.png
---

![image](https://github.com/user-attachments/assets/4d129dac-54c4-425e-bc72-7caa603ebd36)

This is a relatively short machine, starting off with a web app that allows us to submit a github repo for the program to compile for us via Visual Studio. We can use EvilSln to exploit a vulnerability in VS to gain RCE on the target. This is then followed by an abuse of SeImpersonatePrivilege to gain Administrator access.

## 0) Machine Overview
1. [Scans](#1-scans)
2. [Web Enumeration](#2-web-enumeration)
4. [Privilege Escalation](#3-privilege-escalation)

## 1) Scans
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
|_http-title: Visual - Revolutionizing Visual Studio Builds
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (87%)
```

## 2) Web Enumeration

![image](https://github.com/user-attachments/assets/48b6ed67-4372-46cc-9283-20a1c5217045)

So here we have a web application that basically offers to compile our code for us, using Visual Studio. I tried putting a random GitHub repo of mine:
![image](https://github.com/user-attachments/assets/1d143738-925b-4287-9224-e46691c432d9)

So I started researching of ways to potentially exploit this, and almost instantly, I came across [this](https://github.com/cjm00n/EvilSln).
![image](https://github.com/user-attachments/assets/9fdf1b4b-7030-4b7b-be6d-350a5cf28302)

After reading it, it gives a brief explanation about multiple "vulnerabilities" within Visual Studio which Microsoft doesn't seem to even consider as vulnerabilities. So we can leverage this to make our `.csproj` program execute code before being compiled. Once that's done, we can host a Git repository locally, since the machine isn't connected to the internet.

1) Create our repository:
```
dotnet new console -n fakedotnet
```

2) Create a new `.sln` file:
```
cd fakedotnet
dotnet new sln -n fakedotnet
dotnet sln fakedotnet.sln add fakedotnet.csproj
```

3) Commit our changes:
```
git init
git add .
git commit -m 'test1'
```

4) Update the server info and host the server:
```
cd .git
git --bare update-server-info
python3 -m http.server 9000
```

5) Lastly, if we ever need to perform a change:
```
git add . (from fakedotnet directory)
git commit -m 'test2'
cd .git
git --bare update-server-info
```

With that, assuming we have the proper payload within our `.csproj` file, we have RCE:

![image](https://github.com/user-attachments/assets/f0ed7fc2-b2ce-41f8-9e07-0c7028bf25d1)

Then upload our file:

![image](https://github.com/user-attachments/assets/811caeda-2cbc-4059-a4bb-792b530b1248)

Works perfect.

![image](https://github.com/user-attachments/assets/8fc07f92-7f0e-4b59-8b52-40613f884367)

Lets try and get a shell now.

![image](https://github.com/user-attachments/assets/5416cc1b-3cc7-4d86-b8e0-76be0482495a)

Upload our file, and then:

![image](https://github.com/user-attachments/assets/d3301f58-7121-46d6-9c2d-33866d4b7c4b)

## 3) Privilege Escalation

Now that I had a shell, I tried running WinPEAS and PowerUp, but didn't find anything too interesting. Now one cool thing I learnt to start doing recently was to run `tasklist /v` if there is a web-application running, and see under what context its running as. Most of the time it'll just say N/A but that doesn't tell the full story. In this case, I uploaded my own PHP web-shell to the `C:\xampp\htdocs\` directory, to see who's actually running the web-server. In this case, it was `nt_authority/local service`. 

![image](https://github.com/user-attachments/assets/d14ac464-b5b9-4468-9e7b-795374c77b51)

So I decided to look into privilege escalation methods from `local service`.

I came across a super useful tool called FullPowers. 

_**[FullPowers](https://github.com/itm4n/FullPowers)**_ is a Proof-of-Concept tool made for automatically recovering the **default privilege set** of a service account including **SeAssignPrimaryToken** and **SeImpersonate**.

Lets give it a try:

![image](https://github.com/user-attachments/assets/3b3dfe4c-b806-4718-973c-98cf5373b2d2)

Caught the shell, and as we can see, we have all the privileges we wanted :)

![image](https://github.com/user-attachments/assets/a07542d6-d501-4890-88fe-6f10f63c7656)

Then can either go the easy route and upload a meterpreter shell and use `getsystem`:

![image](https://github.com/user-attachments/assets/bc39b9b9-ea1e-4cc3-8937-77a670ec2a2e)

Or do it manually using `EfsPotato`: _(Could have used [GodPotato](https://github.com/BeichenDream/GodPotato) as well, since I think this gives the best versatility and no need to compile.)_
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe EfsPotato.cs -nowarn:1691,618
```

![image](https://github.com/user-attachments/assets/dc4f6956-f567-4b31-89ea-06c2567a2424)

![image](https://github.com/user-attachments/assets/0c3f6854-cb0f-4ada-807a-ce97087208cf)

Pwned.

----
