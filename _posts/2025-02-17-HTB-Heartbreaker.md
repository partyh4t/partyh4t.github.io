---
layout: post
title: "HTB Heartbreaker: Walkthrough"
date: 2025-02-17 11:00:00 +0000
categories: [HTB]
tags: [HTB, Sherlock, ]
image:
    path: https://raw.githubusercontent.com/partyh4t/partyh4t.github.io/refs/heads/main/assets/posts/Headers/Heartbreaker.png
---

![image](https://github.com/user-attachments/assets/a307d9ae-40f0-4261-a4fb-553c8ac6f0b5)

This sherlock investigates a potential breach of a customers database. It involves scrutinizing an email received by one of their employees, comprehending the implications, and uncovering any possible connections to the data breach.

## 0) Walkthrough
1. The victim received an email from an unidentified sender. What email address was used for the suspicious email?

We’re provided with a backup/export of the compromised workstation’s filesystem.

First, I decided to explore the user’s appdata folder, and found a .ost file, which is an export of emails, contacts, and other data from a user’s outlook for offline viewing. We can load it into XstReader from github, and view it.

![image](https://github.com/user-attachments/assets/11d4fe14-dfde-499f-b3c6-ae6fd61c7493)

![image](https://github.com/user-attachments/assets/076adcc4-600c-4068-90ae-cdb8f87efec7)
As we can see, there is an interesting and suspicious email with an embedded file.

We can go to the properties and see the senders email:
![image](https://github.com/user-attachments/assets/b139cfff-fe87-4701-9d87-85d0c734dc16)

2. It appears there's a link within the email. Can you provide the complete URL where the malicious binary file was hosted?

We can right click the link and copy the shortcut and paste it and we see:
```
http://44.206.187.144:9000/Superstar_MemberCard.tiff.exe
```

3. The threat actor managed to identify the victim's AWS credentials. From which file type did the threat actor extract these credentials?

Most likely through the .ost file we’re currently viewing now, which contains some credentials in the drafts.

4. Provide the actual IAM credentials of the victim found within the artifacts.

These are the keys within the drafts of the .ost file:
```
Access key ID:Secret access key

AKIA52GPOBQCK73P2PXL:OFqG/yLZYaudty0Rma6arxVuHFTGQuM6St8SWySj
```

5. When (UTC) was the malicious binary activated on the victim's workstation?
Lets investigate the prefetch file for the binary, maybe it can tell us when it was created/last ran:
```
 & \ZimmermanTools\net6\PECmd.exe" -f .\Windows\prefetch\SUPERSTAR_MEMBERCARD.TIFF.EXE-C2488B05.pf
```
![image](https://github.com/user-attachments/assets/f7cdf369-3850-4f51-b7e5-823e0d27bfee)


6. Following the download and execution of the binary file, the victim attempted to search for specific keywords on the internet. What were those keywords?
   
We can access the user’s firefox places.sqlite db and check for their search history:
```
/wb-ws-01/C/Users/ash.williams/AppData/Roaming/Mozilla/Firefox/Profiles/hy42b1gc.default-release$/sqlite3/places.sqlite
```

We can see quite a few searches all relating to superstar cafe membership:
![image](https://github.com/user-attachments/assets/156f9f29-b34d-4aec-9cca-02c2b6986c0d)


7. At what time (UTC) did the binary successfully send an identical malicious email from the victim's machine to all the contacts?
We can check the .ost file again and see:

![image](https://github.com/user-attachments/assets/b071b94b-dece-4e31-9ba4-d14b6a043c1e)

8. How many recipients were targeted by the distribution of the said email excluding the victim's email account?

![image](https://github.com/user-attachments/assets/87a9dd03-935c-4a09-b313-980a8e6755f8)
Counting them, we get 58. (Probably a better way to see but im an idiot :D)

9. Which legitimate program was utilized to obtain details regarding the domain controller?
We can utilize chainsaw to sift through the evtx logs on the machine, and look for any instances of the Superstar_MemberCard.tiff.exe binary.
```
./chainsaw.exe search "Superstar_MemberCard" C:\Users\Zayd\Downloads\wb-ws-01\C\ --skip-errors
```

After looking through lots of output, we notice an event on sysmon ID 10, which is Process Access, on nltest.exe which is a binary used to obtain a list of domain controllers.

![image](https://github.com/user-attachments/assets/8a479ccd-cd35-4c4d-ac70-2a3b353e023a)

10. Specify the domain (including sub-domain if applicable) that was used to download the tool for exfiltration.

I tried using chainsaw for this again, but the fact I cant specify an event id but also a specific string to look for, made it quite difficult to filter for what I needed, so I loaded the sysmon log into Event Viewer , and filtered for id 22 for DNS queries, and specified the Super string:

![image](https://github.com/user-attachments/assets/94d634a3-8b5b-48e9-8b2c-2abfc20e9cd4)


11. The threat actor attempted to conceal the tool to elude suspicion. Can you specify the name of the folder used to store and hide the file transfer program?

The dns query was performed at `2024-03-13 10:45:20.904`, so we can look for any events right around after that query:

![image](https://github.com/user-attachments/assets/af36f3c6-a187-4565-8e39-3061b2bb51f5)


Then when the attacker unzipped it, we can find where the binary was stored on event id 11:

![image](https://github.com/user-attachments/assets/f1149076-32f0-46ec-97a8-7e7f1dcd30ef)


12. Under which MITRE ATT&CK technique does the action described in question #11 fall?

![image](https://github.com/user-attachments/assets/aa4b8c8d-cec3-436c-b937-405d8a47c9b3)

13. Can you determine the minimum number of files that were compressed before they were extracted?

We can utilize chainsaw again, and grep for any `TargetFileName` instances, which should help us filter out any files that have been created/modified, but chances are if we `uniq` the results, we should be able to discern how many files exactly were extracted.
```
./chainsaw.exe search "Superstar_MemberCard.tiff.exe" C:\Users\Zayd\Downloads\wb-ws-01\C\Windows\System32\winevt\ --skip-errors | Select-String -Pattern "TargetFileName" > files.txt
```

Then on linux:
```
iconv -f UTF-16 -t UTF-8 files.txt > new_files.txt
cat new_files.txt | tr -d ' ' > out.txt
cat out.txt | grep "PublicFiles" | sort | uniq > final.txt
cat final.txt | wc -l

29
```

Now 29 isnt the right answer, since there are 2 zip files and the directory itself which weren’t necessarily “Extracted” with from the zip file:

![image](https://github.com/user-attachments/assets/37b48ea8-7191-4692-8bd9-cdf5b46f1000)

![image](https://github.com/user-attachments/assets/eac90448-4433-4b29-a15c-3c4680bcecd7)

So the answer is 26.


14. To exfiltrate data from the victim's workstation, the binary executed a command. Can you provide the complete command used for this action?

We can filter for Event id 1 and look for any process creations from WinSCP.exe:

![image](https://github.com/user-attachments/assets/71acc954-152b-45d5-896d-d7c188e3eb90)


