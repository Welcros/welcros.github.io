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
  - 
  - 
---

![](/assets/images/htb-writeup-sense/sense_logo.png)

# Description

Description

# Recognition phase

This time I will be testing a script made by [Rana Khalil](https://ranakhalil101.medium.com/), I saw it in one of his writeup and I found it very interesting to leave it doing passive recognition while I enumerate manually.

The script quickly shows us which ports are open by TCP protocol, version and services running on them.

```
---------------------Starting Nmap Quick Scan---------------------

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-23 20:50 CEST
Nmap scan report for 10.10.10.60
Host is up (0.16s latency).
Not shown: 998 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 12.21 seconds



---------------------Starting Nmap Basic Scan---------------------

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-23 20:51 CEST
Nmap scan report for 10.10.10.60
Host is up (0.16s latency).

PORT    STATE SERVICE    VERSION
80/tcp  open  http       lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Did not follow redirect to https://10.10.10.60/
443/tcp open  ssl/https?
| ssl-cert: Subject: commonName=Common Name (eg, YOUR name)/organizationName=CompanyName/stateOrProvinceName=Somewhere/countryName=US
| Not valid before: 2017-10-14T19:21:35
|_Not valid after:  2023-04-06T19:21:35
|_ssl-date: TLS randomness does not represent time
```

It has an ssl certificate, let's see what's here.

Go to https://sense.htb/

It is a pfSense, a free, open source distribution based on FreeBSD, customized to be a firewall and router.  In addition to being a powerful firewall and router platform, it includes a large list of packages that allow you to easily expand the functionality without compromising the security of the system.
[]FOTO 

My first step when I saw this is to investigate the default credentials, I found user:admin password:pfsense, but they didn't work, so I will opt to use ffuf.

```

```
