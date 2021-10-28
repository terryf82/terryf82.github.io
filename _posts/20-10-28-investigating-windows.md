---
layout: post
title:  "TryHackMe: Investigating Windows"
date:   2021-10-28 09:24:00 +1000
categories: blue-team
tags: windows powershell event-viewer task-scheduler mimikatz c2
excerpt_separator: <!--more-->
---

**Investigating Windows** is a forensics room that involves determining the extent of compromise of a Windows host.

<!--more-->

<p align="center"><img src="/assets/images/investigating-windows/main.png" /></p>

Access to the machine is provided by RDP, which TryHackMe also supports through the browser. The compromised host has very little in the way of security software installed, so the bulk of the investigation needs to be carried out using default system software (command prompt, PowerShell, Task Manager, Event Viewer etc.)

> Q. Whats the version and year of the windows machine?

Simply navigate to `Start > Control Panel > System and Security > System`, to reveal the host is running _Windows Server 2016_.

> Q. Which user logged in last?

Open `Event Viewer`, browse to `Windows Logs > Security` and filter the entries by `EventID 4624`, which represent successful logins. Sort the events in chronological order and scroll down to the most recent entry, before the current date (these are entries from you logging onto the machine). The last user to log onto the system was _Administrator_ at _1/29/2021 6:29:01 PM_, seen in the screenshot below (note - there is a more recent entry at _6:29:05 PM_, but the details for this entry indicate it was of `Logon Type 5`, which means it was a service logon started by the Service Control Manager, and not a human user).

<p align="center"><img src="/assets/images/investigating-windows/1.png" /></p>

> Q. When did John log onto the system last?

There are several ways to determine this, the simplest is to run the command `net user John` in a command prompt, to reveal that he last logged in at _03/02/2019 5:48:32 PM_.

<p align="center"><img src="/assets/images/investigating-windows/2.png" /></p>

> Q. What IP does the system connect to when it first starts?

There are several ways compromised Windows hosts can be configured to run code at startup, one of the most common being through `Windows Registry Startup Items`. In a command prompt, type `regedit` and then navigate to `HKEY_LOCAL_MACHINE > SOFTWARE > Microsoft > Windows > CurrentVersion > Run`, where we can see an entry has been added to connect to _10.34.2.3_ on startup:

<p align="center"><img src="/assets/images/investigating-windows/3.png" /></p>

> Q. What two accounts had administrative privileges (other than the Administrator user)?

In a command prompt run `net localgroup administrators` to list the users that have been added to the `administrators` group, which are _Jenny and Guest_.

<p align="center"><img src="/assets/images/investigating-windows/4.png" /></p>

> Q. Whats the name of the scheduled task that is malicous?

In a command prompt run `taskschd` to start the `Task Scheduler`, and then click on `Task Scheduler Library` on the left to list scheduled tasks. Clicking on any task and then `Actions` will give you an idea of what the task is actually doing, whatever its name may indicate.

Honestly there are a number of tasks here that are highly suspicous:

- _Clean file system_ appears to start a netcat listener
- _falshupdate22_ runs a hidden PowerShell
- _GameOver_ appears to be using `Mimikatz` to dump credentials

but for the purposes of this room, _Clean file system_ is the accepted answer (the following question about timing indidicates this, since this is the only scheduled task that is running daily).

<p align="center"><img src="/assets/images/investigating-windows/5.png" /></p>

> Q. What file was the task trying to run daily?

As seen in the previous screenshot, the file run daily is _nc.ps1_

> Q. What port did this file listen locally for?

Refer to previous screenshot, the port listened on is _1348_ (indicated by `-l 1348`)

> Q. When did Jenny last logon?

As mentioned earlier, the easiest way to determine this is to run the command `net user Jenny` in a command prompt, which indicates Jenny has `Never` logged on:

<p align="center"><img src="/assets/images/investigating-windows/6.png" /></p>

> Q. At what date did the compromise take place?

Looking again at the suspicious scheduled tasks, both _GameOver_ and _falshupdate_ both ran first on _03/02/2009_, indicating this as the day of compromise:

<p align="center"><img src="/assets/images/investigating-windows/7.png" /></p>

> Q. At what time did Windows first assign special privileges to a new logon?

Returning to Event Viewer, this time we can filter by `EventID 4672` - Special privileges assigned to a new logon. Looking at the matching events that occurred on the day of compromise, we can see the assignment happened at _03/02/2019 4:04:49 PM_:

<p align="center"><img src="/assets/images/investigating-windows/8.png" /></p>

> Q. What tool was used to get Windows passwords?

Referring back to the scheduled tasks screenshot from before, we've already identified that _Mimikatz_ is being used to dump credentials from the system.

> Q. What was the attackers external control and command servers IP?

Command and Control, or _C2_ servers, provide a means for an attacker to issue commands to a compromised host. The usual method of issuing these commands is to have the host 'check in' with the C2 periodically, and respond to any new commands given. By design this allows the attacker to hide the connections amongst the host's outgoing requests, which are less likely to be flagged as suspicious by intrusion software than incoming requests.

Further, attackers will usually try to obfuscate the C2 address behind a legitimate looking hostname. One way of doing this is to override, or 'poison', the host's DNS data, so that a non-suspicious domain can be used to route C2 traffic. We can check for indicators of this by looking in the host's DNS configuration, which is kept in a plain text file at `C:\Windows\System32\Drivers\etc\hosts`:

<p align="center"><img src="/assets/images/investigating-windows/9.png" /></p>

This file shows clear signs of compromise:

- several anti-virus / anti-malware domains have been remapped to `127.0.0.1` (localhost), which means they can never be reached by any user or software on the system, e.g an anti-virus updater
- both `google.com` and `www.google.com` have been mapped to an external IP, _76.32.97.132_, which is highly unusual and in this case the C2 server

_Note - there are also entries mapping `update.microsoft.com` to an IP, but since the mapped IP `10.2.2.2` is an internal, non-routable address, this is more likely to be a locally managed update server and not malicious_

> Q. What was the extension name of the shell uploaded via the servers website?

Given this is a Windows host, if it is running a webserver the likely software is `IIS`. We can navigate to `C:\Inetpub\wwwroot`, the default location for ISS to confirm, where we discover 3 files:

<p align="center"><img src="/assets/images/investigating-windows/10.png" /></p>

Opening each file in notepad reveals the third file, _tests.jsp_, is a web-shell (the _shell.gif_ file is, surprisingly, actually a gif of a shell =P)

> Q. What was the last port the attacker opened?

An attacker would need to modify the host's firewall to open a port, so that's where we should search. Open `Windows Firewall` from the Start menu, and click on `Inbound Rules`:

<p align="center"><img src="/assets/images/investigating-windows/11.png" /></p>

We can see the most recent inbound rule added was to allow traffic in on port _1337_

> Q. Check for DNS poisoning, what site was targeted?

The answer to this question was already found when we were looking for the C2 server address - the site targeted was _google.com_
