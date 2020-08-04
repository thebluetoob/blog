---
title: Host Enumeration With Nmap
published: true
date: 2019-11-09 12:00
---

# [](#header-1)TL;DR
* Find the IP of the VM with either `netdiscover -r <CIDR>` or `nmap -sn <CIDR>` (ARP vs ICMP respectively)
* Perform a TCP connection scan on all ports with `nmap -sS -p- -T4 -Pn --open <target>`
* Perform an intense Nmap scan on TCP services found listening with `nmap -sS -sV -sC -O -p<ports> -T4 -Pn <target>`
* Repeat for UDP
* Target VM is [Stapler](https://www.vulnhub.com/entry/stapler-1,150/) from VulnHub

# [](#Header-1)Purpose of This Blog Post
The primary audience for this blog post is people who are new to capture the flag (CTF) challenges and are keen to learn but struggle with the question of "where do I get started?".

This post will cover my _personal_ enumeration process that I like to use when first starting a capture the flag (CTF) challenge that involves a deliberately vulnerable virtual machine (VM), such as those available on [VulnHub](https://www.vulnhub.com/) and [HackTheBox](https://www.hackthebox.eu/home). Otherwise known as Boot2Root VMs.

Now I said before that this is my _personal_ enumeration process but that doesn't mean it's all that special. There's a million ways to perform network enumeration on a VM but they'll generally all end up in the same place - a list of listening services as well as some information about them.

If you're new to CTFs and Boot2Root VMs in general I encourage you to check out the [WebPwnized YouTube channel](https://www.youtube.com/watch?v=928Zc0uvOqs) as well as the excellent walkthroughs provided by [Ippsec](https://www.youtube.com/watch?v=oGO9MEIz_tI&list=PLidcsTyj9JXJfpkDrttTdk1MNT6CDwVZF). I would also recommend checking out the different switches available to Nmap and learning what enumeration process best works for you. If nothing else it's a great learning exercise.

# [](#Header-1)Initial Reconnaissance
When you first fire up a Boot2Root VM and connect it to your virtual network (VirtualBox instructions [here](https://www.techrepublic.com/article/how-to-create-multiple-nat-networks-in-virtualbox/)), you won't even know the IP address that was assigned via DHCP. So lets do that first.

# [](#Header-2)ARP Scans with Netdiscover
[Address Resolution Protocol](https://en.wikipedia.org/wiki/Address_Resolution_Protocol) (ARP) is a network protocol used to map the physical (MAC) address of a device to an IP address. Using `netdiscover` we can send ARP _requests_ to every IP address within a given network range (colloquially referred to as a CIDR - Classless inter-domain routing) and log the responses.

`# netdiscover -P -L -i eth1 -r 10.1.1.0/24`
```
_____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 10.1.1.1        00:50:56:c0:00:01      1      60  VMware, Inc.
 10.1.1.129      00:0c:29:9d:60:45      1      60  VMware, Inc.
 10.1.1.254      00:50:56:e2:11:be      1      60  VMware, Inc.

-- Active scan completed, 3 Hosts found. Continuing to listen passively.
```

First we'll break down the command we ran and then the output.

# [](#Header-3)Netdiscover Command

`# netdiscover -P`
>-P: print results in a format suitable for parsing by another program and stop after active scan

Using `-P` allows me to pipe the output of `netdiscover` to a file rather than running it in interactive mode.

`# netdiscover -P -L`
>-L: similar to -P but continue listening after the active scan is completed

Using `-P` means that if I was impatient and didn't wait for the network interface of my target VM to come up then I don't need to run `netdiscover` again as once the VM comes online it will send out ARP requests/responses to other devices on the network in order to discover its neighbours.

`# netdiscover -P -L -i eth1`
>-i: device: your network device

My Kali VM is configured with two network interfaces - a NAT interface that allows my VM to route through my host to the internet; and a Host-Only interface that allows my Kali VM to communicate with the target VM. The target VM does not have internet access.

`# netdiscover -P -L -i eth1 -r 10.1.1.0/24`
>-r: range: scan a given range instead of auto scan. 192.168.6.0/24,/16,/8

The network address I have configured within the VMware Hypervisor settings is `10.1.1.0` with a subnet mask of `255.255.255.0`. Which can be represented as `10.1.1.0/24`

# [](#Header-3)Netdiscover Output

`10.1.1.1        00:50:56:c0:00:01      1      60  VMware, Inc.`

This is the first IP address within my predefined network range and is the default gateway for this network interface.

`10.1.1.129      00:0c:29:9d:60:45      1      60  VMware, Inc.`

This is my target VM. We know this because it's the only other device on my Host-Only network, but we'll confirm it's our target VM later anyway.

`10.1.1.254      00:50:56:e2:11:be      1      60  VMware, Inc.`

This is the VMware DHCP server.

You may be wondering how `netdiscover` knows that these are VMware IP addresses, with the `MAC Vendor` field displaying `VMware, Inc.`.

This is possible due to the fact that the first three bytes of a six byte MAC address are based on the vendor of particular network device. This is called an [organizationally unique identifier (OUI)](https://en.wikipedia.org/wiki/Organizationally_unique_identifier). You can use the [Wireshark OUI Lookup Tool](https://www.wireshark.org/tools/oui-lookup.html) to manually discover the vendor for a given network device.

# [](#Header-2)Ping Sweeps with Nmap
Instead of ARP, it is also possible to use Nmap to send an [Internet Control Message Protocol (ICMP)](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol) (echo request)[https://en.wikipedia.org/wiki/Ping_(networking_utility)] packet (also known as `ping`) to every IP address within a given network range.

`$ nmap -sn -T4 10.1.1.0/24`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2019-11-09 11:44 AEDT
Nmap scan report for 10.1.1.1
Host is up (0.0017s latency).
Nmap scan report for 10.1.1.129
Host is up (0.0011s latency).
Nmap scan report for 10.1.1.255
Host is up (0.00032s latency).
Nmap done: 256 IP addresses (3 hosts up) scanned in 14.64 seconds
```

First we'll break down the command we ran and then the output.

# [](#Header-3)Ping Sweep Command

`$ nmap -sn`
>Ping Scan - disable port scan

>This option tells Nmap not to do a port scan after host discovery, and only print out the available hosts that responded to the scan. This is often known as a "ping scan", but you can also request that traceroute and NSE host scripts be run. This is by default one step more intrusive than the list scan, and can often be used for the same purposes. It allows light reconnaissance of a target network without attracting much attention. Knowing how many hosts are up is more valuable to attackers than the list provided by list scan of every single IP and host name.
>
>Systems administrators often find this option valuable as well. It can easily be used to count available machines on a network or monitor server availability. This is often called a ping sweep, and is more reliable than pinging the broadcast address because many hosts do not reply to broadcast queries.
>
>The default host discovery done with -sn consists of an **ICMP echo request, TCP SYN to port 443, TCP ACK to port 80, and an ICMP timestamp request by default**. When executed by an unprivileged user, only SYN packets are sent (using a connect call) to ports 80 and 443 on the target. When a privileged user tries to scan targets on a local ethernet network, ARP requests are used unless --send-ip was specified. The -sn option can be combined with any of the discovery probe types (the -P* options, excluding -Pn) for greater flexibility. If any of those probe type and port number options are used, the default probes are overridden. When strict firewalls are in place between the source host running Nmap and the target network, using those advanced techniques is recommended. Otherwise hosts could be missed when the firewall drops probes or their responses.
>
>In previous releases of Nmap, -sn was known as -sP.

From the [Nmap man page](https://linux.die.net/man/1/nmap)

So I didn't actually realise that a `-sP`/`-sn` scan sends TCP packets as well as ICMP until I read the above as part of putting this post together. Who knew blogging could be educational!

Anyway the above is a pretty good explanation, Nmap does a `ping` of all of the hosts, and then for the ones that respond to the `ping`, it will perform additional TCP connection attempts to further validate that the host is online.

`$ nmap -sn -T4`
>-T<0-5>: Set timing template (higher is faster)

`-T4` is generally a good balance between reliability and speed when performing enumeration on locally hosted VMs. When scanning VMs hosted in other countries you may need to reduce it to `-T3` due to the wonders of Australian internet.

`$ nmap -sn -T4 10.1.1.0/24`

The network address I have configured within the VMware Hypervisor settings is `10.1.1.0` with a subnet mask of `255.255.255.0`. Which can be represented as `10.1.1.0/24`

# [](#Header-3)Ping Sweep Output
```
Nmap scan report for 10.1.1.129
Host is up (0.0011s latency).
```

The output from Nmap is pretty self explanatory - this snippet is saying that the host with the IP address `10.1.1.129` is online.

# [](#Header-1)TCP Service Discovery With Nmap
Now that we know the IP address of our target VM, we need to figure out which services are running on network interfaces we can access. Services we'd expect to find listening on an external interface include web servers such as Apache and Nginx or SSH servers such as OpenSSH.

`# nmap -sS -p- -T4 -Pn --open 10.1.1.129`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2019-11-09 12:47 AEDT
Nmap scan report for 10.1.1.129
Host is up (0.00025s latency).
Not shown: 65523 filtered ports, 4 closed ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
53/tcp    open  domain
80/tcp    open  http
139/tcp   open  netbios-ssn
666/tcp   open  doom
3306/tcp  open  mysql
12380/tcp open  unknown
MAC Address: 00:0C:29:9D:60:45 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 101.14 seconds
```

As before, we'll first breakdown the command and then the output.

# [](#Header-2)TCP Service Discovery Command

`# nmap -sS`
>-sS/sT/sA/sW/sM: **TCP SYN**/Connect()/ACK/Window/Maimon scans

The `-sS` switch instructs Nmap to perform a TCP SYN scan. Rather than performing the complete TCP three-way handshake (SYN/SYN-ACK/ACK), Nmap will **only** send a TCP SYN request to the port.

`# nmap -sS -p-`
>-p <port ranges>: Only scan specified ports
The next switch, `-p-` instructs Nmap to scan *all* 65,535 possible TCP ports. It is synonymous with `-p1-65535`

`# nmap -sS -p- -T4`
>-T<0-5>: Set timing template (higher is faster)

`-T4` is generally a good balance between reliability and speed when performing enumeration on locally hosted VMs. When scanning VMs hosted in other countries you may need to reduce it to `-T3` due to the wonders of Australian internet.

`# nmap -sS -p- -T4 -Pn`
>Treat all hosts as online -- skip host discovery

As we already established that the host we are scanning is online in the *Initial Reconnaissance* section, we can safely skip host discovery here and save a bit of time.

`# nmap -sS -p- -T4 -Pn --open`
>Only show open (or possibly open) ports

We're only interested in the open ports that Nmap discovers so we can instruct Nmap to exclude closed or filtered ports from the scan output.

`# nmap -sS -p- -T4 -Pn 10.1.1.129`

The final argument passed to Nmap is simply the IP address of our target VM.

# [](#Header-2)TCP Service Discovery Output
```
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
53/tcp    open  domain
80/tcp    open  http
139/tcp   open  netbios-ssn
666/tcp   open  doom
3306/tcp  open  mysql
12380/tcp open  unknown
```
The above output is relatively self explanatory and is simply a list of open ports found listening on the target VM as well as the **default service that uses that port**.

It is important to note however that at this point Nmap has not interrogated the service(s) listening on these ports, and there is no reason why a systems administrator can't configure their SSH server to listen on port 80.

In the next stage we will instruct Nmap to interrogate each of the listening services and provide us with additional information that may be of use.

# [](#Header-1)TCP Service Enumeration with Nmap
Now we have the IP address of our target VM, as well as a list of open TCP ports with *something* listening but no idea what that *something* could be.

This section will focus on performing more in-depth enumeration with Nmap so as to discover more information about these listening services.

`# nmap -sS -sV -sC -O -p21,22,53,80,139,666,3306,12380 -T4 -Pn 10.1.1.129`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2019-11-09 12:55 AEDT
Nmap scan report for 10.1.1.129
Host is up (0.00032s latency).

PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.1.1.128
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open  ssh         OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 81:21:ce:a1:1a:05:b1:69:4f:4d:ed:80:28:e8:99:05 (RSA)
|   256 5b:a5:bb:67:91:1a:51:c2:d3:21:da:c0:ca:f0:db:9e (ECDSA)
|_  256 6d:01:b7:73:ac:b0:93:6f:fa:b9:89:e6:ae:3c:ab:d3 (ED25519)
53/tcp    open  domain      dnsmasq 2.75
| dns-nsid: 
|_  bind.version: dnsmasq-2.75
80/tcp    open  http        PHP cli server 5.5 or later
|_http-title: 404 Not Found
139/tcp   open  netbios-ssn Samba smbd 4.3.9-Ubuntu (workgroup: WORKGROUP)
666/tcp   open  doom?
| fingerprint-strings: 
|   NULL: 
|     message2.jpgUT 
|     QWux
|     "DL[E
|     #;3[
|     \xf6
|     u([r
|     qYQq
|     Y_?n2
|     3&M~{
|     9-a)T
|     L}AJ
|_    .npy.9
3306/tcp  open  mysql       MySQL 5.7.12-0ubuntu1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.12-0ubuntu1
|   Thread ID: 9
|   Capabilities flags: 63487
|   Some Capabilities: IgnoreSigpipes, InteractiveClient, DontAllowDatabaseTableColumn, FoundRows, ODBCClient, SupportsTransactions, LongColumnFlag, Speaks41ProtocolOld, Speaks41ProtocolNew, Support41Auth, ConnectWithDatabase, IgnoreSpaceBeforeParenthesis, LongPassword, SupportsCompression, SupportsLoadDataLocal, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: gJq:\x1F\x1C9et<\x12hId|#k(\x11~
|_  Auth Plugin Name: mysql_native_password
12380/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port666-TCP:[...snip...]
MAC Address: 00:0C:29:9D:60:45 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11, Linux 3.16 - 4.6, Linux 3.2 - 4.9, Linux 4.4
Network Distance: 1 hop
Service Info: Host: RED; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 10h00m00s, deviation: 0s, median: 9h59m59s
|_nbstat: NetBIOS name: RED, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.9-Ubuntu)
|   Computer name: red
|   NetBIOS computer name: RED\x00
|   Domain name: \x00
|   FQDN: red
|_  System time: 2019-11-09T11:55:55+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-11-09T11:56:15
|_  start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 83.94 seconds
```

# [](#Header-2)TCP Service Enumeration Command

As before, first we'll break down the command we executed and then the output.

`# nmap -sS`
>-sS/sT/sA/sW/sM: **TCP SYN**/Connect()/ACK/Window/Maimon scans
The `-sS` switch instructs Nmap to perform a TCP SYN scan. Rather than performing the complete TCP three-way handshake (SYN/SYN-ACK/ACK), Nmap will **only** send a TCP SYN request to the port.

`# nmap -sS -sV`
>-sV: Probe open ports to determine service/version info
Nmap will actually interact with the service discovered and attempt to determine both what service is listening as well as which version.

`# nmap -sS -sV -sC`
>-sC: equivalent to --script=default
>Performs a script scan using the default set of scripts. It is equivalent to --script=default. Some of the scripts in this category are considered intrusive and should not be run against a target network without permission. (From the [Nmap man page](https://linux.die.net/man/1/nmap))

Nmap contains a built in scripting engine (Nmap Scripting Engine or NSE) with hundreds of scripts bundled in the default install that allow for a huge range of information discovery features. Including vulnerability scanning, brute forcing, interaction with services such as FTP to determine if anonymous logins are allowed, and much, **much** more.

The `-sC` switch simply runs the default set of scripts against the services. Detailing the functionality of *all* of the available NSE scripts would take an eternity and is out of scope for this blog post.

`# nmap -sS -sV -sC -O`
>-O: Enable OS detection
The `-O` switch instructs Nmap to attempt to identify which Operating System the target VM is running. For example which version of the Linux Kernel or if it is Windows 7/8/10.

`# nmap -sS -sV -sC -O -p21,22,53,80,139,666,3306,12380`
>-p <port ranges>: Only scan specified ports
The next switch, `-p-` instructs Nmap to scan *just* the ports we found with the first (faster) scan.

`# nmap -sS -sV -sC -O -p21,22,53,80,139,666,3306,12380 -T4`
>-T<0-5>: Set timing template (higher is faster)

`-T4` is generally a good balance between reliability and speed when performing enumeration on locally hosted VMs. When scanning VMs hosted in other countries you may need to reduce it to `-T3` due to the wonders of Australian internet.

`# nmap -sS -sV -sC -O -p21,22,53,80,139,666,3306,12380 -T4 -Pn`
>Treat all hosts as online -- skip host discovery

As we already established that the host we are scanning is online in the *Initial Reconnaissance* section, we can safely skip host discovery here and save a bit of time.

`# nmap -sS -sV -sC -O -p21,22,53,80,139,666,3306,12380 -T4 -Pn 10.1.1.129`

The final argument passed to Nmap is simply the IP address of our target VM.

# [](#Header-2)TCP Service Enumeration Output

We'll break up each section of the output of Nmap in to more manageable chunks and review each of them below.

# [](#Header-3)Port 21/FTP
```
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.1.1.128
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
```

Reviewing the above output we now know the following information:
* Port 21 is running vsFTPd 3.0.3
* vsFTPd is configured to allow anonymous logins

Nmap is able to fingerprint the service as `vsftpd 2.0.8 or later` based on the network traffic, but due to the Nmap scripts that were executed thanks to the `-sC` parameter being passed, we can see from the banner information that it is in fact `vsFTPd 3.0.3`.

# [](#Header-3)Port 22/SSH
```
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 81:21:ce:a1:1a:05:b1:69:4f:4d:ed:80:28:e8:99:05 (RSA)
|   256 5b:a5:bb:67:91:1a:51:c2:d3:21:da:c0:ca:f0:db:9e (ECDSA)
|_  256 6d:01:b7:73:ac:b0:93:6f:fa:b9:89:e6:ae:3c:ab:d3 (ED25519)
```

Based on the above information we now know the following information:
* Port 22 is running OpenSSH 7.2p2 which was [released](https://www.openssh.com/txt/release-7.2) on 2016-02-29.
* The target VM is likely running Ubuntu. Possibly Ubuntu 16.04 based on the aforementioned date.
* The fingerprint(s) of the SSH hostkeys (although it does not apply here, weak SSH key generation is a [known vulnerability](https://github.com/g0tmi1k/debian-ssh))

# [](#Header-3)Port 53/DNS
```
PORT      STATE SERVICE     VERSION
53/tcp    open  domain      dnsmasq 2.75
| dns-nsid: 
|_  bind.version: dnsmasq-2.75
```
Based on the above information we now know the following information:
* Port 53 is running dnsmasq-2.75. [Released](http://www.thekelleys.org.uk/dnsmasq/) on 2015-07-30.
    * dnsmasq-2.76 was released on 2016-05-18, again indicating that the machine may be running Ubuntu 16.04.

# [](#Header-3)Port 80/PHP CLI Server
```
PORT      STATE SERVICE     VERSION
80/tcp    open  http        PHP cli server 5.5 or later
|_http-title: 404 Not Found
```
Based on the above information we now know the following information:
* Port 80 is running PHP cli server 5.5 or later, however there doesn't appear to be a webpage being served in the root directory.
    * Using a tool such as `dirbuster` or `gobuster` to attempt to brute force possible directory names here may be a valid next step.

# [](#Header-3)Port 139/SMBd
```
PORT      STATE SERVICE     VERSION
139/tcp   open  netbios-ssn Samba smbd 4.3.9-Ubuntu (workgroup: WORKGROUP)
```
Based on the above information we now know the following information:
* Port 139 is running Samba smbd 4.3.9-Ubuntu, which was [released](https://code.launchpad.net/~usd-import-team/ubuntu/+source/samba/+git/samba/+ref/ubuntu/wily-security) on 2016-05-25.
* Further SMB enumeration will be covered in the Nmap host script section.

# [](#Header-3)Port 666/Unknown
```
PORT      STATE SERVICE     VERSION
666/tcp   open  doom?
| fingerprint-strings: 
|   NULL: 
|     message2.jpgUT 
|     QWux
|     "DL[E
|     #;3[
|     \xf6
|     u([r
|     qYQq
|     Y_?n2
|     3&M~{
|     9-a)T
|     L}AJ
|_    .npy.9

1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port666-TCP:[...snip...]
```

Based on the above information we now know the following information:
* Nmap was *not* able to successfully fingerprint this TCP service
* The VM appears to be echoing out a JPG file upon connection
    * This service will require manual interaction in order to determine what is going on here.
* Nmap has also printed out a portion of the information to send to the developers to aid in service detection. However we won't be doing this here as we know (spoiler alert) that this is just part of the particular Boot2Root VM that I'm doing this demo on.


# [](#Header-3)Port 3306/MySQL
```
PORT      STATE SERVICE     VERSION
3306/tcp  open  mysql       MySQL 5.7.12-0ubuntu1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.12-0ubuntu1
|   Thread ID: 9
|   Capabilities flags: 63487
|   Some Capabilities: IgnoreSigpipes, InteractiveClient, DontAllowDatabaseTableColumn, FoundRows, ODBCClient, SupportsTransactions, LongColumnFlag, Speaks41ProtocolOld, Speaks41ProtocolNew, Support41Auth, ConnectWithDatabase, IgnoreSpaceBeforeParenthesis, LongPassword, SupportsCompression, SupportsLoadDataLocal, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: gJq:\x1F\x1C9et<\x12hId|#k(\x11~
|_  Auth Plugin Name: mysql_native_password
```
Based on the above information we now know the following information:
* Port 3306 is running MySQL MySQL 5.7.12
* Authentication is required to interact with the service
    * MySQL is typically configured to only listen on `localhost`, however without credentials we can't go much further here.

# [](#Header-3)Port 12380/Apache HTTPd
```
PORT      STATE SERVICE     VERSION
12380/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
```
Based on the above information we now know the following information:
* Port 12380 is running Apache httpd 2.4.18
* Unlike the service listening on port 80, there does appear to be a website here (albeit without a title)

# [](#Header-3)Operating System Detection
```
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11, Linux 3.16 - 4.6, Linux 3.2 - 4.9, Linux 4.4
Network Distance: 1 hop
Service Info: Host: RED; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Based on the above information we now know the following information:
* Further confirmation that the target VM is running Linux
* The hostname of the target VM is likely `RED`

# [](#Header-3)Nmap Host Script Results
```
|_clock-skew: mean: 10h00m00s, deviation: 0s, median: 9h59m59s
|_nbstat: NetBIOS name: RED, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.9-Ubuntu)
|   Computer name: red
|   NetBIOS computer name: RED\x00
|   Domain name: \x00
|   FQDN: red
|_  System time: 2019-11-09T11:55:55+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-11-09T11:56:15
|_  start_date: N/A
```
Based on the above information we now know the following information:
* Further confirmation that the target VM is running Linux
* Further confirmation that the hostname of the target VM is likely `RED`
* Which SMB security controls are enabled on the target VM.

# [](#Header-1)UDP Service Discovery With Nmap

UDP Service discovery with Nmap is almost identical to TCP service discovery, we just use a different switch in Nmap to define a *UDP scan* instead of a *TCP SYN scan* and drop the `-p-` switch as we want the scan to finish sometime this century.

`# nmap -sU -T4 -Pn --open 10.1.1.129`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2019-11-09 15:51 AEDT
Warning: 10.1.1.129 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.1.1.129
Host is up (0.00041s latency).
Not shown: 975 closed ports
PORT      STATE         SERVICE
53/udp    open|filtered domain
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
112/udp   open|filtered mcidas
137/udp   open          netbios-ns
138/udp   open|filtered netbios-dgm
1105/udp  open|filtered ftranhc
1214/udp  open|filtered fasttrack
16700/udp open|filtered unknown
18683/udp open|filtered unknown
18821/udp open|filtered unknown
19605/udp open|filtered unknown
20004/udp open|filtered unknown
21186/udp open|filtered unknown
21207/udp open|filtered unknown
26966/udp open|filtered unknown
30697/udp open|filtered unknown
36384/udp open|filtered unknown
41702/udp open|filtered unknown
43094/udp open|filtered unknown
43824/udp open|filtered unknown
44968/udp open|filtered unknown
46093/udp open|filtered unknown
57813/udp open|filtered unknown
59207/udp open|filtered unknown
MAC Address: 00:0C:29:9D:60:45 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1067.02 seconds

```

As you can see from the above output the only change is `-sU` instead of `-sS`, which if we check the output of `nmap --help` we can see is:

>-sU: UDP Scan

And that's all there is to it!

Now the *output* of Nmap is quite different though. Because UDP is a *stateless* protocol and doesn't have the nice clean TCP SYN/SYN-ACK/ACK on connection establishment and FIN/ACK/FIN/ACK on termination, Nmap isn't able to label ports as open or closed with as much confidence.

You'll also notice that this scan took *a lot* longer to run, 101.14 seconds for the TCP service discovery scan and 1067.02 seconds for the UDP service discovery scan. Ouch.

Much like in the TCP service discovery scan section however, we still want to perform additional enumeration against the possibly open UDP services to see if we can gather any additional information.

# [](#Header-1)UDP Service Enumeration with Nmap

Much like the previous section, in-depth service enumeration against UDP services is very similar to that performed against TCP services. Just replace `-sS` with `-sU` and our list of TCP ports with our list of UDP ports!

`# nmap -sU -sV -sC -O -p53,68,69,112,137,138,1105,1214,16700,18683,18821,19605,20004,21186,21207,26966,30697,36384,41702,43094,43824,44968,46093,57813,59207 -T4 -Pn --open 10.1.1.129`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2019-11-09 17:02 AEDT
Warning: 10.1.1.129 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.1.1.129
Host is up (0.00029s latency).
Not shown: 17 closed ports
PORT      STATE         SERVICE     VERSION
53/udp    open          domain      dnsmasq 2.75
| dns-nsid: 
|_  bind.version: dnsmasq-2.75
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
137/udp   open          netbios-ns  Samba nmbd netbios-ns (workgroup: WORKGROUP)
138/udp   open|filtered netbios-dgm
16700/udp open|filtered unknown
41702/udp open|filtered unknown
43094/udp open|filtered unknown
MAC Address: 00:0C:29:9D:60:45 (VMware)
Too many fingerprints match this host to give specific OS details
Network Distance: 1 hop
Service Info: Host: RED

Host script results:
|_nbstat: NetBIOS name: RED, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 155.51 seconds
```

From the above it looks like the only ports worth investigating more would be 68, 69, 137, and 138. This is because Nmap was able to actually provide some information about the services listening on those ports.

You can also see that Nmap has changed it's mind somewhat about which ports are really *open*. The joys of UDP!

Personally I leave UDP scans to the end of my enumeration process because of the time it takes as well as TCP services being so much more common in Boot2Root CTFs. But then of course that leads to people putting *only* UDP based services on their Boot2Root VMs specifically to trip up people like me.

# [](#Header-1)Where To From Here?
# [](#Header-2)Service Specific Enumeration
In just a few short steps you have gone from knowing that there's a VM *somewhere* on the network to knowing:
* Which operating system the target VM is running
* Which services you can interact with
* The *version* of the services you can interact with

Next steps for this VM in particular may be:
* Anonymous logins were allowed over FTP - see if there is anything stored there!
* There was a website on port 12380 wasn't there? What sort of website? Is it using a content management system such as Wordpress? Go find out!
* You have pretty detailed information about the versions of the software running - are there any known vulnerabilities for that software?

In order to perform the next steps you will most likely require more specific tooling than just Nmap. A fantastic resource for service specific tools is [this](https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/) penetration testing tools cheat sheet.

# [](#Header-2)Automation of Reconnaissance Phase
As you get more comfortable with Nmap, you will likely find an enumeration process that you prefer, and Nmap switches that you find the most useful. You'll also find that you are running the same Nmap commands over and over against different Boot2Root VMs - a fantastic opportunity to automate your enumeration process.

Although I won't share my enumeration script as I really do think it's an invaluable learning exercise to write your own, my network enumeration script performs the following steps:
* Create a simple directory structure
* Perform an initial scan with Nmap, saving the results to a file within the aforementioned directory structure
* Parse out the discovered ports
* Perform an intensive scan with Nmap of *only* the open ports, saving the results to a file within the aforementioned directory structure
* Generate a human readable HTML report for both the initial and intensive scans using `xsltproc` and the bundled Nmap XSL stylesheet

`# ./enumerate-ports.sh 10.1.1.129`
```
performing initial TCP scan. Saving results to 1-initial-reconnaissance/nmap/10.1.1.129_tcp_initial
Initial TCP scan for 10.1.1.129 completed successfully
Generating HTML report for initial TCP scan
performing TCP version scan. Saving results to 1-initial-reconnaissance/nmap/10.1.1.129_tcp_version
TCP version scan for 10.1.1.129 completed successfully
Initial TCP scan report generated
TCP version scan report generated
nmap scans complete for 10.1.1.129
```

`tree -A`
```
.
├── 1-initial-reconnaissance
│   └── nmap
│       ├── 10.1.1.129_tcp_version.nmap
│       ├── 10.1.1.129_tcp_version_report.html
│       └── archive
│           ├── 10.1.1.129_tcp_initial.gnmap
│           ├── 10.1.1.129_tcp_initial.nmap
│           ├── 10.1.1.129_tcp_initial_report.html
│           ├── 10.1.1.129_tcp_initial.xml
│           ├── 10.1.1.129_tcp_version.gnmap
│           └── 10.1.1.129_tcp_version.xml
└── enumerate-ports.sh
```