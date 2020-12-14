---
layout: post
title:  "HackTheBox - OpenKeyS"
date:   2020-12-13 12:00:00 +1100
categories: [CTF, HTB]
tags: [ctf, htb, ssh, openbsd]
---

![Image of info card](/images/htb/openkeys/info-card.png)

# Enumeration
---

## Initial Information

Based on the information provided by HackTheBox, OpenKeys is rated as medium difficulty and is running OpenBSD for it's Operating System.

## Editing hosts
A domain name can be assigned to the ip address localy in the `/etc/hosts` file to assist in refering to the machine.

```
sudo vim /etc/hosts
[ip] openkeys.htb
```

## Nmap Scan

For scanning the system's TCP ports with nmap, an initial port scan is run which only focuses on finding open ports. The open ports detected are then used in a second scan where the -A flag is used to Enable OS detection, version detection, script scanning, and traceroute.

```
sudo nmap -A -T4 -Pn -oN nmap-scan-all -p$(sudo nmap -p- --min-rate=1000 -T4 openkeys.htb | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) openkeys.htb
```

![Image of nmap results](/images/htb/openkeys/nmap.png)

Nmap reveals that port 22 (ssh) and 80 (http) are open. Further agressive OS guesses also confirm that OpenBSD is running on the system as HackTheBox says.


## Gobuster

[Gobuster](https://github.com/OJ/gobuster) can be used for brute forcing files and directories on the website. For the command used bellow the following arguments are used:
- **-u** is the target URL
- **-w** is the path to the wordlist
- **-t** is the number of concurrent threads (default 10)
- **-s** is positive status codes (will be overwritten with status-codes-blacklist if set) (default "200,204,301,302,307,401,403")
- **-o** is the output file to write results to (defaults to stdout)
- **-x** is the file extension(s) to search for
- **-e** is expanded mode, print full URLs

```
sudo gobuster dir -u http://openkeys.htb/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 100 -s '200,204,301,302,307,403,500' -o gobuster.out -x php,txt -e
```

![Image of gobuster scan](/images/htb/openkeys/gobuster.png)

A number of directories are listed that will be explored later on.

## Browsing

Visting `http://openkeys.htb` reveals a login portal. The other notable mention is that the title for the page is `OpenKeyS - Retrieve your OpenSSH keys`.

![Image of website home](/images/htb/openkeys/website-home.png)

It can be infered from the machine name of `OpenKeyS` and the site title that the website most likely stores SSH keys which can be accessed online, which would make a perfect foothold if a users private key can be obtained.

Navigating to the /includes folder found from the gobuster shows a directoy listing revealing an auth.php and auth.php.swp file.

![Image of the includes directory](/images/htb/openkeys/website-includes.png)

The server tries to load the auth.php and reveals no information however the auth.php.swp file displays text, so the file can be downloaded and inspected offline.

# Exploitation
---

## Discovery

While most of the contents of the `auth.php.swp` file arn't human readable, the few words thare can be outputed using the `strings` command.
```
strings auth.php.swp
```

![Image of auth file strings](/images/htb/openkeys/auth.php.swp-strings.png)

Searching online for .swp files leads to <https://fileinfo.com/extension/swp> which mentions that the `.swp` extension is linked to the text editor program `vi` and `vim`.

Knowing that the swap file is related to vim, the man pages can be viewed to find more information.

More information about the swapSearching through the man pages in vim using `man vim | grep swap`

```
# man vim | grep swap
-n          No swap file will be used.  Recovery after a crash will be impossible.  Handy if you want to edit a file on  a  very
-r          List swap files, with information about using them for recovery.
-r {file}   Recovery mode.  The swap file is used to recover a crashed editing session.  The swap file is a file with  the  same
```

According to the man pages, the -r flag can be used to recover the original session.
```
vim -r auth.php.swp
```

The code is successfully recovered. In the recovered code a file path can be found to `../auth_helpers/check_auth`.

Navigating to http://openkeys.htb/auth_helpers/ reveals the check_auth file mentioned which can be downloaded.

Inspecting the file reveals that it's a OpenBSD file:
```
file check_auth 
```

And inspecting the human readable text shows several bits of information.
```
# strings check_auth 
/usr/libexec/ld.so
OpenBSD
libc.so.95.1
_csu_finish
exit
_Jv_RegisterClasses
atexit
auth_userokay
<snip>
```
The text `auth_userokay` looks interesting and searching it online leads to <https://man.openbsd.org/authenticate.3> where it explains:
> These functions provide a simplified interface to the BSD Authentication system.. The auth_userokay() function provides a single function call interface. Provided with a user's name in name, and an optional style, type, and password, the auth_userokay() function returns a simple yes/no response.

Searching for OpenBSD authentication exploits leads to several articles such as <https://thehackernews.com/2019/12/openbsd-authentication-vulnerability.html> which mentions several exploits.

## Exploiting

In the post linked above, several CVE's are listed that are of interest, in particular the OpenBSD Authentication Bypass (CVE-2019-19521). It says:
> Using this flaw, a remote attacker can successfully access vulnerable services with any password just by entering the username as "-schallenge" or "-schallenge: passwd," and it works because a hyphen (-) before username tricks OpenBSD into interpreting the value as a command-line option and not as a username.

Following the exploit instructions, naviagte back to the website homepage at http://openkeys.htb/index.php and enter `-schallenge` for the username and any text for the password, in this case `password123` was used.

![Image of auth bypass step 1](/images/htb/openkeys/website-bypass1.png)

![Image auth bypass step 2](/images/htb/openkeys/website-bypass2.png)

While it succsuflly bypasses the login, an error message displays saysing that OpenSSH key not found for user -schallenge.

![Image of auth bypass step 3](/images/htb/openkeys/website-bypass3.png)

There is the potential for the username of `Jenifer` to exist since that name was obtained from inspecting the `auth.php.swp` file.

To attempt to log in as Jennifer using the autehnticaion bypass exploit earlier, the request can be intercepted with burpsuite, and the username Jennifer can be added to the cookie.

The exploit works and the text for Jennifer's OpenSSH private key is outputed.

![Image of ssh key](/images/htb/openkeys/website-sshkey.png)

The text for the ssh key needs to be copied and saved to a file, which in this case will be called id_rsa.

The permissions of the id_rsa file will also need to be changed to be allowed to be used as a private key for ssh, which can be done using `chmod`.
```
chmod 600 id_rsa
```

With the key configured, connect through ssh.
```
ssh jennifer@openkeys.htb -i id_rsa
```

And we get a shell as jennifer.

![Image of initial shell](/images/htb/openkeys/init-shell.png)

We can then get the user flag from jennifer's home directory.

# Post Enumeration

Enumerating the host information using `uname -a` reveals that the verison of OpenBSD is 6.6
```
openkeys$ uname -a
OpenBSD openkeys.htb 6.6 GENERIC#353 amd64
```

# Privilege Escalation

## Discovery of Vulnerability

The article from earlier <https://thehackernews.com/2019/12/openbsd-authentication-vulnerability.html> mentioned:

> OpenBSD developers released security patches for OpenBSD 6.5 and OpenBSD 6.6

It was discorvered that the system is running OpenBSD 6.6 and since the authentication bypass exploit worked, it's safe to assume the system is vulnerable to the local privilege escalation exploits.

Focusing on `CVE-2019-19520`
> Due to the mishandling of environment-provided paths used in dlopen(), xlock, which comes installed by default on OpenBSD, could allow local attackers to escalate privileges to 'auth' group.

Searching for a proof of concept leads to a github exploit by user bcoles. <https://github.com/bcoles/local-exploits>

## Exploiting

Rather than downloading the exploit to the machine, it the exploit code can be copied to the clipboard and pasted directly in OpenKeyS by using `vim` to create a file and pasting the code inside.

After giving the exploit file execution permissions with `chmod +x openbsd-authroot`, the exploit can be ran gaining accesses to a shell as root.

![Image of root shell](/images/htb/openkeys/root-shell.png)

Lastly the root flag is located in the /root directory.