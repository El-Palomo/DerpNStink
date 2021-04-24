# DerpNStink
Desarrollo del CTF DerpNStink

## 1. Configuración de la VM

- Download la VM: https://www.vulnhub.com/entry/derpnstink-1,221/

## 2. Escaneo de Puertos

```
# Nmap 7.91 scan initiated Wed Apr 21 17:14:59 2021 as: nmap -n -P0 -p- -sC -sV -O -T5 -oA full 192.168.56.105
Nmap scan report for 192.168.56.105
Host is up (0.00072s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 12:4e:f8:6e:7b:6c:c6:d8:7c:d8:29:77:d1:0b:eb:72 (DSA)
|   2048 72:c5:1c:5f:81:7b:dd:1a:fb:2e:59:67:fe:a6:91:2f (RSA)
|   256 06:77:0f:4b:96:0a:3a:2c:3b:f0:8c:2b:57:b5:97:bc (ECDSA)
|_  256 28:e8:ed:7c:60:7f:19:6c:e3:24:79:31:ca:ab:5d:2d (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-robots.txt: 2 disallowed entries 
|_/php/ /temporary/
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: DeRPnStiNK
MAC Address: 08:00:27:93:7E:9A (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

<img src="https://github.com/El-Palomo/DerpNStink/blob/main/derp1.jpg" width=80% />






















