# YAPS
**Y**et **A**nother **P**HP **S**hell

Yeah, I know, I know... But that's it. =)

As the name reveals, this is yet another PHP reverse shell, one more among hundreds available out there. It is a single PHP file containing all its functions and you can control it via a simple netcat listener (`nc -lp 1337`).

In the current version (1.0), its main functions support only linux systems, but i'm planning to make it work with Windows too.

It's currently in its first version and I haven't tested it much yet, and there are still many things I intend to do and improve for the next versions, so please let me know if you've found any bugs. =)

## Features
* Single PHP file (no need to install packages, libs, or download tons of files)
* Works with netcat, ncat, socat, multi/handler, almost any listener
* Customizable password protection
* Can do some enumeration
  * Network info (interfaces, iptables rules, active ports)
  * User info
  * List SUID and GUID files
  *  Search for SSH keys (public and private)
  *  List crontab
  *  List writable PHP files
* Auto download LinPEAS, LinEnum or Linux Exploit Suggester
* Write and run PHP code on remote host
* Stabilize shell

## Cons
* Connection isn't encrypted (nc does not support SSL)
* Not interactive (although you can spawn an interactive shell with `!stabilize`)
  * CTRL+C breaks it; can't use arrows to navigate (unless you use `rlwrap`)

## Working commands
* `!help - Display the help menu`
* `!color - Toggle PS1 color (locally only, no environment variable is changed)`
* `!enum - Download LinPEAS and LinEnum to /tmp and get them ready to use`
* `!info - list informations about the target (the enumeration I mentioned above)`
* `!stabilize - Spawn a interactive reverse shell on another port (works w/ sudo, su, mysql, etc.)`
* `!passwd - Password option (enable, disable, set, modify)`
* `!php - Write and run PHP on the remote host`
* `!suggester - Download Linux Exploit Suggester to /tmp and get it ready to use`

## Screenshots


## Credits  (add links)

#### linpeas

#### linenum

#### suggester

#### pentest monkey
