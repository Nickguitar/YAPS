# YAPS
**Y**et **A**nother **P**HP **S**hell

Yeah, I know, I know... But that's it. =)

As the name reveals, this is yet another PHP reverse shell, one more among hundreds available out there. It is a single PHP file containing all its functions and you can control it via a simple netcat listener (`nc -lp 1337`).

In the current version (1.0), its main functions support only linux systems, but i'm planning to make it work with Windows too.

It's currently in its first version and I haven't tested it much yet, and there are still many things I intend to do and improve for the next versions, so please let me know if you've found any bugs. =)

## Features
* Single PHP file (no need to install packages, libs, etc.)
* Works with netcat, ncat, socat, multi/handler, ...
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

## Commands
asdasd
asdasd
asdasd

## Screenshots


## Credits  (add links)

#### linpeas

#### linenum

#### suggester

#### pentest monkey
