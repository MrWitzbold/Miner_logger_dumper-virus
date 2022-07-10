# Miner_logger_dumper-virus

When trying to get a GUI for a game I don't even play so I could crack it, someone sent me a virus to mess with me, so I was curious to know what it was.
First off, I knew one of its functions was logging discord tokens because my friend opened before we realized what it was, and whoever sent the virus started sending me messages through his account encouraging me to open it. I didn't, and a few minutes later my friend told me what had happened.

![alt text]([https://i.imgur.com/bW2ceaW.png))

The virus uses a few utilities to steal tokens and several other malicious activites, here's a list:

Process hacker (prob to kill antiviruses),
TeamViewer GmbH,
Blackbone Injector (a memory hacking tool for windows),
LSASS Dumper (dumps information about the machine's security policy),
RDP brute-force tool (bruteforces the microsoft remote desktop protocol),
PuTTY (a backdoored version of putty),
Bitcoin miner,

In the important functions I decompiled the functions some of these utilities use, but it wasn't possible to get them all since even after deobfuscated, the generated code had missing functions and some bad code.
