+++
title = 'Overcomplicated Linux Process Enumeration'
date = 2026-07-16T20:18:54+02:00
draft = false 
+++

The guide on how to overthink process enumeration in Linux.

I am coming from the Windows heavy internals background, however, Linux has been always super interesting to me. This is where I started, back in the day doing some heavy auditd stuff here and there. It is time that I have decided to get back to Linux and share something that might help or inspire others.

Why the f.. would you want to enumerate processes? Well, this would be the case of your typical recon phase once you got into the host. You can find some interesting stuff... From the maldev point of view, you usually want to enumerate processes to find some juicy targets for potential process injection (that's what you do in Windows world, so I assume that would be also valid in Linux land, lol, idk).

In Linux you can just simply utilize tools like `ps` or `pstree` in order to enumerate the process. That's soooo boring, this is freaking maldev isn't it? You build this sh\*t from ground up...

Better... Do it in assembly... ;) because why not? I like pain too.

```
Code blocks
```
