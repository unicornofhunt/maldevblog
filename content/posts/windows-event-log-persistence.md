+++
title = 'Windows Event Log Persistence'
date = 2026-07-27T09:33:44+02:00
draft = false
+++

## Weird but insane

Going through some different persistence techniques on Windows, I was highly inspired by one that is about storing your payload within the Windows Event Log and then retrieving it when needed. This is suuuuper funny, however, I do believe it would be rather effective.

The idea is simple:
    - Write and Event to `Application` channel with Source that looks "legit enough" and store binary data of shellcode there (gonna do simple MessageBox)
    - Retrieve the binary data and execute it

BONUS: See what's gonna get logged in terms of telemetry if you have `MDE`!!! (WOW, much WOW, MDEEEEEE). HEHE - what's gonna get logged while we are writing the events, this is quite ironic isn't it? ;)

I have also decided to write this one in C, I think the previous post with assembly was cool but it might not resontate with people that well. (Surprise that no ones cares or knows how to write/read assembly lol).

<iframe data-testid="embed-iframe" style="border-radius:12px" src="https://open.spotify.com/embed/track/2umFCVDZCQwadG1UtK0gLh?utm_source=generator&si=aca3a5fcb4604c38" width="100%" height="352" frameBorder="0" allowfullscreen="" allow="autoplay; clipboard-write; encrypted-media; fullscreen; picture-in-picture" loading="lazy"></iframe>

## Win32 APIs to write event

Below are the names of the Win32 APIs that we are going to utilize to write the event:

- `RegisterEventSourceW` (If source cannot be found, it defaults to Application log, perfectly fine for us. Opens handle to EventLog that we need for `ReportEventW` call)
- `ReportEventW` (Actual API that writes the event)
- `DeregisterEventSource` (Closes the EventLog handle - be good boy cleanup)

Cool sample from MS DOCS: [link](https://learn.microsoft.com/en-us/windows/win32/eventlog/reporting-an-event)


