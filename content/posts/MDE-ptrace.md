+++
title = 'MDE Ptrace'
date = 2026-10-28T10:33:55+01:00
draft = false 
+++

## Make MDE for Linux Great Again - ptrace events

While going through Microsoft documentation web site for MDE for Linux I have noticed something super interesting:

[MDE PTRACE](https://learn.microsoft.com/en-us/defender-endpoint/linux-preferences#configure-monitoring-of-ptrace-events)

There is this configuration you can switch that's disabled by default that will provide you with `ptrace` events.

The example of setting this up can be "derived" from full configuration profile example: [full conf example](https://learn.microsoft.com/en-us/defender-endpoint/linux-preferences#full-configuration-profile-example)

```
   "features":{
      "supplementarySensorConfigurations":{
        <SNIP>
        "enableProcessCalls":"enabled",
        <SNIP>
      },
```
Mainly we are interested in the above configuration that you would put in `/etc/opt/microsoft/mdatp/managed/mdatp_managed.json`


## Why should you care?

Excellent question! And the answer is quite easy; this is the process injection technique that adversaries use in Linux environments.

[MITRE GOODNES](https://attack.mitre.org/techniques/T1055/008/)

As per MITRE description:

"Ptrace system call injection is a method of executing arbitrary code in the address space of a separate live process."

NOTE: I do not have custom configuration file on my system, however, I do have these events. My MDE build is this slow-insider preview enabled (crazy whatever master blaster lol) build.

That means these are awesome events for detecting Ptrace injection. That's huge for MDE, because the telemetry is very limited.

Exploring how the Ptrace Injection would deserve a separate post, however the rough idea (high level):

```
// Attach to the process
ptrace(PTRACE_ATTACH, pid, NULL, NULL) 

// Write shellcode using memwrite via different means, good example would be via: https://offlinemark.com/an-obscure-quirk-of-proc/

ptrace(PTRACE_GETREGS, pid, NULL, &regs) 

//Point rip to addr with shellcode
regs.rip = addr;

// Set registers back
ptrace(PTRACE_SETREGS, pid, NULL, &regs)

// Detach and resume
ptrace(PTRACE_DETACH, pid, NULL, NULL) 
```

## TELEMETRY

The below KQL query would find our execution:

```
    DeviceEvents
    | where TimeGenerated > ago(1h)
    | where ActionType =~ "PTraceDetected"
    | project TimeGenerated, ActionType, FolderPath, FileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, AdditionalFields
    | sort by TimeGenerated desc
```

![MDE Events](/images/ptrace_mde_events.png)

*Checkout how we had 4 different ptrace syscalls and you are presented with 4 PTraceDetected events with corresponding Request Types.*


If you want to do some exploration on how the things are in your environment:

```
    DeviceEvents
    | where TimeGenerated > ago(30d)
    | where ActionType =~ "PTraceDetected"
    | summarize count() by InitiatingProcessFileName, FileName

```


