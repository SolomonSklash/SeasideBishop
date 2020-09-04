# SeasideBishop
A C port of b33f's UrbanBishop

## Background

This repo is a port of [b33f's](https://github.com/FuzzySecurity) very neat C# shellcode loader [UrbanBishop](https://github.com/FuzzySecurity/Sharp-Suite/tree/master/UrbanBishop). [Rastamouse](https://github.com/rasta-mouse) also has a [port](https://github.com/rasta-mouse/RuralBishop) that makes use of D/Invoke. They did the heavy lifting on this, I simply rewrote it in C and made a few tweaks.

My post about this project is [here](https://www.solomonsklash.io/seaside-bishop.html).

## Injection Overview

SeasideBishop is a remote process shellcode injector. It uses only native Windows APIs, and only supports x64.

First, a handle to the remote target process is opened with `NtOpenProcess`. A section view is created and mapped
in the local process with `NtCreateSection` and `NtMapViewOfSection`, then the shellcode payload is `memcopy`'d
into it. This section is subsequently mapped in the target process, thereby allocating the shellcode without using
a more suspicious API like `WriteProcessMemory`. Next a new suspended thread is created, pointing to the
address of `RtlExitUserThread`. A user APC is queued onto the new thread with `NtQueueApcThread`, pointing
to the executable shellcode within the remote mapped section. Finally the thread is executed by calling
`NtAlertResumeThread`.

## Running The Code

Open the solution file in Visual Studio (I used 2019 Community) and compile using x64 Release mode. You may need to
change the Compile As setting to C.

## Thanks

Many thanks to [Adamant](https://krabsonsecurity.com/) and AsaurusRex for their help on this.
