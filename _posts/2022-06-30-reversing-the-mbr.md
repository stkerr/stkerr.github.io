---
layout: post
title:  "Reverse Engineering the Master Boot Record"
date:   2022-06-30 9:11:22 -0400
categories: jekyll update
---

_Note: I originally wrote this blog article back in 2010. It was the most popular post on my
blog by an order of magnitude so I wanted to re-post it in case folks still wanted to read it. I have made
some updates to formatting to improve readability but the original content is the same. Enjoy!_

One day, I was curious about how the computer system goes from booting to actually loading up an operating system. Obviously, it must retrieve the operating system from disk at some point, so I decided to investigate this. The first step in this process is reading the MBR, or [Master Boot Record](http://en.wikipedia.org/wiki/Master_boot_record) of the hard drive. The MBR is used to store data about where the OS is stored on the drive.

I figured the MBR would be interesting to learn a little bit more about, so I decided to load it up into [IDA Pro](http://www.hex-rays.com/idapro/), a tool for disassembling programs, and see what I could find out.

![This baby rhino was also curious about MBRs.](/assets/Baby-rhino-6078359-262x300.jpg)
This baby rhino was also curious about MBRs.

I learned a lot and had a lot of fun, so I'm presenting it here to share my results.

For this analysis, I assume that you are familiar with the x86 architecture and assembly. If not, WikiBooks has some great information about it [here](http://en.wikibooks.org/wiki/X86_Assembly). I am also using IDA Pro to do this. I have tried to provide comments and labeling in my IDA work, but I also explain each block of code separately.

The first step in figuring out the MBR was to actually get a copy of it I could work with. To do this, I used [Hex Workshop](http://www.hexworkshop.com), which offers a way to do a binary copy of hard disks. The MBR is always located as the first sector of the disk, so I used Hex Workshop and extracted this file. It is only 1 sector long, so it is a mere 512 bytes.

After looking at [Wikipedia](http://en.wikipedia.org/wiki/Master_boot_record), I figured out the MBR structure was:

    0000h - 01B7h       Code Area (440 bytes)

    01B8h - 01BBh       Disk Signature (4 bytes)
    01BCh - 01BDh       Generally Zeroed out (2 bytes)
    01BEh - 01FDh       List of Partition Records (4 16-byte structures)
    01FEh - 01FFh       MBR Signature (2 bytes - Must be AA55h)

The above structure is what gets loaded into memory and executed. The code area is going to do a few different things, which I look at below. The disk signature can be used to uniquely identify a hard disk. The partition records define different operating systems and partitions on the hard disk. Have you ever noticed how you have to jump through some hoops if you want to have more than 4 operating systems or partitions on your computer? Well, that's because you only have 4 partition records available. The MBR signature helps illustrate that this is in fact an MBR structure.


The partition records are a pretty important part of the MBR, so I also examined their structure. It is:

```
0000h - 0000h    Status byte (80h for bootable, 00h for non-bootable, others are invalid) (1 byte)
0001h - 0003h    CHS address of first absolute sector (3 bytes)
0004h - 0004h    Partition type (1 byte)
0005h - 0007h    CHS address of last absolute sector (3 bytes)
0008h - 000Bh    LBA of first absolute sector (4 bytes)
000Ch - 000Fh    Number of sectors in partition (4 bytes)
```

That is a pretty simple structure; just a start and stop address, length, and a few informational bytes. The CHS format is a little confusing though. CHS stands for Cylinder-Head-Sector and defines an address inside of a physical hard drive. You can read more about CHS here. The LBA address stands for Logical Block Address. LBA is a format to linearly address space on the hard drive, rather than defining 3 separate numbers for Cylinder-Head-Sector format. More information about LBA is here.


After examining the file MBR structure, I loaded the binary file into IDA Pro. Since it is a binary file, IDA doesn't know where the correct segments or entry points are, or even if it is 16 or 32 bit code. Since we don't have an OS yet, we know that this code is 16 bit. Looking at the MBR structure, the code starts at the very first byte of the file. Knowing this, I configured IDA and converted the first few bytes to code. I got the following:


```
s0:0000 ; ---------------------------------------------------------------------------
s0:0000
s0:0000 ; Segment type: Pure code
s0:0000 seg000          segment byte public 'CODE' use16
s0:0000                 assume cs:seg000
s0:0000                 assume es:nothing, ss:nothing, ds:nothing, fs:nothing, gs:nothing
s0:0000                 xor     ax, ax          ; Zero out AX
s0:0002                 mov     ss, ax          ; Set SS to 0
s0:0004                 mov     sp, 7C00h       ; Set SP to 7C00h
s0:0007                 mov     es, ax          ; Set ES to 0
s0:0009                 mov     ds, ax          ; Set DS to 0
s0:000B                 mov     si, 7C00h       ; Source for the copy
s0:000E                 mov     di, 600h        ; This is the destination for the copy
s0:0011                 mov     cx, 200h        ; We want to copy 200h bytes, which is the length
s0:0011                                         ;    of one sector, i.e. the whole MBR.
s0:0014                 cld                     ; Clear Direction Flag
s0:0015                 rep movsb               ; Copies CX bytes from [SI] to [DI]
s0:0015                                         ;    i.e. from [7C00h] to [600h]
s0:0017                 push    ax              ; New value for CS
s0:0018
s0:0018 loc_18:                                 ; New value for IP
s0:0018                 push    61Ch
s0:001B                 retf                    ; Pops the top of the stack into IP then pops CS 
s0:001B\t                                        ;    off next.
s0:001B                                         ;    i.e. we will run from 0000h:61Ch,
s0:001B                                         ;    which is where we just copied ourselves to.
s0:001B                                         ;
s0:001B                                         ; Execution continues at the next instruction.
```

I have tried to add a lot of comments to show what is going on. Essentially though, what this is doing is copying the MBR from 0000h:7C00h to 0000:600h. This is necessary, because it will later load the OS to 0000h:7C00h, so it needs to get itself out of the way. It does this using the `rep movsb` which does a binary copy of 200 bytes from `SI (7C00h)` to `DI (600h)`.

An interesting part about the code above is the way that the `retf` instruction is used. This does what is known as a `far jump`. This means it not only jumps to a different instruction address, but also a different code segment. Both of these values are popped off of the stack, with the offset being on top and the new segment being second. Before the retf instruction, the program pushes 0 and then '61Ch' onto the stack to setup for this far jump. This may seem strange, but since it just copied all the program data to 0000h:0600h, 61Ch is actually the offset to the instruction directly after the retf in the binary.

The next few instructions are:

```
s0:001C                 sti                     ; Enable interrupts
s0:001D                 mov     cx, 4           ; This will be used for the loop.
s0:001D                                         ;    We only want to examine 4 partition records.
s0:0020                 mov     bp, 7BEh        ; This is the offset to the first partition 
s0:0020                                         ;   record.
s0:0020                                         ; In the MBR structure, the first partition 
s0:0020                                         ;    record is at base+1BEh, 
s0:0023                                              so it is 600h + 1BEh = 7BEh
s0:0023
```


First thing this code does is to enable [interrupts](http://en.wikipedia.org/wiki/Interrupt) so that it can be interrupted if necessary. Next, it sets the CX register to 4 and BP to 7BEh. BP is the offset to the partition records (there is a description of these records [here](http://en.wikipedia.org/wiki/Master_boot_record). CX is indicating that we will only examine 4 records (since there are only 4 in the MBR). So this is setting up to iterate over the 4 partition records to find the bootable one that we want.

After this is a loop that tries to find a bootable partition entry. The code is:

```
s0:0023 loc_23:                                 ; CODE XREF: seg000:0030\u0019j
s0:0023                 cmp     byte ptr [bp+0], 0 ; Compares the status byte to 0
s0:0027                 jl      short FoundBootableEntry ; Jumps if the status flag is not 0. 
s0:0027                                         ;    This will happen if the MSB of [bp+0]
s0:0027                                         ;    is 1, essentially saying that if it
s0:0027                                         ;    is 0x80, it will jump.
s0:0027                                         ;
s0:0027                                         ; This jump indicates that we have found the 
s0:0027                                         ;    bootable partition.
s0:0029                 jnz     PrintInvalidPartitionTable ; It's not 0x80 and it's not 0x0, so 
s0:0029                                         ;    it's invalid. Jump to an error state.
s0:002D                 add     bp, 10h         ; Go to the next partition record.
s0:0030                 loop    loc_23          ; Loop while CX != 0
s0:0032                 int     18h             ; TRANSFER TO ROM BASIC
s0:0032                                         ; causes transfer to ROM-based BASIC (IBM-PC)
s0:0032                                         ; often reboots a compatible; often has no effect 
s0:0034                                         ; at all
```

Remember how above we moved the offset of 7BEh into BP? That is so this loop can then examine the partition records. The comparison is checking the status byte of the partition record and comparing it to 0. If it is 0, the first jump will not be taken, nor will the second jump, so 10h is added to BP and the loop is restarted. Advancing the BP register means that we will examine a different partition record. If, after 4 iterations, we have still not found a bootable partition entry, an `int 18h` call will be made. On old IBM PCs, this would run a BASIC interpreter from ROM, but few computers have this. So essentially, an int 18h call will just stop the system. Imagine that, if you have no bootable entries, you're computer won't boot!

If the status byte of the parition record was in fact 80h, the first jump would have been taken. The JL instruction does a jump if the status flag is set to 1. This flag will get set by the previous CMP instruction if the high order bit is set in the status byte, i.e. the status byte is 80h. If the entries status byte is neither 80h or 00h, a jump is made to the PrintInvalidPartitionTable location. I'll talk about that a little bit, but it's pretty boring (it just prints an error message); when a bootable entry is found, things are much more fun.

The next block of code is run when a bootable entry is found. Here it is:

```
s0:0034 FoundBootableEntry:                     ; CODE XREF: seg000:0027\u0018j
s0:0034                                         ; seg000:00AE\u0019j
s0:0034                 mov     [bp+0], dl      ; Save the drive number for later
s0:0034                                         ;    Note that since this will most likely be the
s0:0034                                         ;    first hard drive, DL will probably be 0x80
s0:0037                 push    bp
s0:0038                 mov     byte ptr [bp+11h], 5
s0:003C                 mov     byte ptr [bp+10h], 0 ; This is a sentinel value for later
s0:0040
s0:0040 loc_40:                                 ; DATA XREF: seg000:014F\u0019r
s0:0040                 mov     ah, 41h ; 'A'
s0:0042                 mov     bx, 55AAh
s0:0045                 int     13h             ; DISK - Installation Check
s0:0045                                         ;   CF set on error
s0:0045                                         ;   CF cleared on success
s0:0045                                         ;   BX = AA55 if installed
s0:0045                                         ;   AH = major version of extensions
s0:0045                                         ;   CX = API subset
s0:0045                                         ;   DH = Extension version
s0:0047                 pop     bp
s0:0048                 jb      short AttemptLoadFromDisk ; Jump if Below (CF=1)
s0:004A                 cmp     bx, 0AA55h      ; DATA XREF: seg000:0045\u0018r
s0:004A                                         ; seg000:007E\u0019r ...
s0:004A                                         ; Compare Two Operands
s0:004E                 jnz     short AttemptLoadFromDisk ; Jump if Not Zero (ZF=0)
s0:0050                 test    cx, 1           ; Logical Compare
s0:0054                 jz      short AttemptLoadFromDisk ; Jump if Zero (ZF=1)
s0:0056                 inc     byte ptr [bp+10h] ; This acts like a sentinel value
s0:0056                                         ;    for whether or not the INT 13
s0:0056                                         ;    extended read is installed
s0:0059
```

First part of this block does is moves the DL register into where the entry's status byte used to be. I wasn't really too sure what was going on here for a long time, since if it overwrites the partition record, won't it not boot correctly next time? Well, it turns out that the first hard drive is represented by 80h, so most of the time, things will be fine. I don't have 2 hard drives, so I'm not sure what would happen if you had two hard drives and had your bootable entry on the second hard drive. I suspect that the 2nd hard drive would just have its own MBR and would run that instead. Running code on 1 hard drive and loading data from another hard drive seems a little bit silly anyways, so I'm pretty sure that's whats going on. If you know more, please leave a comment!

Next, the code saves the partition record to the stack and moves the values 5 and 0 into the status byte. The 5 indicates the number of attempts that will be made to read from disk later. Multiple attempts will be made because the disk read might fail while the disk spins up. The 0 value is a sentinel value for whether or not the BIOS supports the extended interrupt 13h feature. This is an advanced, easier way to load lots of data from disk into memory, but not all BIOSs support it. The code above runs several different checks and if they all succeed, it stores a 1 where it had just stored a 0, indicating the extended read feature is supported. If any of those checks fails, it just jumps down a few lines and continues executing and will use the older method.

The next section of code loads the first sector of the OS into memory, using a different method depending on whether or not the extended read is supported. Here it is:

```
s0:0059 AttemptLoadFromDisk:                    ; CODE XREF: seg000:0048\u0018j
s0:0059                                         ; seg000:004E\u0018j ...
s0:0059                 pushad                  ; Save all our registers for a little bit
s0:005B                 cmp     byte ptr [bp+10h], 0 ; Did our sentinel value get changed?
s0:005F                 jz      short InstallationFailed ; DATA XREF: seg000:0032\u0018r
s0:005F                                         ; Jump if Zero (ZF=1)
s0:0061                 push    large 0         ; LBA of 0
s0:0067                 push    large dword ptr [bp+8] ; DATA XREF: seg000:00E5\u0019r
s0:0067                                         ; seg000:0125\u0019r
s0:0067                                         ; Transfer buffer
s0:0067                                         ;    This is also the LBA of first absolute sector
s0:0067                                         ;    in the MBR partition record
s0:006B                 push    0               ; Transfer buffer
s0:006E                 push    7C00h           ; Number of blocks
s0:006E                                         ;    Note that only the first byte is relevant,
s0:006E                                         ;    and the second is ignored, so we are only
s0:006E                                         ;    reading 7Ch
s0:0071                 push    1               ; Reserved
s0:0074                 push    10h             ; Packet is size 10h
s0:0077                 mov     ah, 42h ; 'B'
s0:0079                 mov     dl, [bp+0]      ; Drive number
s0:007C                 mov     si, sp          ; Point to the address packet we just made
s0:007E                 int     13h             ; DISK - Extended Read
s0:007E                                         ;
s0:007E                                         ;    Reads DS:SI into a disk appress packet
s0:007E                                         ;      a disk address packet is:
s0:007E                                         ;      00 BYTE: Size of packet (10h or 18h)
s0:007E                                         ;      01 BYTE: Reserved
s0:007E                                         ;      02 WORD: Number of blocks to transfer
s0:007E                                         ;      04 DWORD: Transfer buffer
s0:007E                                         ;      08 QWORD: Starting absolute block number (LBA)
s0:007E                                         ;      10 QWORD: 64-bit flat address of transfer buffer (optional, used if the DWORD at 04 is FFFFh:FFFFh)
s0:007E                                         ;
s0:007E                                         ;    CF cleared if successful
s0:007E                                         ;    AH = 0 on success
s0:0080                 lahf                    ; Preserve the flags for a second
s0:0081                 add     sp, 10h         ; Pop the address packet we were using off the stack
s0:0084                 sahf                    ; Store AH into Flags Register
s0:0085                 jmp     short PostDiskReadState ; Jump
s0:0087 ; ---------------------------------------------------------------------------
s0:0087
s0:0087 InstallationFailed:                     ; CODE XREF: seg000:005F\u0018j
s0:0087                 mov     ax, 201h        ; The extended read interrupt is not installed,
s0:0087                                         ;    so use the legacy version
s0:0087                                         ; AH = 2 (Disk read sectors into memory)
s0:0087                                         ; AL = 1 (Read 1 sector)
s0:008A                 mov     bx, 7C00h       ; This is the destination buffer
s0:008D                 mov     dl, [bp+0]      ; Drive number
s0:0090                 mov     dh, [bp+1]      ; These 3 bytes are a CHS structure
s0:0093                 mov     cl, [bp+2]
s0:0096                 mov     ch, [bp+3]
s0:0099                 int     13h             ; DISK - READ SECTORS INTO MEMORY
s0:0099                                         ; AL = number of sectors to read, CH = track, CL = sector
s0:0099                                         ; DH = head, DL = drive, ES:BX -> buffer to fill
s0:0099                                         ; Return: CF set on error, AH = status, AL = number of sectors read
```

Right away, a comparison is done against the sentinel value. If it is 0 (indicating no extended read), a jump is taken to the InstallationFailed label. If the extended read is supported, an "address packet" is set up for the interrupt and then the int 13h call is made, performing the read. This was actually a pretty tricky section to figure out, mostly because I found all the documentation about address packets was pretty confusing. After the extended read is completed, the code jumps to the PostDiskReadState location. I expect there are a few errors in my comments about the address packet, which I might try to figure out more about later.

Both the extended read and the non-extended read code do essentially the same thing though. They load the first sector of the bootable partition into memory at 0000h:7C00h. This will most likely be the operating system's loader which will get things started up properly. Before we jump to the OS though, first we have a little bit of maintenance to do, to make sure we are set up and good to go.

After the disk reads are done, we need to make sure that everything succeeded, which is what this block of code does:

```
s0:009B PostDiskReadState:                      ; CODE XREF: seg000:0085\u0018j
s0:009B                 popad                   ; Restore all our registers
s0:009D                 jnb     short DiskReadSuccess ; Jump if CF = 0
s0:009D                                         ;    i.e. The interrupt we just executed (either one)
s0:009D                                         ;    just succeeded.
s0:009F                 dec     byte ptr [bp+11h] ; Remember this was set to 5 before?
s0:009F                                         ;    This is looping and trying the disk several times,
s0:009F                                         ;    (it might have failed while the disk spun up)
s0:00A2                 jnz     short ReattemptDiskRead ; Jump if Not Zero (ZF=0)
s0:00A4                 cmp     byte ptr [bp+0], 80h ; 'Ç' ; Is this drive letter 80h, i.e. the 
s0:00A4                                                    ; first hard drive?
s0:00A8                 jz      PrintErrorLoadingOperatingSystem ; Jump if Zero (ZF=1)
s0:00AC                 mov     dl, 80h ; 'Ç'   ; Re-try on the first hard drive
s0:00AE                 jmp     short FoundBootableEntry ; Jump
s0:00B0 ; ---------------------------------------------------------------------------
s0:00B0
s0:00B0 ReattemptDiskRead:                      ; CODE XREF: seg000:00A2\u0018j
s0:00B0                 push    bp
s0:00B1                 xor     ah, ah          ; Logical Exclusive OR
s0:00B3                 mov     dl, [bp+0]
s0:00B6                 int     13h             ; DISK - RESET DISK SYSTEM
s0:00B6                                         ; DL = drive (if bit 7 is set both hard disks and 
s0:00B6                                         ;   floppy disks reset)
s0:00B6                                         ;
s0:00B6                                         ; This is important so we can try the read again
s0:00B8                 pop     bp
s0:00B9                 jmp     short AttemptLoadFromDisk ; Jump
```

For both style of disk reads, if the operation succeeded, the carry flag will be cleared. As such, there is a JNB instruction that is taken if the load succeeded and jumps to the DiskReadSuccess location. If not, the counter we previously set to 5 is decremented. Remember how I talked about that the disk read might fail sometimes? This code is taking into account the drive being busy, not being spun up, or any other reason by just re-trying a few times. If however, it has failed after the 5 attempts, something is wrong. A comparison is then made to see if we are on the first hard drive by comparing the drive letter we wrote to [BP+0] with 80h. If it is, there is a problem loading the OS, so we print an error message. If not, we change the DL register to 80h, indicating the first hard drive, and try the whole process again.

The ReattemptDiskRead code is pretty straightforward. All it does is resets the disk system and jumps back to the AttemptLoadFromDisk location. Pretty simple, huh?

Hopefully the disk read will succeed though, and the code will get to the DiskReadSuccess location. We are very close to actually jumping to the OS in that case. Here is the code:

```
s0:00BB DiskReadSuccess:                        ; CODE XREF: seg000:009D\u0018j
s0:00BB                 cmp     word ptr ds:7DFEh, 0AA55h ; We just loaded new code to 7C00h. Check 
s0:00BB                                         ;    to see if it has the bootable signature AA55.
s0:00BB                                         ;    This signature indicates a VBR, which indicates
s0:00BB                                         ;    an operating system
s0:00C1                 jnz     short PrintMissingOperatingSystem ; The last two bytes are NOT AA55h
s0:00C1                                                           ; so there is no OS.
s0:00C1                                         ;    Print an error message.
s0:00C3                 push    word ptr [bp+0]
s0:00C6                 call    CheckKeyboardSystemFlag ; Call Procedure
s0:00C9                 jnz     short CheckForTPM ; Jump if Not Zero (ZF=0)
s0:00CB                 cli                     ; Disable interrupts for a while
s0:00CC                 mov     al, 0D1h ; '-'
s0:00CE                 out     64h, al         ; AT Keyboard controller 8042.
s0:00CE                                         ;    Enables writing the output port
s0:00D0                 call    CheckKeyboardSystemFlag ; Call Procedure
s0:00D3                 mov     al, 0DFh ; '¯'
s0:00D5                 out     60h, al         ; AT Keyboard controller 8042.
s0:00D5                                         ;    Enables writing to the status register
s0:00D7                 call    CheckKeyboardSystemFlag ; Call Procedure
s0:00DA                 mov     al, 0FFh        ; Enable A20 memory line
s0:00DC                 out     64h, al         ; AT Keyboard controller 8042.
s0:00DC                                         ; Reset the keyboard and start internal diagnostics
s0:00DE                 call    CheckKeyboardSystemFlag ; Call Procedure
s0:00E1                 sti                     ; Enable interrupts
s0:0156 ; ¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦ S U B R O U T I N E ¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦
s0:0156
s0:0156
s0:0156 CheckKeyboardSystemFlag proc near       ; CODE XREF: seg000:00C6\u0018p
s0:0156                                         ; seg000:00D0\u0018p ...
s0:0156                 sub     cx, cx          ; CX = 0
s0:0158
s0:0158 CheckByte2:                             ; CODE XREF: CheckKeyboardSystemFlag+8\u0019j
s0:0158                 in      al, 64h         ; AT Keyboard controller 8042.
s0:015A                 jmp     short $+2       ; Jump
s0:015C                 and     al, 2           ; Logical AND
s0:015E                 loopne  CheckByte2      ; Loop while rCX != 0 and ZF=0
s0:0160                 and     al, 2           ; Logical AND
s0:0162                 retn                    ; Return Near from Procedure
s0:0162 CheckKeyboardSystemFlag endp
```

This code first checks to see that we did, in fact load an OS and not just some garbage into memory by checking for the AA55h signature. If it is not there, we print an error message. Otherwise, we're going to fiddle with the keyboard controller a bit. This code makes several calls to the CheckKeyboardSystemFlag function, which basically loops until the keyboard controller is ready to talk to to the CPU. I'm a little fuzzy on what the output to the ports is doing, but I'm pretty sure that it is enabling the [A20 address line](http://en.wikipedia.org/wiki/A20_line), which enables larger amounts of memory to be used. It's a pretty common task and there are write-ups all over the Internet, so I won't go into it.

After the MBR is done fiddling with the keyboard controller, it decides to check for a [Trusted Platform Module](http://en.wikipedia.org/wiki/Trusted_Platform_Module). The TPM is used to do several security related things, such as for Windows BitLocker encryption. There is a lot of complex documentation, so after I figured out that this was TPM code, I decided not to investigate it further. It is listed below:

```
s0:00E2 CheckForTPM:                            ; CODE XREF: seg000:00C9\u0018j
s0:00E2                 mov     ax, 0BB00h
s0:00E5                 int     1Ah
s0:00E7                 and     eax, eax        ; Logical AND
s0:00EA                 jnz     short JumpToLoadedMemory ; Jump if Not Zero (ZF=0)
s0:00EC                 cmp     ebx, 41504354h  ; Compare Two Operands
s0:00F3                 jnz     short JumpToLoadedMemory ; Jump if Not Zero (ZF=0)
s0:00F5                 cmp     cx, 102h        ; Compare Two Operands
s0:00F9                 jb      short JumpToLoadedMemory ; Jump if Below (CF=1)
s0:00FB                 push    large 0BB07h
s0:0101                 push    large 200h
s0:0107                 push    large 8
s0:010D                 push    ebx
s0:010F                 push    ebx
s0:0111                 push    ebp
s0:0113                 push    large 0
s0:0119                 push    large 7C00h
s0:011F                 popad                   ; Pop all General Registers (use32)
s0:0121                 push    0
s0:0124                 pop     es
s0:0125                 int     1Ah             ; This makes a call to the TPM
```

The code first checks for the presence of a TPM module. If it is not there, it jumps to the JumpToLoadedMemory location, otherwise it makes a call to the TPM.

Well, ladies and gentlement, thanks for sticking with me. After all that, we are finally ready to jump to the operating system that we loaded into memory. It's very simple, so without further adieu:

```
s0:0127 JumpToLoadedMemory:                     ; CODE XREF: seg000:00EA\u0018j
s0:0127                                         ; seg000:00F3\u0018j ...
s0:0127                 pop     dx
s0:0128                 xor     dh, dh          ; Logical Exclusive OR
s0:012A                 jmp     far ptr 0:7C00h ; Jump to the code we have loaded
```

That's it?! Yup, that's it. Anti-climactic, though I guess Master Boot Records aren't supposed to be entertaining.

There is some more code that I didn't talk about yet, because it has to do with printing the error messages out. I'm not going to explain it here, since I'm already over 3000 words and I'm sure you're sick of reading. Here it is:

```
s0:0131 PrintMissingOperatingSystem:            ; CODE XREF: seg000:00C1\u0018j
s0:0131                 mov     al, ds:7B7h
s0:0134                 jmp     short DisplayErrorMessage ; Jump
s0:0136 ; ---------------------------------------------------------------------------
s0:0136
s0:0136 PrintErrorLoadingOperatingSystem:       ; CODE XREF: seg000:00A8\u0018j
s0:0136                 mov     al, ds:7B6h
s0:0139                 jmp     short DisplayErrorMessage ; Jump
s0:013B ; ---------------------------------------------------------------------------
s0:013B
s0:013B PrintInvalidPartitionTable:             ; CODE XREF: seg000:0029\u0018j
s0:013B                 mov     al, ds:7B5h
s0:013E
s0:013E DisplayErrorMessage:                    ; CODE XREF: seg000:0134\u0018j
s0:013E                                         ; seg000:0139\u0018j
s0:013E                 xor     ah, ah          ; Clear out the high byte of the AX register.
s0:0140                 add     ax, 700h        ; We now point to 700h + whatever offset we were given
s0:0140                                         ;    above.
s0:0143                 mov     si, ax
s0:0145
s0:0145 PrintErrorStringLoop:                   ; CODE XREF: seg000:0151\u0019j
s0:0145                 lodsb                   ; Load byte at DS:SI into AL
s0:0146                 cmp     al, 0           ; Is the next byte 0? We're looking at a 0 terminated
s0:0146                                         ;     string, so this is important.
s0:0148                 jz      short HaltSystem ; Jump if Zero (ZF=1)
s0:014A                 mov     bx, 7
s0:014D                 mov     ah, 0Eh
s0:014F                 int     10h             ; - VIDEO - WRITE CHARACTER AND ADVANCE CURSOR (TTY WRITE)
s0:014F                                         ; AL = character, BH = display page (alpha modes)
s0:014F                                         ; BL = foreground color (graphics modes)
s0:0151                 jmp     short PrintErrorStringLoop ; Jump
s0:0153 ; ---------------------------------------------------------------------------
s0:0153
s0:0153 HaltSystem:                             ; CODE XREF: seg000:0148\u0018j
s0:0153                                         ; seg000:0154\u0019j
s0:0153                 hlt                     ; This stops the computer.
s0:0154                 jmp     short HaltSystem ; Jump
s0:0156
s0:0162 ; ---------------------------------------------------------------------------
s0:0163 aInvalidPartiti db 'Invalid partition table',0
s0:017B aErrorLoadingOp db 'Error loading operating system',0
s0:019A aMissingOperati db 'Missing operating system',0
s0:01B3                 db    0
s0:01B4                 db    0
s0:01B5                 db  63h ; c             ; Redirect to the error message at 63h,
s0:01B5                                         ;    i.e. \"Invalid Partition Table\"
s0:01B6                 db  7Bh ; {             ; Redirect to the error message at 7Bh,
s0:01B6                                         ;    i.e. \"Error loading operating system\"
s0:01B7                 db  9Ah ; Ü             ; Redirect to the error message at 9Ah,
s0:01B7                                         ;    i.e. \"Missing operating system\"
```

I realize that a blog post is a pretty difficult way to explain an RE task like this well. As such, I'm going to make my IDA Pro database available for download [here](/assets/MBR.idb). If you don't have IDA, there is a free version (which I use) available [here](http://www.hex-rays.com/idapro/idadownfreeware.htm). It is missing quite a few features, but the price is right, and for work like this (16-bit MBR code), a lot of the newer features aren't even relevant.

If you're interested, you could do this analysis on your own computer. Depending on your computer's manufacturer, you might have some small differences, but those are what makes it fun, right? To get started, get the [trial](http://www.bpsoft.com/downloads) of Hex Workshop, extract the MBR (it's the first sector on the disk), then use the free version of IDA Pro to examine it. Happy hunting!
