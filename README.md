# K2

![DBGXSHELL](./Media/DbgX.Shell.png)

`K2` is a deliberately small kernel PoC for detecting direct-syscalls executed by frameworks such as SysWhispers (and children), HellsGate and frameworks using similar techniques.

## SUMMARY

The driver registers a few high-signal callbacks:

- process creation
- thread creation
- process handle opens / duplicates
- thread handle opens / duplicates

When one of those events fires, `K2` walks the current user stack and checks:

- whether the top user frame resolves into the real mapped `ntdll.dll`
- whether the frame is inside the expected `Nt*` export set for that callback
- whether the frame lands in a different `Nt*` export, which is a useful indirect-syscall signal
- whether the caller frame comes from executable private memory, writable+executable memory, or other non-image executable regions

For object-handle callbacks that means allowing the legitimate creator syscalls as well. For example, a thread handle create can naturally arrive from `NtOpenThread`, `NtCreateThreadEx`, `NtCreateUserProcess`, or `ZwAlpcOpenSenderThread`, and a process handle create can legitimately come from `NtOpenProcess`, `NtCreateUserProcess`, or `ZwAlpcOpenSenderProcess`. Treating every non-`NtOpen*` path as malicious creates noise from normal WMI, CLR, CSRSS, CTF, and other Win32 activity.

The detections are logged to the kernel debugger with detailed reason strings and a short stack dump so they are easy to inspect in WinDbg.

The driver also does a few practical hardening steps so the callbacks stay usable under load:

- duplicate detections are rate-limited for a short window instead of being spammed continuously
- `ntdll` / `win32u` module base lookups are cached per process to avoid repeated loader walks on hot paths
- PE export parsing validates image RVAs before probing user memory

## WHY?

A lot of offensive syscall tooling leans on the same tired assumption:

- "If I avoid the import table, I disappear."

That assumption does not survive basic stack inspection.

`SysWhispers`, `Hell's Gate`, and their endless descendants are useful examples of how operators try to bypass user-mode hooks, but they also produce recognizable execution patterns:

- the syscall path does not begin in the expected `ntdll` stub
- the stack points at a different `Nt*` export than the one being exercised
- the call origin lives in private or suspicious executable memory rather than the real image-backed `ntdll`

This PoC focuses on that gap. It is not trying to be a product, and it is not trying to "stop all syscall evasion." It is just a compact way to prove that these techniques are still observable when you look at the right things.

## BUILD

From this directory:

```bat
msbuild K2.vcxproj /t:Build /p:Configuration=Debug /p:Platform=x64 /p:SignMode=Off
```

The project-side WDK signing path is not reliable on this box, so the practical path is:

```bat
set K2_PFX_PASSWORD=your-pfx-password
installer.bat
```

or:

```bat
installer.bat your-pfx-password
```

The installer will sign `K2.sys` with the local `.pfx` before staging it into `System32\drivers`.

## INSTALL & REMOVE

Put `K2.sys` in this same directory as the scripts, then run as admin:

```bat
installer.bat
```

To remove it:

```bat
remover.bat
```

The installer copies `K2.sys` into `C:\Windows\System32\drivers\K2.sys`, creates or updates the `K2` kernel service to point there, and starts it. The remover stops and deletes the service, then removes the staged driver file.

## WINDBG

Filter on the `K2` prefix:

```text
[K2] ============================================================
[K2] id=... event=... process=...
[K2]   pid=... tid=... frameCount=...
[K2]   reasons=...
[K2]   ntdll=... frame0=...
[K2]   resolved=... base=... span=...
[K2]   expected=... base=... span=...
[K2]   alt=... base=... span=...
[K2]   alt2=... base=... span=...
[K2]   alt3=... base=... span=...
[K2]   caller=... type=...
[K2]   callerProtect=... exec=... private=... writable=... image=...
[K2]   STACK[0] frame=...
[K2]     module=... or module=unmapped-or-non-image
[K2]     regionBase=... type=... protect=...
[K2]     classification=exec:... private:... writable:... image:...
[K2]     export=...
[K2] ============================================================
```
