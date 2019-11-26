# MiniDump

alternative to procdump written in `C#` (perfect for execute-assembly) and `C`.

# Usage
```
MiniDumpCs.exe PID
```

```
> MiniDumpCs.exe 620
MiniDumpWriteDump found at 0x000007FEE3891EF0
Trying to dump PID: 620
Process HANDLE 0x0000000000000024
memory.dmp HANDLE 0x0000000000000028
Process Completed (1)(87)
```

# Compiling

For 64 bits systems
```
x86_64-w64-mingw32-gcc.exe dump.c -o dump64.exe
```

For 32 bits systems
```
mingw32-gcc.exe dump.c -o dump.exe
```

# Credit 
Mr.Un1k0d3r RingZer0 Team
