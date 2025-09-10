# WinAPIWrapper

A small C++ utility that provides a **wrapper around Windows API functions**.  
Instead of linking directly against `kernel32.lib`, `user32.lib`, `advapi32.lib`, etc.,  
this project loads DLLs dynamically at runtime and resolves function pointers via  
`LoadLibraryW` and `GetProcAddress`.

The result is a **strongly-typed, RAII-based wrapper** that:

- Dynamically loads core Windows libraries (`kernel32.dll`, `user32.dll`, `advapi32.dll`, `ntdll.dll`).
- Provides typed function pointers for common APIs (file I/O, registry, crypto, memory, system info, etc.).
- Caches resolved functions for efficiency.
- Throws exceptions with human-readable Win32 error messages.

---

## Import Address Table (IAT) Evasion

One key effect of using this wrapper is that **API functions do not appear in the Import Address Table (IAT)**.  
Only a few essentials like `LoadLibraryW` and `GetProcAddress` remain visible.  

- In **malware development**, this same technique is often leveraged for:
  - **IAT evasion**: hiding sensitive API calls (e.g. `WriteProcessMemory`, `CreateRemoteThread`) from static analysis.
  - Making detection harder for security tools that scan import tables.
  - Dynamically resolving only what is needed, when it is needed.

This project demonstrates the mechanism in a transparent way:  
function names are still stored as plain strings (no hashing, no obfuscation).  
In real-world malware, obfuscation layers are often added to further conceal API usage.

---

## Disclaimer

This repository is for **educational and research purposes only**.  
The techniques shown here (dynamic API resolution, IAT evasion) are dual-use:  
they can be applied in **legitimate software engineering** and are also  
commonly abused in **malware**.  

⚠️ Do not use this code for malicious purposes. The intent is to study, learn,  
and understand how these techniques work in practice.
