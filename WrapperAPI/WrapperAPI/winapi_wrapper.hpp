#pragma once

// Transparent WinAPI wrapper using dynamic loading (no hashing / no obfuscation).
// Expanded modules: kernel32, user32, advapi32, ntdll.
// - Strongly-typed function pointers
// - RAII module loader
// - Cached GetProcAddress lookups
// - Optional try_get() for version-dependent APIs

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <winternl.h>  // For NT types like NTSTATUS, RTL_OSVERSIONINFOW
#include <winsvc.h>    // Service Control Manager types (SC_HANDLE, etc.)
#include <wincrypt.h>  // CryptoAPI (CryptAcquireContextW, CryptGenRandom, ...)

#include <string>
#include <string_view>
#include <unordered_map>
#include <stdexcept>
#include <mutex>
#include <array>
#include <cstdint>

// =======================
// XOR helper (ANSI)
// =======================
template<std::size_t N, uint8_t Key>
struct XorA {
    std::array<uint8_t, N> enc{};

    // (A) constructor from literal (kept for compatibility; avoid using if you want no literal)
    constexpr XorA(const char(&s)[N]) {
        for (std::size_t i = 0; i < N; ++i) enc[i] = static_cast<uint8_t>(s[i]) ^ Key;
    }
    // (B) constructor from pre-xored array (preferred)
    constexpr XorA(const unsigned char(&pre_xored)[N]) {
        for (std::size_t i = 0; i < N; ++i) enc[i] = static_cast<uint8_t>(pre_xored[i]);
    }

    /*void decrypt(char(&out)[N]) const {
        for (std::size_t i = 0; i < N; ++i) out[i] = static_cast<char>(enc[i] ^ Key);
    }*/
    
    void decrypt(char(&out)[N]) const {
        for (std::size_t i = 0; i + 1 < N; ++i)
            out[i] = static_cast<char>(enc[i] ^ Key);
        out[N - 1] = '\0'; // force terminator
    }


    static void secure_erase(volatile char(&buf)[N]) {
        for (std::size_t i = 0; i < N; ++i) buf[i] = 0;
    }
};

// kept for compatibility; not used when using pre-xored arrays
template<std::size_t N>
constexpr auto xor_a(const char(&s)[N]) {
    return XorA<N, 0x5Au>(s);
}

// =======================
// Error helpers
// =======================
inline std::string Win32ErrorMessage(DWORD code) {
    LPSTR buf = nullptr;
    DWORD len = ::FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&buf), 0, nullptr);

    std::string msg = (len && buf) ? std::string(buf, len) : std::string("Unknown error");
    if (buf) ::LocalFree(buf);
    return msg;
}

inline std::string Narrow(const std::wstring& ws) {
    if (ws.empty()) return {};
    const int size = ::WideCharToMultiByte(
        CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()),
        nullptr, 0, nullptr, nullptr
    );
    std::string out(size, '\0');
    if (size > 0) {
        ::WideCharToMultiByte(
            CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()),
            &out[0], size, nullptr, nullptr
        );
    }
    return out;
}


struct Win32Exception : std::runtime_error {
    DWORD error_code;
    explicit Win32Exception(const std::string& where, DWORD ec)
        : std::runtime_error(where + " failed with " + std::to_string(ec) + " (" + Win32ErrorMessage(ec) + ")"),
        error_code(ec) {
    }
};

// =======================
// RAII module loader
// =======================
class DynModule {
public:
    explicit DynModule(const wchar_t* module_name)
        : name_(module_name), handle_(::LoadLibraryW(module_name)) {
        if (!handle_) {
            throw Win32Exception("LoadLibraryW(" + Narrow(name_) + ")", ::GetLastError());
        }
    }

    DynModule(const DynModule&) = delete;
    DynModule& operator=(const DynModule&) = delete;

    DynModule(DynModule&& other) noexcept
        : name_(std::move(other.name_)), handle_(other.handle_) {
        other.handle_ = nullptr;
    }

    DynModule& operator=(DynModule&& other) noexcept {
        if (this != &other) {
            close();
            name_ = std::move(other.name_);
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    ~DynModule() { close(); }

    template<typename Fn>
    Fn get(const char* proc_name) const {
        FARPROC p = find(proc_name);
        return reinterpret_cast<Fn>(p);
    }

    // Accept XorA<N,Key> (literal or pre-xored array)
    template<typename Fn, std::size_t N, uint8_t Key>
    Fn get_xor(const XorA<N, Key>& name) const {
        char buf[N];
        name.decrypt(buf);
        FARPROC p = find(buf);
        XorA<N, Key>::secure_erase(reinterpret_cast<volatile char(&)[N]>(buf));
        return reinterpret_cast<Fn>(p);
    }

    template<typename Fn, std::size_t N, uint8_t Key>
    Fn try_get_xor(const XorA<N, Key>& name) const noexcept {
        char buf[N];
        name.decrypt(buf);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = cache_.find(buf);
            if (it != cache_.end()) {
                XorA<N, Key>::secure_erase(reinterpret_cast<volatile char(&)[N]>(buf));
                return reinterpret_cast<Fn>(it->second);
            }
        }
        FARPROC p = ::GetProcAddress(handle_, buf);
        std::string key(buf);
        XorA<N, Key>::secure_erase(reinterpret_cast<volatile char(&)[N]>(buf));
        if (p) {
            std::lock_guard<std::mutex> lock(mutex_);
            cache_.emplace(std::move(key), p);
        }
        return reinterpret_cast<Fn>(p);
    }

    template<typename Fn>
    Fn try_get(const char* proc_name) const noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = cache_.find(proc_name);
            if (it != cache_.end()) return reinterpret_cast<Fn>(it->second);
        }
        FARPROC p = ::GetProcAddress(handle_, proc_name);
        if (p) {
            std::lock_guard<std::mutex> lock(mutex_);
            cache_.emplace(proc_name, p);
        }
        return reinterpret_cast<Fn>(p);
    }

    HMODULE handle() const noexcept { return handle_; }
    const std::wstring& name() const noexcept { return name_; }

private:
    FARPROC find(const char* proc_name) const {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = cache_.find(proc_name);
            if (it != cache_.end()) return it->second;
        }

        FARPROC p = ::GetProcAddress(handle_, proc_name);
        if (!p) {
            throw Win32Exception("GetProcAddress(" + Narrow(name_) + "::" + proc_name + ")", ::GetLastError());
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            cache_.emplace(proc_name, p);
        }
        return p;
    }

    void close() noexcept {
        if (handle_) {
            ::FreeLibrary(handle_);
            handle_ = nullptr;
        }
    }

    std::wstring name_;
    HMODULE handle_{ nullptr };
    mutable std::unordered_map<std::string, FARPROC> cache_;
    mutable std::mutex mutex_;
};

// =======================
// FP typedefs
// =======================
// (same as before)...

// KERNEL32
using CreateFileW_t = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using CloseHandle_t = BOOL(WINAPI*)(HANDLE);
using ReadFile_t = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
using WriteFile_t = BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
using GetLastError_t = DWORD(WINAPI*)(void);

using CreateDirectoryW_t = BOOL(WINAPI*)(LPCWSTR, LPSECURITY_ATTRIBUTES);
using RemoveDirectoryW_t = BOOL(WINAPI*)(LPCWSTR);
using DeleteFileW_t = BOOL(WINAPI*)(LPCWSTR);
using MoveFileExW_t = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, DWORD);

using GetFileAttributesExW_t = BOOL(WINAPI*)(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
using SetFileAttributesW_t = BOOL(WINAPI*)(LPCWSTR, DWORD);

using GetModuleFileNameW_t = DWORD(WINAPI*)(HMODULE, LPWSTR, DWORD);
using GetModuleHandleW_t = HMODULE(WINAPI*)(LPCWSTR);

using CreateProcessW_t = BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
using WaitForSingleObject_t = DWORD(WINAPI*)(HANDLE, DWORD);
using GetExitCodeProcess_t = BOOL(WINAPI*)(HANDLE, LPDWORD);
using TerminateProcess_t = BOOL(WINAPI*)(HANDLE, UINT);

using CreateEventW_t = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
using SetEvent_t = BOOL(WINAPI*)(HANDLE);
using ResetEvent_t = BOOL(WINAPI*)(HANDLE);

using CreateFileMappingW_t = HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
using MapViewOfFile_t = LPVOID(WINAPI*)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
using UnmapViewOfFile_t = BOOL(WINAPI*)(LPCVOID);

using VirtualAlloc_t = LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
using VirtualFree_t = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD);
using VirtualProtect_t = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);

using GetSystemTimeAsFileTime_t = void (WINAPI*)(LPFILETIME);
using QueryPerformanceCounter_t = BOOL(WINAPI*)(LARGE_INTEGER*);
using QueryPerformanceFrequency_t = BOOL(WINAPI*)(LARGE_INTEGER*);
using Sleep_t = void  (WINAPI*)(DWORD);
using GetTickCount64_t = ULONGLONG(WINAPI*)(void);

using GetEnvironmentVariableW_t = DWORD(WINAPI*)(LPCWSTR, LPWSTR, DWORD);
using SetEnvironmentVariableW_t = BOOL(WINAPI*)(LPCWSTR, LPCWSTR);

using GetTempPathW_t = DWORD(WINAPI*)(DWORD, LPWSTR);
using GetTempFileNameW_t = UINT(WINAPI*)(LPCWSTR, LPCWSTR, UINT, LPWSTR);

// USER32
using MessageBoxW_t = int   (WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT);
using GetSystemMetrics_t = int   (WINAPI*)(int);
using FindWindowW_t = HWND(WINAPI*)(LPCWSTR, LPCWSTR);
using GetForegroundWindow_t = HWND(WINAPI*)(void);
using SetForegroundWindow_t = BOOL(WINAPI*)(HWND);
using ShowWindow_t = BOOL(WINAPI*)(HWND, int);
using GetWindowTextW_t = int   (WINAPI*)(HWND, LPWSTR, int);
using SetWindowTextW_t = BOOL(WINAPI*)(HWND, LPCWSTR);
using GetWindowRect_t = BOOL(WINAPI*)(HWND, LPRECT);
using GetClientRect_t = BOOL(WINAPI*)(HWND, LPRECT);
using RegisterClassExW_t = ATOM(WINAPI*)(const WNDCLASSEXW*);
using CreateWindowExW_t = HWND(WINAPI*)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);
using DestroyWindow_t = BOOL(WINAPI*)(HWND);
using DefWindowProcW_t = LRESULT(WINAPI*)(HWND, UINT, WPARAM, LPARAM);
using GetMessageW_t = BOOL(WINAPI*)(LPMSG, HWND, UINT, UINT);
using TranslateMessage_t = BOOL(WINAPI*)(const MSG*);
using DispatchMessageW_t = LRESULT(WINAPI*)(const MSG*);
using PostQuitMessage_t = void  (WINAPI*)(int);

// ADVAPI32
using RegOpenKeyExW_t = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
using RegCreateKeyExW_t = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM,
    const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
using RegSetValueExW_t = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
using RegQueryValueExW_t = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
using RegEnumKeyExW_t = LSTATUS(WINAPI*)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
using RegEnumValueW_t = LSTATUS(WINAPI*)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
using RegDeleteKeyW_t = LSTATUS(WINAPI*)(HKEY, LPCWSTR);
using RegDeleteValueW_t = LSTATUS(WINAPI*)(HKEY, LPCWSTR);
using RegCloseKey_t = LSTATUS(WINAPI*)(HKEY);
using RegGetValueW_t = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD);

using OpenProcessToken_t = BOOL(WINAPI*)(HANDLE, DWORD, PHANDLE);
using GetTokenInformation_t = BOOL(WINAPI*)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
using LookupPrivilegeValueW_t = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, PLUID);
using AdjustTokenPrivileges_t = BOOL(WINAPI*)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);

using OpenSCManagerW_t = SC_HANDLE(WINAPI*)(LPCWSTR, LPCWSTR, DWORD);
using CreateServiceW_t = SC_HANDLE(WINAPI*)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD,
    LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
using OpenServiceW_t = SC_HANDLE(WINAPI*)(SC_HANDLE, LPCWSTR, DWORD);
using StartServiceW_t = BOOL(WINAPI*)(SC_HANDLE, DWORD, LPCWSTR*);
using ControlService_t = BOOL(WINAPI*)(SC_HANDLE, DWORD, LPSERVICE_STATUS);
using DeleteService_t = BOOL(WINAPI*)(SC_HANDLE);
using CloseServiceHandle_t = BOOL(WINAPI*)(SC_HANDLE);

using CryptAcquireContextW_t = BOOL(WINAPI*)(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
using CryptReleaseContext_t = BOOL(WINAPI*)(HCRYPTPROV, DWORD);
using CryptGenRandom_t = BOOL(WINAPI*)(HCRYPTPROV, DWORD, BYTE*);

// NTDLL typedefs (unchanged)
using RtlGetVersion_t = NTSTATUS(NTAPI*)(PRTL_OSVERSIONINFOW);
using NtDelayExecution_t = NTSTATUS(NTAPI*)(BOOLEAN, PLARGE_INTEGER);
using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
using RtlNtStatusToDosError_t = ULONG(NTAPI*)(NTSTATUS);
using RtlInitUnicodeString_t = VOID(NTAPI*)(PUNICODE_STRING, PCWSTR);
using NtClose_t = NTSTATUS(NTAPI*)(HANDLE);

// ============================================================================
//  SECTION: pre-xored names (enc_* arrays) and their X instances
//  These arrays were produced with your stringEncryption.py using XOR key 0x5A.
//  Each array must include the terminating 0x00 byte.
//  For each enc_<Name> below we declare the corresponding X<Name> with DECL_XENC.
// ============================================================================

//#define DECL_XENC(name) static const XorA<sizeof(enc_##name), 0x5Au> X##name(enc_##name)
#define DECL_XENC(name) static const XorA<sizeof(enc_##name), 0xAAu> X##name(enc_##name)
#define ENC_XOR(name) X##name

// CreateFileW
constexpr unsigned char enc_CreateFileW[] = {
    0xE9, 0xD8, 0xCF, 0xCB, 0xDE, 0xCF, 0xEC, 0xC3, 0xC6, 0xCF, 0xFD, 0x00
};
DECL_XENC(CreateFileW);

// ReadFile
constexpr unsigned char enc_ReadFile[] = {
    0xF8, 0xCF, 0xCB, 0xCE, 0xEC, 0xC3, 0xC6, 0xCF, 0x00
};
DECL_XENC(ReadFile);

// WriteFile
constexpr unsigned char enc_WriteFile[] = {
    0xFD, 0xD8, 0xC3, 0xDE, 0xCF, 0xEC, 0xC3, 0xC6, 0xCF, 0x00
};
DECL_XENC(WriteFile);

// DeleteFileW
constexpr unsigned char enc_DeleteFileW[] = {
    0xEE, 0xCF, 0xC6, 0xCF, 0xDE, 0xCF, 0xEC, 0xC3, 0xC6, 0xCF, 0xFD, 0x00
};
DECL_XENC(DeleteFileW);

constexpr unsigned char enc_MoveFileExW[] = {
    0xE7, 0xC5, 0xDC, 0xCF, 0xEC, 0xC3, 0xC6, 0xCF, 0xEF, 0xD2, 0xFD, 0x00
}; DECL_XENC(MoveFileExW);

constexpr unsigned char enc_GetFileAttributesExW[] = {
    0xED, 0xCF, 0xDE, 0xEC, 0xC3, 0xC6, 0xCF, 0xEB, 0xDE, 0xDE, 0xD8, 0xC3, 0xC8, 0xDF, 0xDE, 0xCF, 0xD9, 0xEF, 0xD2, 0xFD, 0x00
}; DECL_XENC(GetFileAttributesExW);

constexpr unsigned char enc_SetFileAttributesW[] = {
    0xF9, 0xCF, 0xDE, 0xEC, 0xC3, 0xC6, 0xCF, 0xEB, 0xDE, 0xDE, 0xD8, 0xC3, 0xC8, 0xDF, 0xDE, 0xCF, 0xD9, 0xFD, 0x00
}; DECL_XENC(SetFileAttributesW);

constexpr unsigned char enc_CreateDirectoryW[] = {
    0xE9, 0xD8, 0xCF, 0xCB, 0xDE, 0xCF, 0xEE, 0xC3, 0xD8, 0xCF, 0xC9, 0xDE, 0xC5, 0xD8, 0xD3, 0xFD, 0x00
}; DECL_XENC(CreateDirectoryW);

constexpr unsigned char enc_RemoveDirectoryW[] = {
    0xF8, 0xCF, 0xC7, 0xC5, 0xDC, 0xCF, 0xEE, 0xC3, 0xD8, 0xCF, 0xC9, 0xDE, 0xC5, 0xD8, 0xD3, 0xFD, 0x00
}; DECL_XENC(RemoveDirectoryW);

constexpr unsigned char enc_CreateProcessW[] = {
    0xE9, 0xD8, 0xCF, 0xCB, 0xDE, 0xCF, 0xFA, 0xD8, 0xC5, 0xC9, 0xCF, 0xD9, 0xD9, 0xFD, 0x00
}; DECL_XENC(CreateProcessW);

constexpr unsigned char enc_WaitForSingleObject[] = {
    0xFD, 0xCB, 0xC3, 0xDE, 0xEC, 0xC5, 0xD8, 0xF9, 0xC3, 0xC4, 0xCD, 0xC6, 0xCF, 0xE5, 0xC8, 0xC0, 0xCF, 0xC9, 0xDE, 0x00
}; DECL_XENC(WaitForSingleObject);

constexpr unsigned char enc_GetExitCodeProcess[] = {
    0xED, 0xCF, 0xDE, 0xEF, 0xD2, 0xC3, 0xDE, 0xE9, 0xC5, 0xCE, 0xCF, 0xFA, 0xD8, 0xC5, 0xC9, 0xCF, 0xD9, 0xD9, 0x00
}; DECL_XENC(GetExitCodeProcess);

constexpr unsigned char enc_TerminateProcess[] = {
    0xFE, 0xCF, 0xD8, 0xC7, 0xC3, 0xC4, 0xCB, 0xDE, 0xCF, 0xFA, 0xD8, 0xC5, 0xC9, 0xCF, 0xD9, 0xD9, 0x00
}; DECL_XENC(TerminateProcess);

constexpr unsigned char enc_CreateEventW[] = {
    0xE9, 0xD8, 0xCF, 0xCB, 0xDE, 0xCF, 0xEF, 0xDC, 0xCF, 0xC4, 0xDE, 0xFD, 0x00
}; DECL_XENC(CreateEventW);

constexpr unsigned char enc_SetEvent[] = {
    0xF9, 0xCF, 0xDE, 0xEF, 0xDC, 0xCF, 0xC4, 0xDE, 0x00
}; DECL_XENC(SetEvent);

constexpr unsigned char enc_ResetEvent[] = {
    0xF8, 0xCF, 0xD9, 0xCF, 0xDE, 0xEF, 0xDC, 0xCF, 0xC4, 0xDE, 0x00
}; DECL_XENC(ResetEvent);

constexpr unsigned char enc_CreateFileMappingW[] = {
    0xE9, 0xD8, 0xCF, 0xCB, 0xDE, 0xCF, 0xEC, 0xC3, 0xC6, 0xCF, 0xE7, 0xCB, 0xDA, 0xDA, 0xC3, 0xC4, 0xCD, 0xFD, 0x00
}; DECL_XENC(CreateFileMappingW);

constexpr unsigned char enc_MapViewOfFile[] = {
    0xE7, 0xCB, 0xDA, 0xFC, 0xC3, 0xCF, 0xDD, 0xE5, 0xCC, 0xEC, 0xC3, 0xC6, 0xCF, 0x00
}; DECL_XENC(MapViewOfFile);

constexpr unsigned char enc_UnmapViewOfFile[] = {
    0xFF, 0xC4, 0xC7, 0xCB, 0xDA, 0xFC, 0xC3, 0xCF, 0xDD, 0xE5, 0xCC, 0xEC, 0xC3, 0xC6, 0xCF, 0x00
}; DECL_XENC(UnmapViewOfFile);

constexpr unsigned char enc_VirtualAlloc[] = {
    0xFC, 0xC3, 0xD8, 0xDE, 0xDF, 0xCB, 0xC6, 0xEB, 0xC6, 0xC6, 0xC5, 0xC9, 0x00
}; DECL_XENC(VirtualAlloc);

constexpr unsigned char enc_VirtualFree[] = {
    0xFC, 0xC3, 0xD8, 0xDE, 0xDF, 0xCB, 0xC6, 0xEC, 0xD8, 0xCF, 0xCF, 0x00
}; DECL_XENC(VirtualFree);

constexpr unsigned char enc_VirtualProtect[] = {
    0xFC, 0xC3, 0xD8, 0xDE, 0xDF, 0xCB, 0xC6, 0xFA, 0xD8, 0xC5, 0xDE, 0xCF, 0xC9, 0xDE, 0x00
}; DECL_XENC(VirtualProtect);

constexpr unsigned char enc_GetModuleFileNameW[] = {
    0xED, 0xCF, 0xDE, 0xE7, 0xC5, 0xCE, 0xDF, 0xC6, 0xCF, 0xEC, 0xC3, 0xC6, 0xCF, 0xE4, 0xCB, 0xC7, 0xCF, 0xFD, 0x00
}; DECL_XENC(GetModuleFileNameW);

constexpr unsigned char enc_GetModuleHandleW[] = {
    0xED, 0xCF, 0xDE, 0xE7, 0xC5, 0xCE, 0xDF, 0xC6, 0xCF, 0xE2, 0xCB, 0xC4, 0xCE, 0xC6, 0xCF, 0xFD, 0x00
}; DECL_XENC(GetModuleHandleW);

constexpr unsigned char enc_GetSystemTimeAsFileTime[] = {
    0xED, 0xCF, 0xDE, 0xF9, 0xD3, 0xD9, 0xDE, 0xCF, 0xC7, 0xFE, 0xC3, 0xC7, 0xCF, 0xEB, 0xD9, 0xEC, 0xC3, 0xC6, 0xCF, 0xFE, 0xC3, 0xC7, 0xCF, 0x00
}; DECL_XENC(GetSystemTimeAsFileTime);

constexpr unsigned char enc_QueryPerformanceCounter[] = {
    0xFB, 0xDF, 0xCF, 0xD8, 0xD3, 0xFA, 0xCF, 0xD8, 0xCC, 0xC5, 0xD8, 0xC7, 0xCB, 0xC4, 0xC9, 0xCF, 0xE9, 0xC5, 0xDF, 0xC4, 0xDE, 0xCF, 0xD8, 0x00
}; DECL_XENC(QueryPerformanceCounter);

constexpr unsigned char enc_QueryPerformanceFrequency[] = {
    0xFB, 0xDF, 0xCF, 0xD8, 0xD3, 0xFA, 0xCF, 0xD8, 0xCC, 0xC5, 0xD8, 0xC7, 0xCB, 0xC4, 0xC9, 0xCF, 0xEC, 0xD8, 0xCF, 0xDB, 0xDF, 0xCF, 0xC4, 0xC9, 0xD3, 0x00
}; DECL_XENC(QueryPerformanceFrequency);

constexpr unsigned char enc_Sleep[] = {
    0xF9, 0xC6, 0xCF, 0xCF, 0xDA, 0x00
}; DECL_XENC(Sleep);

constexpr unsigned char enc_GetTickCount64[] = {
    0xED, 0xCF, 0xDE, 0xFE, 0xC3, 0xC9, 0xC1, 0xE9, 0xC5, 0xDF, 0xC4, 0xDE, 0x9C, 0x9E, 0x00
}; DECL_XENC(GetTickCount64);

constexpr unsigned char enc_GetEnvironmentVariableW[] = {
    0xED, 0xCF, 0xDE, 0xEF, 0xC4, 0xDC, 0xC3, 0xD8, 0xC5, 0xC4, 0xC7, 0xCF, 0xC4, 0xDE, 0xFC, 0xCB, 0xD8, 0xC3, 0xCB, 0xC8, 0xC6, 0xCF, 0xFD, 0x00
}; DECL_XENC(GetEnvironmentVariableW);

constexpr unsigned char enc_SetEnvironmentVariableW[] = {
    0xF9, 0xCF, 0xDE, 0xEF, 0xC4, 0xDC, 0xC3, 0xD8, 0xC5, 0xC4, 0xC7, 0xCF, 0xC4, 0xDE, 0xFC, 0xCB, 0xD8, 0xC3, 0xCB, 0xC8, 0xC6, 0xCF, 0xFD, 0x00
}; DECL_XENC(SetEnvironmentVariableW);

constexpr unsigned char enc_GetTempPathW[] = {
    0xED, 0xCF, 0xDE, 0xFE, 0xCF, 0xC7, 0xDA, 0xFA, 0xCB, 0xDE, 0xC2, 0xFD, 0x00
}; DECL_XENC(GetTempPathW);

constexpr unsigned char enc_GetTempFileNameW[] = {
    0xED, 0xCF, 0xDE, 0xFE, 0xCF, 0xC7, 0xDA, 0xEC, 0xC3, 0xC6, 0xCF, 0xE4, 0xCB, 0xC7, 0xCF, 0xFD, 0x00
}; DECL_XENC(GetTempFileNameW);

constexpr unsigned char enc_CloseHandle[] = {
    0xE9, 0xC6, 0xC5, 0xD9, 0xCF, 0xE2, 0xCB, 0xC4, 0xCE, 0xC6, 0xCF, 0x00
}; DECL_XENC(CloseHandle);

constexpr unsigned char enc_GetLastError[] = {
    0xED, 0xCF, 0xDE, 0xE6, 0xCB, 0xD9, 0xDE, 0xEF, 0xD8, 0xD8, 0xC5, 0xD8, 0x00
}; DECL_XENC(GetLastError);

/*** User32 ***/
constexpr unsigned char enc_MessageBoxW[] = {
    0xE7, 0xCF, 0xD9, 0xD9, 0xCB, 0xCD, 0xCF, 0xE8, 0xC5, 0xD2, 0xFD, 0x00
}; DECL_XENC(MessageBoxW);

constexpr unsigned char enc_GetSystemMetrics[] = {
    0xED, 0xCF, 0xDE, 0xF9, 0xD3, 0xD9, 0xDE, 0xCF, 0xC7, 0xE7, 0xCF, 0xDE, 0xD8, 0xC3, 0xC9, 0xD9, 0x00
}; DECL_XENC(GetSystemMetrics);

constexpr unsigned char enc_FindWindowW[] = {
    0xEC, 0xC3, 0xC4, 0xCE, 0xFD, 0xC3, 0xC4, 0xCE, 0xC5, 0xDD, 0xFD, 0x00
}; DECL_XENC(FindWindowW);

constexpr unsigned char enc_GetForegroundWindow[] = {
    0xED, 0xCF, 0xDE, 0xEC, 0xC5, 0xD8, 0xCF, 0xCD, 0xD8, 0xC5, 0xDF, 0xC4, 0xCE, 0xFD, 0xC3, 0xC4, 0xCE, 0xC5, 0xDD, 0x00
}; DECL_XENC(GetForegroundWindow);

constexpr unsigned char enc_SetForegroundWindow[] = {
    0xF9, 0xCF, 0xDE, 0xEC, 0xC5, 0xD8, 0xCF, 0xCD, 0xD8, 0xC5, 0xDF, 0xC4, 0xCE, 0xFD, 0xC3, 0xC4, 0xCE, 0xC5, 0xDD, 0x00
}; DECL_XENC(SetForegroundWindow);

constexpr unsigned char enc_ShowWindow[] = {
    0xF9, 0xC2, 0xC5, 0xDD, 0xFD, 0xC3, 0xC4, 0xCE, 0xC5, 0xDD, 0x00
}; DECL_XENC(ShowWindow);

constexpr unsigned char enc_GetWindowTextW[] = {
    0xED, 0xCF, 0xDE, 0xFD, 0xC3, 0xC4, 0xCE, 0xC5, 0xDD, 0xFE, 0xCF, 0xD2, 0xDE, 0xFD, 0x00
}; DECL_XENC(GetWindowTextW);

constexpr unsigned char enc_SetWindowTextW[] = {
    0xF9, 0xCF, 0xDE, 0xFD, 0xC3, 0xC4, 0xCE, 0xC5, 0xDD, 0xFE, 0xCF, 0xD2, 0xDE, 0xFD, 0x00
}; DECL_XENC(SetWindowTextW);

constexpr unsigned char enc_GetWindowRect[] = {
    0xED, 0xCF, 0xDE, 0xFD, 0xC3, 0xC4, 0xCE, 0xC5, 0xDD, 0xF8, 0xCF, 0xC9, 0xDE, 0x00
}; DECL_XENC(GetWindowRect);

constexpr unsigned char enc_GetClientRect[] = {
    0xED, 0xCF, 0xDE, 0xE9, 0xC6, 0xC3, 0xCF, 0xC4, 0xDE, 0xF8, 0xCF, 0xC9, 0xDE, 0x00
}; DECL_XENC(GetClientRect);

constexpr unsigned char enc_RegisterClassExW[] = {
    0xF8, 0xCF, 0xCD, 0xC3, 0xD9, 0xDE, 0xCF, 0xD8, 0xE9, 0xC6, 0xCB, 0xD9, 0xD9, 0xEF, 0xD2, 0xFD, 0x00
}; DECL_XENC(RegisterClassExW);

constexpr unsigned char enc_CreateWindowExW[] = {
    0xE9, 0xD8, 0xCF, 0xCB, 0xDE, 0xCF, 0xFD, 0xC3, 0xC4, 0xCE, 0xC5, 0xDD, 0xEF, 0xD2, 0xFD, 0x00
}; DECL_XENC(CreateWindowExW);

constexpr unsigned char enc_DestroyWindow[] = {
    0xEE, 0xCF, 0xD9, 0xDE, 0xD8, 0xC5, 0xD3, 0xFD, 0xC3, 0xC4, 0xCE, 0xC5, 0xDD, 0x00
}; DECL_XENC(DestroyWindow);

constexpr unsigned char enc_DefWindowProcW[] = {
    0xEE, 0xCF, 0xCC, 0xFD, 0xC3, 0xC4, 0xCE, 0xC5, 0xDD, 0xFA, 0xD8, 0xC5, 0xC9, 0xFD, 0x00
}; DECL_XENC(DefWindowProcW);

constexpr unsigned char enc_GetMessageW[] = {
    0xED, 0xCF, 0xDE, 0xE7, 0xCF, 0xD9, 0xD9, 0xCB, 0xCD, 0xCF, 0xFD, 0x00
}; DECL_XENC(GetMessageW);

constexpr unsigned char enc_TranslateMessage[] = {
    0xFE, 0xD8, 0xCB, 0xC4, 0xD9, 0xC6, 0xCB, 0xDE, 0xCF, 0xE7, 0xCF, 0xD9, 0xD9, 0xCB, 0xCD, 0xCF, 0x00
}; DECL_XENC(TranslateMessage);

constexpr unsigned char enc_DispatchMessageW[] = {
    0xEE, 0xC3, 0xD9, 0xDA, 0xCB, 0xDE, 0xC9, 0xC2, 0xE7, 0xCF, 0xD9, 0xD9, 0xCB, 0xCD, 0xCF, 0xFD, 0x00
}; DECL_XENC(DispatchMessageW);

constexpr unsigned char enc_PostQuitMessage[] = {
    0xFA, 0xC5, 0xD9, 0xDE, 0xFB, 0xDF, 0xC3, 0xDE, 0xE7, 0xCF, 0xD9, 0xD9, 0xCB, 0xCD, 0xCF, 0x00
}; DECL_XENC(PostQuitMessage);


constexpr unsigned char enc_RegOpenKeyExW[] = {
    0xF8, 0xCF, 0xCD, 0xE5, 0xDA, 0xCF, 0xC4, 0xE1, 0xCF, 0xD3, 0xEF, 0xD2, 0xFD, 0x00
}; DECL_XENC(RegOpenKeyExW);

constexpr unsigned char enc_RegCreateKeyExW[] = {
    0xF8, 0xCF, 0xCD, 0xE9, 0xD8, 0xCF, 0xCB, 0xDE, 0xCF, 0xE1, 0xCF, 0xD3, 0xEF, 0xD2, 0xFD, 0x00
}; DECL_XENC(RegCreateKeyExW);

constexpr unsigned char enc_RegSetValueExW[] = {
    0xF8, 0xCF, 0xCD, 0xF9, 0xCF, 0xDE, 0xFC, 0xCB, 0xC6, 0xDF, 0xCF, 0xEF, 0xD2, 0xFD, 0x00
}; DECL_XENC(RegSetValueExW);

constexpr unsigned char enc_RegQueryValueExW[] = {
    0xF8, 0xCF, 0xCD, 0xFB, 0xDF, 0xCF, 0xD8, 0xD3, 0xFC, 0xCB, 0xC6, 0xDF, 0xCF, 0xEF, 0xD2, 0xFD, 0x00
}; DECL_XENC(RegQueryValueExW);

constexpr unsigned char enc_RegEnumKeyExW[] = {
    0xF8, 0xCF, 0xCD, 0xEF, 0xC4, 0xDF, 0xC7, 0xE1, 0xCF, 0xD3, 0xEF, 0xD2, 0xFD, 0x00
}; DECL_XENC(RegEnumKeyExW);

constexpr unsigned char enc_RegEnumValueW[] = {
    0xF8, 0xCF, 0xCD, 0xEF, 0xC4, 0xDF, 0xC7, 0xFC, 0xCB, 0xC6, 0xDF, 0xCF, 0xFD, 0x00
}; DECL_XENC(RegEnumValueW);

constexpr unsigned char enc_RegDeleteKeyW[] = {
    0xF8, 0xCF, 0xCD, 0xEE, 0xCF, 0xC6, 0xCF, 0xDE, 0xCF, 0xE1, 0xCF, 0xD3, 0xFD, 0x00
}; DECL_XENC(RegDeleteKeyW);

constexpr unsigned char enc_RegDeleteValueW[] = {
    0xF8, 0xCF, 0xCD, 0xEE, 0xCF, 0xC6, 0xCF, 0xDE, 0xCF, 0xFC, 0xCB, 0xC6, 0xDF, 0xCF, 0xFD, 0x00
}; DECL_XENC(RegDeleteValueW);

constexpr unsigned char enc_RegCloseKey[] = {
    0xF8, 0xCF, 0xCD, 0xE9, 0xC6, 0xC5, 0xD9, 0xCF, 0xE1, 0xCF, 0xD3, 0x00
}; DECL_XENC(RegCloseKey);

constexpr unsigned char enc_RegGetValueW[] = {
    0xF8, 0xCF, 0xCD, 0xED, 0xCF, 0xDE, 0xFC, 0xCB, 0xC6, 0xDF, 0xCF, 0xFD, 0x00
}; DECL_XENC(RegGetValueW);

constexpr unsigned char enc_OpenProcessToken[] = {
    0xE5, 0xDA, 0xCF, 0xC4, 0xFA, 0xD8, 0xC5, 0xC9, 0xCF, 0xD9, 0xD9, 0xFE, 0xC5, 0xC1, 0xCF, 0xC4, 0x00
}; DECL_XENC(OpenProcessToken);

constexpr unsigned char enc_GetTokenInformation[] = {
    0xED, 0xCF, 0xDE, 0xFE, 0xC5, 0xC1, 0xCF, 0xC4, 0xE3, 0xC4, 0xCC, 0xC5, 0xD8, 0xC7, 0xCB, 0xDE, 0xC3, 0xC5, 0xC4, 0x00
}; DECL_XENC(GetTokenInformation);

constexpr unsigned char enc_LookupPrivilegeValueW[] = {
    0xE6, 0xC5, 0xC5, 0xC1, 0xDF, 0xDA, 0xFA, 0xD8, 0xC3, 0xDC, 0xC3, 0xC6, 0xCF, 0xCD, 0xCF, 0xFC, 0xCB, 0xC6, 0xDF, 0xCF, 0xFD, 0x00
}; DECL_XENC(LookupPrivilegeValueW);

constexpr unsigned char enc_AdjustTokenPrivileges[] = {
    0xEB, 0xCE, 0xC0, 0xDF, 0xD9, 0xDE, 0xFE, 0xC5, 0xC1, 0xCF, 0xC4, 0xFA, 0xD8, 0xC3, 0xDC, 0xC3, 0xC6, 0xCF, 0xCD, 0xCF, 0xD9, 0x00
}; DECL_XENC(AdjustTokenPrivileges);

constexpr unsigned char enc_OpenSCManagerW[] = {
    0xE5, 0xDA, 0xCF, 0xC4, 0xF9, 0xE9, 0xE7, 0xCB, 0xC4, 0xCB, 0xCD, 0xCF, 0xD8, 0xFD, 0x00
}; DECL_XENC(OpenSCManagerW);

constexpr unsigned char enc_CreateServiceW[] = {
    0xE9, 0xD8, 0xCF, 0xCB, 0xDE, 0xCF, 0xF9, 0xCF, 0xD8, 0xDC, 0xC3, 0xC9, 0xCF, 0xFD, 0x00
}; DECL_XENC(CreateServiceW);

constexpr unsigned char enc_OpenServiceW[] = {
    0xE5, 0xDA, 0xCF, 0xC4, 0xF9, 0xCF, 0xD8, 0xDC, 0xC3, 0xC9, 0xCF, 0xFD, 0x00
}; DECL_XENC(OpenServiceW);

constexpr unsigned char enc_StartServiceW[] = {
    0xF9, 0xDE, 0xCB, 0xD8, 0xDE, 0xF9, 0xCF, 0xD8, 0xDC, 0xC3, 0xC9, 0xCF, 0xFD, 0x00
}; DECL_XENC(StartServiceW);

constexpr unsigned char enc_ControlService[] = {
    0xE9, 0xC5, 0xC4, 0xDE, 0xD8, 0xC5, 0xC6, 0xF9, 0xCF, 0xD8, 0xDC, 0xC3, 0xC9, 0xCF, 0x00
}; DECL_XENC(ControlService);

constexpr unsigned char enc_DeleteService[] = {
    0xEE, 0xCF, 0xC6, 0xCF, 0xDE, 0xCF, 0xF9, 0xCF, 0xD8, 0xDC, 0xC3, 0xC9, 0xCF, 0x00
}; DECL_XENC(DeleteService);

constexpr unsigned char enc_CloseServiceHandle[] = {
    0xE9, 0xC6, 0xC5, 0xD9, 0xCF, 0xF9, 0xCF, 0xD8, 0xDC, 0xC3, 0xC9, 0xCF, 0xE2, 0xCB, 0xC4, 0xCE, 0xC6, 0xCF, 0x00
}; DECL_XENC(CloseServiceHandle);

constexpr unsigned char enc_CryptAcquireContextW[] = {
    0xE9, 0xD8, 0xD3, 0xDA, 0xDE, 0xEB, 0xC9, 0xDB, 0xDF, 0xC3, 0xD8, 0xCF, 0xE9, 0xC5, 0xC4, 0xDE, 0xCF, 0xD2, 0xDE, 0xFD, 0x00
}; DECL_XENC(CryptAcquireContextW);

constexpr unsigned char enc_CryptReleaseContext[] = {
    0xE9, 0xD8, 0xD3, 0xDA, 0xDE, 0xF8, 0xCF, 0xC6, 0xCF, 0xCB, 0xD9, 0xCF, 0xE9, 0xC5, 0xC4, 0xDE, 0xCF, 0xD2, 0xDE, 0x00
}; DECL_XENC(CryptReleaseContext);

constexpr unsigned char enc_CryptGenRandom[] = {
    0xE9, 0xD8, 0xD3, 0xDA, 0xDE, 0xED, 0xCF, 0xC4, 0xF8, 0xCB, 0xC4, 0xCE, 0xC5, 0xC7, 0x00
}; DECL_XENC(CryptGenRandom);

constexpr unsigned char enc_RtlGetVersion[] = {
    0xF8, 0xDE, 0xC6, 0xED, 0xCF, 0xDE, 0xFC, 0xCF, 0xD8, 0xD9, 0xC3, 0xC5, 0xC4, 0x00
}; DECL_XENC(RtlGetVersion);

constexpr unsigned char enc_NtDelayExecution[] = {
    0xE4, 0xDE, 0xEE, 0xCF, 0xC6, 0xCB, 0xD3, 0xEF, 0xD2, 0xCF, 0xC9, 0xDF, 0xDE, 0xC3, 0xC5, 0xC4, 0x00
}; DECL_XENC(NtDelayExecution);

constexpr unsigned char enc_NtQuerySystemInformation[] = {
    0xE4, 0xDE, 0xFB, 0xDF, 0xCF, 0xD8, 0xD3, 0xF9, 0xD3, 0xD9, 0xDE, 0xCF, 0xC7, 0xE3, 0xC4, 0xCC, 0xC5, 0xD8, 0xC7, 0xCB, 0xDE, 0xC3, 0xC5, 0xC4, 0x00
}; DECL_XENC(NtQuerySystemInformation);

constexpr unsigned char enc_RtlNtStatusToDosError[] = {
    0xF8, 0xDE, 0xC6, 0xE4, 0xDE, 0xF9, 0xDE, 0xCB, 0xDE, 0xDF, 0xD9, 0xFE, 0xC5, 0xEE, 0xC5, 0xD9, 0xEF, 0xD8, 0xD8, 0xC5, 0xD8, 0x00
}; DECL_XENC(RtlNtStatusToDosError);

constexpr unsigned char enc_RtlInitUnicodeString[] = {
    0xF8, 0xDE, 0xC6, 0xE3, 0xC4, 0xC3, 0xDE, 0xFF, 0xC4, 0xC3, 0xC9, 0xC5, 0xCE, 0xCF, 0xF9, 0xDE, 0xD8, 0xC3, 0xC4, 0xCD, 0x00
}; DECL_XENC(RtlInitUnicodeString);

constexpr unsigned char enc_NtClose[] = {
    0xE4, 0xDE, 0xE9, 0xC6, 0xC5, 0xD9, 0xCF, 0x00
}; DECL_XENC(NtClose);

// ============================================================================
//  Wrappers per module (use ENC_XOR(...) for names)
// ============================================================================

struct Kernel32 {
    Kernel32() : mod(L"kernel32.dll") {
        // File I/O
        CreateFileW = mod.get_xor<CreateFileW_t>(ENC_XOR(CreateFileW));
        ReadFile = mod.get_xor<ReadFile_t>(ENC_XOR(ReadFile));
        WriteFile = mod.get_xor<WriteFile_t>(ENC_XOR(WriteFile));
        DeleteFileW = mod.get_xor<DeleteFileW_t>(ENC_XOR(DeleteFileW));
        MoveFileExW = mod.get_xor<MoveFileExW_t>(ENC_XOR(MoveFileExW));
        GetFileAttributesExW = mod.get_xor<GetFileAttributesExW_t>(ENC_XOR(GetFileAttributesExW));
        SetFileAttributesW = mod.get_xor<SetFileAttributesW_t>(ENC_XOR(SetFileAttributesW));
        CreateDirectoryW = mod.get_xor<CreateDirectoryW_t>(ENC_XOR(CreateDirectoryW));
        RemoveDirectoryW = mod.get_xor<RemoveDirectoryW_t>(ENC_XOR(RemoveDirectoryW));

        // Processes / sync
        CreateProcessW = mod.get_xor<CreateProcessW_t>(ENC_XOR(CreateProcessW));
        WaitForSingleObject = mod.get_xor<WaitForSingleObject_t>(ENC_XOR(WaitForSingleObject));
        GetExitCodeProcess = mod.get_xor<GetExitCodeProcess_t>(ENC_XOR(GetExitCodeProcess));
        TerminateProcess = mod.get_xor<TerminateProcess_t>(ENC_XOR(TerminateProcess));
        CreateEventW = mod.get_xor<CreateEventW_t>(ENC_XOR(CreateEventW));
        SetEvent = mod.get_xor<SetEvent_t>(ENC_XOR(SetEvent));
        ResetEvent = mod.get_xor<ResetEvent_t>(ENC_XOR(ResetEvent));

        // Memory / mapping
        CreateFileMappingW = mod.get_xor<CreateFileMappingW_t>(ENC_XOR(CreateFileMappingW));
        MapViewOfFile = mod.get_xor<MapViewOfFile_t>(ENC_XOR(MapViewOfFile));
        UnmapViewOfFile = mod.get_xor<UnmapViewOfFile_t>(ENC_XOR(UnmapViewOfFile));
        VirtualAlloc = mod.get_xor<VirtualAlloc_t>(ENC_XOR(VirtualAlloc));
        VirtualFree = mod.get_xor<VirtualFree_t>(ENC_XOR(VirtualFree));
        VirtualProtect = mod.get_xor<VirtualProtect_t>(ENC_XOR(VirtualProtect));

        // System info / misc
        GetModuleFileNameW = mod.get_xor<GetModuleFileNameW_t>(ENC_XOR(GetModuleFileNameW));
        GetModuleHandleW = mod.get_xor<GetModuleHandleW_t>(ENC_XOR(GetModuleHandleW));
        GetSystemTimeAsFileTime = mod.get_xor<GetSystemTimeAsFileTime_t>(ENC_XOR(GetSystemTimeAsFileTime));
        QueryPerformanceCounter = mod.get_xor<QueryPerformanceCounter_t>(ENC_XOR(QueryPerformanceCounter));
        QueryPerformanceFrequency = mod.get_xor<QueryPerformanceFrequency_t>(ENC_XOR(QueryPerformanceFrequency));
        Sleep = mod.get_xor<Sleep_t>(ENC_XOR(Sleep));
        GetTickCount64 = mod.get_xor<GetTickCount64_t>(ENC_XOR(GetTickCount64));
        GetEnvironmentVariableW = mod.get_xor<GetEnvironmentVariableW_t>(ENC_XOR(GetEnvironmentVariableW));
        SetEnvironmentVariableW = mod.get_xor<SetEnvironmentVariableW_t>(ENC_XOR(SetEnvironmentVariableW));
        GetTempPathW = mod.get_xor<GetTempPathW_t>(ENC_XOR(GetTempPathW));
        GetTempFileNameW = mod.get_xor<GetTempFileNameW_t>(ENC_XOR(GetTempFileNameW));

        // Always last: Close/GetLastError
        CloseHandle = mod.get_xor<CloseHandle_t>(ENC_XOR(CloseHandle));
        GetLastError = mod.get_xor<GetLastError_t>(ENC_XOR(GetLastError));
    }

    DynModule mod;

    // Pointers
    CreateFileW_t    CreateFileW = nullptr;
    ReadFile_t       ReadFile = nullptr;
    WriteFile_t      WriteFile = nullptr;
    DeleteFileW_t    DeleteFileW = nullptr;
    MoveFileExW_t    MoveFileExW = nullptr;
    GetFileAttributesExW_t GetFileAttributesExW = nullptr;
    SetFileAttributesW_t   SetFileAttributesW = nullptr;
    CreateDirectoryW_t     CreateDirectoryW = nullptr;
    RemoveDirectoryW_t     RemoveDirectoryW = nullptr;

    CreateProcessW_t CreateProcessW = nullptr;
    WaitForSingleObject_t WaitForSingleObject = nullptr;
    GetExitCodeProcess_t  GetExitCodeProcess = nullptr;
    TerminateProcess_t    TerminateProcess = nullptr;
    CreateEventW_t  CreateEventW = nullptr;
    SetEvent_t      SetEvent = nullptr;
    ResetEvent_t    ResetEvent = nullptr;

    CreateFileMappingW_t CreateFileMappingW = nullptr;
    MapViewOfFile_t      MapViewOfFile = nullptr;
    UnmapViewOfFile_t    UnmapViewOfFile = nullptr;
    VirtualAlloc_t       VirtualAlloc = nullptr;
    VirtualFree_t        VirtualFree = nullptr;
    VirtualProtect_t     VirtualProtect = nullptr;

    GetModuleFileNameW_t GetModuleFileNameW = nullptr;
    GetModuleHandleW_t   GetModuleHandleW = nullptr;
    GetSystemTimeAsFileTime_t GetSystemTimeAsFileTime = nullptr;
    QueryPerformanceCounter_t  QueryPerformanceCounter = nullptr;
    QueryPerformanceFrequency_t QueryPerformanceFrequency = nullptr;
    Sleep_t              Sleep = nullptr;
    GetTickCount64_t     GetTickCount64 = nullptr;
    GetEnvironmentVariableW_t GetEnvironmentVariableW = nullptr;
    SetEnvironmentVariableW_t SetEnvironmentVariableW = nullptr;
    GetTempPathW_t       GetTempPathW = nullptr;
    GetTempFileNameW_t   GetTempFileNameW = nullptr;

    CloseHandle_t  CloseHandle = nullptr;
    GetLastError_t GetLastError = nullptr;
};

struct User32 {
    User32() : mod(L"user32.dll") {
        MessageBoxW = mod.get_xor<MessageBoxW_t>(ENC_XOR(MessageBoxW));
        GetSystemMetrics = mod.get_xor<GetSystemMetrics_t>(ENC_XOR(GetSystemMetrics));
        FindWindowW = mod.get_xor<FindWindowW_t>(ENC_XOR(FindWindowW));
        GetForegroundWindow = mod.get_xor<GetForegroundWindow_t>(ENC_XOR(GetForegroundWindow));
        SetForegroundWindow = mod.get_xor<SetForegroundWindow_t>(ENC_XOR(SetForegroundWindow));
        ShowWindow = mod.get_xor<ShowWindow_t>(ENC_XOR(ShowWindow));
        GetWindowTextW = mod.get_xor<GetWindowTextW_t>(ENC_XOR(GetWindowTextW));
        SetWindowTextW = mod.get_xor<SetWindowTextW_t>(ENC_XOR(SetWindowTextW));
        GetWindowRect = mod.get_xor<GetWindowRect_t>(ENC_XOR(GetWindowRect));
        GetClientRect = mod.get_xor<GetClientRect_t>(ENC_XOR(GetClientRect));
        RegisterClassExW = mod.get_xor<RegisterClassExW_t>(ENC_XOR(RegisterClassExW));
        CreateWindowExW = mod.get_xor<CreateWindowExW_t>(ENC_XOR(CreateWindowExW));
        DestroyWindow = mod.get_xor<DestroyWindow_t>(ENC_XOR(DestroyWindow));
        DefWindowProcW = mod.get_xor<DefWindowProcW_t>(ENC_XOR(DefWindowProcW));
        GetMessageW = mod.get_xor<GetMessageW_t>(ENC_XOR(GetMessageW));
        TranslateMessage = mod.get_xor<TranslateMessage_t>(ENC_XOR(TranslateMessage));
        DispatchMessageW = mod.get_xor<DispatchMessageW_t>(ENC_XOR(DispatchMessageW));
        PostQuitMessage = mod.get_xor<PostQuitMessage_t>(ENC_XOR(PostQuitMessage));
    }

    DynModule mod;

    MessageBoxW_t         MessageBoxW = nullptr;
    GetSystemMetrics_t    GetSystemMetrics = nullptr;
    FindWindowW_t         FindWindowW = nullptr;
    GetForegroundWindow_t GetForegroundWindow = nullptr;
    SetForegroundWindow_t SetForegroundWindow = nullptr;
    ShowWindow_t          ShowWindow = nullptr;
    GetWindowTextW_t      GetWindowTextW = nullptr;
    SetWindowTextW_t      SetWindowTextW = nullptr;
    GetWindowRect_t       GetWindowRect = nullptr;
    GetClientRect_t       GetClientRect = nullptr;
    RegisterClassExW_t    RegisterClassExW = nullptr;
    CreateWindowExW_t     CreateWindowExW = nullptr;
    DestroyWindow_t       DestroyWindow = nullptr;
    DefWindowProcW_t      DefWindowProcW = nullptr;
    GetMessageW_t         GetMessageW = nullptr;
    TranslateMessage_t    TranslateMessage = nullptr;
    DispatchMessageW_t    DispatchMessageW = nullptr;
    PostQuitMessage_t     PostQuitMessage = nullptr;
};

struct Advapi32 {
    Advapi32() : mod(L"advapi32.dll") {
        // Registry
        RegOpenKeyExW = mod.get_xor<RegOpenKeyExW_t>(ENC_XOR(RegOpenKeyExW));
        RegCreateKeyExW = mod.get_xor<RegCreateKeyExW_t>(ENC_XOR(RegCreateKeyExW));
        RegSetValueExW = mod.get_xor<RegSetValueExW_t>(ENC_XOR(RegSetValueExW));
        RegQueryValueExW = mod.get_xor<RegQueryValueExW_t>(ENC_XOR(RegQueryValueExW));
        RegEnumKeyExW = mod.get_xor<RegEnumKeyExW_t>(ENC_XOR(RegEnumKeyExW));
        RegEnumValueW = mod.get_xor<RegEnumValueW_t>(ENC_XOR(RegEnumValueW));
        RegDeleteKeyW = mod.get_xor<RegDeleteKeyW_t>(ENC_XOR(RegDeleteKeyW));
        RegDeleteValueW = mod.get_xor<RegDeleteValueW_t>(ENC_XOR(RegDeleteValueW));
        RegCloseKey = mod.get_xor<RegCloseKey_t>(ENC_XOR(RegCloseKey));
        RegGetValueW = mod.try_get_xor<RegGetValueW_t>(ENC_XOR(RegGetValueW)); // may be null on very old systems

        // Tokens / privileges
        OpenProcessToken = mod.get_xor<OpenProcessToken_t>(ENC_XOR(OpenProcessToken));
        GetTokenInformation = mod.get_xor<GetTokenInformation_t>(ENC_XOR(GetTokenInformation));
        LookupPrivilegeValueW = mod.get_xor<LookupPrivilegeValueW_t>(ENC_XOR(LookupPrivilegeValueW));
        AdjustTokenPrivileges = mod.get_xor<AdjustTokenPrivileges_t>(ENC_XOR(AdjustTokenPrivileges));

        // Services (SCM)
        OpenSCManagerW = mod.get_xor<OpenSCManagerW_t>(ENC_XOR(OpenSCManagerW));
        CreateServiceW = mod.get_xor<CreateServiceW_t>(ENC_XOR(CreateServiceW));
        OpenServiceW = mod.get_xor<OpenServiceW_t>(ENC_XOR(OpenServiceW));
        StartServiceW = mod.get_xor<StartServiceW_t>(ENC_XOR(StartServiceW));
        ControlService = mod.get_xor<ControlService_t>(ENC_XOR(ControlService));
        DeleteService = mod.get_xor<DeleteService_t>(ENC_XOR(DeleteService));
        CloseServiceHandle = mod.get_xor<CloseServiceHandle_t>(ENC_XOR(CloseServiceHandle));

        // CryptoAPI
        CryptAcquireContextW = mod.get_xor<CryptAcquireContextW_t>(ENC_XOR(CryptAcquireContextW));
        CryptReleaseContext = mod.get_xor<CryptReleaseContext_t >(ENC_XOR(CryptReleaseContext));
        CryptGenRandom = mod.get_xor<CryptGenRandom_t      >(ENC_XOR(CryptGenRandom));
    }

    DynModule mod;

    // Registry
    RegOpenKeyExW_t    RegOpenKeyExW = nullptr;
    RegCreateKeyExW_t  RegCreateKeyExW = nullptr;
    RegSetValueExW_t   RegSetValueExW = nullptr;
    RegQueryValueExW_t RegQueryValueExW = nullptr;
    RegEnumKeyExW_t    RegEnumKeyExW = nullptr;
    RegEnumValueW_t    RegEnumValueW = nullptr;
    RegDeleteKeyW_t    RegDeleteKeyW = nullptr;
    RegDeleteValueW_t  RegDeleteValueW = nullptr;
    RegCloseKey_t      RegCloseKey = nullptr;
    RegGetValueW_t     RegGetValueW = nullptr; // optional

    // Tokens
    OpenProcessToken_t      OpenProcessToken = nullptr;
    GetTokenInformation_t   GetTokenInformation = nullptr;
    LookupPrivilegeValueW_t LookupPrivilegeValueW = nullptr;
    AdjustTokenPrivileges_t AdjustTokenPrivileges = nullptr;

    // Services
    OpenSCManagerW_t     OpenSCManagerW = nullptr;
    CreateServiceW_t     CreateServiceW = nullptr;
    OpenServiceW_t       OpenServiceW = nullptr;
    StartServiceW_t      StartServiceW = nullptr;
    ControlService_t     ControlService = nullptr;
    DeleteService_t      DeleteService = nullptr;
    CloseServiceHandle_t CloseServiceHandle = nullptr;

    // CryptoAPI
    CryptAcquireContextW_t CryptAcquireContextW = nullptr;
    CryptReleaseContext_t  CryptReleaseContext = nullptr;
    CryptGenRandom_t       CryptGenRandom = nullptr;
};

struct NtDll {
    NtDll() : mod(L"ntdll.dll") {
        RtlGetVersion = mod.get_xor<RtlGetVersion_t>(ENC_XOR(RtlGetVersion));
        NtDelayExecution = mod.get_xor<NtDelayExecution_t>(ENC_XOR(NtDelayExecution));
        NtQuerySystemInformation = mod.try_get_xor<NtQuerySystemInformation_t>(ENC_XOR(NtQuerySystemInformation)); // optional
        RtlNtStatusToDosError = mod.try_get_xor<RtlNtStatusToDosError_t>(ENC_XOR(RtlNtStatusToDosError));      // optional
        RtlInitUnicodeString = mod.get_xor<RtlInitUnicodeString_t>(ENC_XOR(RtlInitUnicodeString));
        NtClose = mod.get_xor<NtClose_t>(ENC_XOR(NtClose));
    }

    DynModule mod;

    RtlGetVersion_t              RtlGetVersion = nullptr;
    NtDelayExecution_t           NtDelayExecution = nullptr;
    NtQuerySystemInformation_t   NtQuerySystemInformation = nullptr; // may be null
    RtlNtStatusToDosError_t      RtlNtStatusToDosError = nullptr;    // may be null
    RtlInitUnicodeString_t       RtlInitUnicodeString = nullptr;
    NtClose_t                    NtClose = nullptr;
};

// ============================================================================
// End of file
// ============================================================================
