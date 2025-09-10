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

// --- Error helpers -----------------------------------------------------------

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

// --- RAII module loader with cached GetProcAddress ---------------------------

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

    // Optional: resolves a procedure if present; returns nullptr if not found.
    template<typename Fn>
    Fn try_get(const char* proc_name) const noexcept {
        // Check cache first
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

// --- Strongly-typed function pointer aliases --------------------------------
// KERNEL32 --------------------------------------------------------------------

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

// USER32 ----------------------------------------------------------------------

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

// ADVAPI32 --------------------------------------------------------------------
// Registry
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
using RegGetValueW_t = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD); // optional pre-Vista

// Tokens / privileges
using OpenProcessToken_t = BOOL(WINAPI*)(HANDLE, DWORD, PHANDLE);
using GetTokenInformation_t = BOOL(WINAPI*)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
using LookupPrivilegeValueW_t = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, PLUID);
using AdjustTokenPrivileges_t = BOOL(WINAPI*)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);

// Services (SCM)
using OpenSCManagerW_t = SC_HANDLE(WINAPI*)(LPCWSTR, LPCWSTR, DWORD);
using CreateServiceW_t = SC_HANDLE(WINAPI*)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD,
    LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
using OpenServiceW_t = SC_HANDLE(WINAPI*)(SC_HANDLE, LPCWSTR, DWORD);
using StartServiceW_t = BOOL(WINAPI*)(SC_HANDLE, DWORD, LPCWSTR*);
using ControlService_t = BOOL(WINAPI*)(SC_HANDLE, DWORD, LPSERVICE_STATUS);
using DeleteService_t = BOOL(WINAPI*)(SC_HANDLE);
using CloseServiceHandle_t = BOOL(WINAPI*)(SC_HANDLE);

// CryptoAPI (classic)
using CryptAcquireContextW_t = BOOL(WINAPI*)(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
using CryptReleaseContext_t = BOOL(WINAPI*)(HCRYPTPROV, DWORD);
using CryptGenRandom_t = BOOL(WINAPI*)(HCRYPTPROV, DWORD, BYTE*);

// NTDLL -----------------------------------------------------------------------
// Only a small, stable subset. These are *not* obfuscated and are used transparently.
using RtlGetVersion_t = NTSTATUS(NTAPI*)(PRTL_OSVERSIONINFOW);
using NtDelayExecution_t = NTSTATUS(NTAPI*)(BOOLEAN, PLARGE_INTEGER);
using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
using RtlNtStatusToDosError_t = ULONG(NTAPI*)(NTSTATUS);
using RtlInitUnicodeString_t = VOID(NTAPI*)(PUNICODE_STRING, PCWSTR);
using NtClose_t = NTSTATUS(NTAPI*)(HANDLE);

// --- Per-module wrappers -----------------------------------------------------

struct Kernel32 {
    Kernel32() : mod(L"kernel32.dll") {
        // File I/O
        CreateFileW = mod.get<CreateFileW_t>("CreateFileW");
        ReadFile = mod.get<ReadFile_t>("ReadFile");
        WriteFile = mod.get<WriteFile_t>("WriteFile");
        DeleteFileW = mod.get<DeleteFileW_t>("DeleteFileW");
        MoveFileExW = mod.get<MoveFileExW_t>("MoveFileExW");
        GetFileAttributesExW = mod.get<GetFileAttributesExW_t>("GetFileAttributesExW");
        SetFileAttributesW = mod.get<SetFileAttributesW_t>("SetFileAttributesW");
        CreateDirectoryW = mod.get<CreateDirectoryW_t>("CreateDirectoryW");
        RemoveDirectoryW = mod.get<RemoveDirectoryW_t>("RemoveDirectoryW");

        // Processes / sync
        CreateProcessW = mod.get<CreateProcessW_t>("CreateProcessW");
        WaitForSingleObject = mod.get<WaitForSingleObject_t>("WaitForSingleObject");
        GetExitCodeProcess = mod.get<GetExitCodeProcess_t>("GetExitCodeProcess");
        TerminateProcess = mod.get<TerminateProcess_t>("TerminateProcess");
        CreateEventW = mod.get<CreateEventW_t>("CreateEventW");
        SetEvent = mod.get<SetEvent_t>("SetEvent");
        ResetEvent = mod.get<ResetEvent_t>("ResetEvent");

        // Memory / mapping
        CreateFileMappingW = mod.get<CreateFileMappingW_t>("CreateFileMappingW");
        MapViewOfFile = mod.get<MapViewOfFile_t>("MapViewOfFile");
        UnmapViewOfFile = mod.get<UnmapViewOfFile_t>("UnmapViewOfFile");
        VirtualAlloc = mod.get<VirtualAlloc_t>("VirtualAlloc");
        VirtualFree = mod.get<VirtualFree_t>("VirtualFree");
        VirtualProtect = mod.get<VirtualProtect_t>("VirtualProtect");

        // System info / misc
        GetModuleFileNameW = mod.get<GetModuleFileNameW_t>("GetModuleFileNameW");
        GetModuleHandleW = mod.get<GetModuleHandleW_t>("GetModuleHandleW");
        GetSystemTimeAsFileTime = mod.get<GetSystemTimeAsFileTime_t>("GetSystemTimeAsFileTime");
        QueryPerformanceCounter = mod.get<QueryPerformanceCounter_t>("QueryPerformanceCounter");
        QueryPerformanceFrequency = mod.get<QueryPerformanceFrequency_t>("QueryPerformanceFrequency");
        Sleep = mod.get<Sleep_t>("Sleep");
        GetTickCount64 = mod.get<GetTickCount64_t>("GetTickCount64");
        GetEnvironmentVariableW = mod.get<GetEnvironmentVariableW_t>("GetEnvironmentVariableW");
        SetEnvironmentVariableW = mod.get<SetEnvironmentVariableW_t>("SetEnvironmentVariableW");
        GetTempPathW = mod.get<GetTempPathW_t>("GetTempPathW");
        GetTempFileNameW = mod.get<GetTempFileNameW_t>("GetTempFileNameW");

        // Always last: Close/GetLastError
        CloseHandle = mod.get<CloseHandle_t>("CloseHandle");
        GetLastError = mod.get<GetLastError_t>("GetLastError");
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
        MessageBoxW = mod.get<MessageBoxW_t>("MessageBoxW");
        GetSystemMetrics = mod.get<GetSystemMetrics_t>("GetSystemMetrics");
        FindWindowW = mod.get<FindWindowW_t>("FindWindowW");
        GetForegroundWindow = mod.get<GetForegroundWindow_t>("GetForegroundWindow");
        SetForegroundWindow = mod.get<SetForegroundWindow_t>("SetForegroundWindow");
        ShowWindow = mod.get<ShowWindow_t>("ShowWindow");
        GetWindowTextW = mod.get<GetWindowTextW_t>("GetWindowTextW");
        SetWindowTextW = mod.get<SetWindowTextW_t>("SetWindowTextW");
        GetWindowRect = mod.get<GetWindowRect_t>("GetWindowRect");
        GetClientRect = mod.get<GetClientRect_t>("GetClientRect");
        RegisterClassExW = mod.get<RegisterClassExW_t>("RegisterClassExW");
        CreateWindowExW = mod.get<CreateWindowExW_t>("CreateWindowExW");
        DestroyWindow = mod.get<DestroyWindow_t>("DestroyWindow");
        DefWindowProcW = mod.get<DefWindowProcW_t>("DefWindowProcW");
        GetMessageW = mod.get<GetMessageW_t>("GetMessageW");
        TranslateMessage = mod.get<TranslateMessage_t>("TranslateMessage");
        DispatchMessageW = mod.get<DispatchMessageW_t>("DispatchMessageW");
        PostQuitMessage = mod.get<PostQuitMessage_t>("PostQuitMessage");
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
        RegOpenKeyExW = mod.get<RegOpenKeyExW_t>("RegOpenKeyExW");
        RegCreateKeyExW = mod.get<RegCreateKeyExW_t>("RegCreateKeyExW");
        RegSetValueExW = mod.get<RegSetValueExW_t>("RegSetValueExW");
        RegQueryValueExW = mod.get<RegQueryValueExW_t>("RegQueryValueExW");
        RegEnumKeyExW = mod.get<RegEnumKeyExW_t>("RegEnumKeyExW");
        RegEnumValueW = mod.get<RegEnumValueW_t>("RegEnumValueW");
        RegDeleteKeyW = mod.get<RegDeleteKeyW_t>("RegDeleteKeyW");
        RegDeleteValueW = mod.get<RegDeleteValueW_t>("RegDeleteValueW");
        RegCloseKey = mod.get<RegCloseKey_t>("RegCloseKey");
        RegGetValueW = mod.try_get<RegGetValueW_t>("RegGetValueW"); // may be null on very old systems

        // Tokens / privileges
        OpenProcessToken = mod.get<OpenProcessToken_t>("OpenProcessToken");
        GetTokenInformation = mod.get<GetTokenInformation_t>("GetTokenInformation");
        LookupPrivilegeValueW = mod.get<LookupPrivilegeValueW_t>("LookupPrivilegeValueW");
        AdjustTokenPrivileges = mod.get<AdjustTokenPrivileges_t>("AdjustTokenPrivileges");

        // Services (SCM)
        OpenSCManagerW = mod.get<OpenSCManagerW_t>("OpenSCManagerW");
        CreateServiceW = mod.get<CreateServiceW_t>("CreateServiceW");
        OpenServiceW = mod.get<OpenServiceW_t>("OpenServiceW");
        StartServiceW = mod.get<StartServiceW_t>("StartServiceW");
        ControlService = mod.get<ControlService_t>("ControlService");
        DeleteService = mod.get<DeleteService_t>("DeleteService");
        CloseServiceHandle = mod.get<CloseServiceHandle_t>("CloseServiceHandle");

        // CryptoAPI
        CryptAcquireContextW = mod.get<CryptAcquireContextW_t>("CryptAcquireContextW");
        CryptReleaseContext = mod.get<CryptReleaseContext_t>("CryptReleaseContext");
        CryptGenRandom = mod.get<CryptGenRandom_t>("CryptGenRandom");
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
        RtlGetVersion = mod.get<RtlGetVersion_t>("RtlGetVersion");
        NtDelayExecution = mod.get<NtDelayExecution_t>("NtDelayExecution");
        NtQuerySystemInformation = mod.try_get<NtQuerySystemInformation_t>("NtQuerySystemInformation"); // optional
        RtlNtStatusToDosError = mod.try_get<RtlNtStatusToDosError_t>("RtlNtStatusToDosError");      // optional
        RtlInitUnicodeString = mod.get<RtlInitUnicodeString_t>("RtlInitUnicodeString");
        NtClose = mod.get<NtClose_t>("NtClose");
    }

    DynModule mod;

    RtlGetVersion_t              RtlGetVersion = nullptr;
    NtDelayExecution_t           NtDelayExecution = nullptr;
    NtQuerySystemInformation_t   NtQuerySystemInformation = nullptr; // may be null
    RtlNtStatusToDosError_t      RtlNtStatusToDosError = nullptr;    // may be null
    RtlInitUnicodeString_t       RtlInitUnicodeString = nullptr;
    NtClose_t                    NtClose = nullptr;
};
