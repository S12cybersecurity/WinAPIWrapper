#include "winapi_wrapper.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <cstring>

static void PrintHex(const BYTE* data, size_t len) {
    std::ios_base::fmtflags f(std::cout.flags());
    for (size_t i = 0; i < len; ++i) {
        if (i && (i % 16 == 0)) std::cout << "\n";
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<unsigned>(data[i]) << " ";
    }
    std::cout << "\n";
    std::cout.flags(f);
}

int wmain() {
    try {
        Kernel32 k32;
        User32 u32;
        Advapi32 adv;
        NtDll ntdll;

        // --- USER32: simple check
        u32.MessageBoxW(nullptr,
            L"WinAPI wrapper: kernel32/user32/advapi32/ntdll loaded successfully.",
            L"WinAPI Wrapper", MB_OK | MB_ICONINFORMATION);

        // --- KERNEL32: create & write a small file
        HANDLE h = k32.CreateFileW(
            L".\\hello.txt",
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (h == INVALID_HANDLE_VALUE) {
            DWORD ec = k32.GetLastError();
            std::cerr << "CreateFileW failed: " << ec << " (" << Win32ErrorMessage(ec) << ")\n";
            return 1;
        }

        const char* msg = "Hello from an expanded WinAPI wrapper.\r\n";
        DWORD written = 0;
        if (!k32.WriteFile(h, msg, static_cast<DWORD>(std::strlen(msg)), &written, nullptr)) {
            DWORD ec = k32.GetLastError();
            std::cerr << "WriteFile failed: " << ec << " (" << Win32ErrorMessage(ec) << ")\n";
            k32.CloseHandle(h);
            return 1;
        }
        k32.CloseHandle(h);

        // --- ADVAPI32: create a test registry key and set a DWORD value
        HKEY hKey = nullptr;
        DWORD disp = 0;
        LSTATUS ls = adv.RegCreateKeyExW(HKEY_CURRENT_USER,
            L"Software\\WinApiWrapperDemo",
            0, nullptr, 0,
            KEY_ALL_ACCESS, nullptr, &hKey, &disp);
        if (ls == ERROR_SUCCESS) {
            DWORD enabled = 1;
            ls = adv.RegSetValueExW(hKey, L"Enabled", 0, REG_DWORD,
                reinterpret_cast<const BYTE*>(&enabled),
                sizeof(enabled));
            adv.RegCloseKey(hKey);
            if (ls != ERROR_SUCCESS) {
                std::cerr << "RegSetValueExW failed: " << ls << "\n";
            }
        }
        else {
            std::cerr << "RegCreateKeyExW failed: " << ls << "\n";
        }

        // --- ADVAPI32 (CryptoAPI): get 16 bytes of random data
        HCRYPTPROV hProv = 0;
        if (adv.CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            BYTE rnd[16] = {};
            if (adv.CryptGenRandom(hProv, sizeof(rnd), rnd)) {
                std::cout << "Random bytes (CryptGenRandom):\n";
                PrintHex(rnd, sizeof(rnd));
            }
            else {
                DWORD ec = k32.GetLastError();
                std::cerr << "CryptGenRandom failed: " << ec << " (" << Win32ErrorMessage(ec) << ")\n";
            }
            adv.CryptReleaseContext(hProv, 0);
        }
        else {
            DWORD ec = k32.GetLastError();
            std::cerr << "CryptAcquireContextW failed: " << ec << " (" << Win32ErrorMessage(ec) << ")\n";
        }

        // --- NTDLL: query OS version via RtlGetVersion
        RTL_OSVERSIONINFOW ver{};
        ver.dwOSVersionInfoSize = sizeof(ver);
        NTSTATUS st = ntdll.RtlGetVersion(&ver);
        if (st >= 0) { // NT_SUCCESS
            std::wcout << L"RtlGetVersion -> " << ver.dwMajorVersion << L"."
                << ver.dwMinorVersion << L" (build " << ver.dwBuildNumber << L")\n";
        }
        else {
            DWORD winerr = ntdll.RtlNtStatusToDosError ? ntdll.RtlNtStatusToDosError(st) : ERROR_MR_MID_NOT_FOUND;
            std::cerr << "RtlGetVersion failed, NTSTATUS=" << std::hex << st
                << " WinErr=" << std::dec << winerr << " (" << Win32ErrorMessage(winerr) << ")\n";
        }

        // Optional: micro-sleep using NtDelayExecution (100ms)
        LARGE_INTEGER interval{};
        // Negative = relative time in 100-ns intervals
        interval.QuadPart = -1LL * 1000000LL; // 100 ms
        st = ntdll.NtDelayExecution(FALSE, &interval);
        if (st < 0) {
            DWORD winerr = ntdll.RtlNtStatusToDosError ? ntdll.RtlNtStatusToDosError(st) : ERROR_MR_MID_NOT_FOUND;
            std::cerr << "NtDelayExecution failed, NTSTATUS=" << std::hex << st
                << " WinErr=" << std::dec << winerr << " (" << Win32ErrorMessage(winerr) << ")\n";
        }

        // Final UI confirmation
        u32.MessageBoxW(nullptr, L"All demo calls finished OK. Check hello.txt and registry value.",
            L"WinAPI Wrapper Demo", MB_OK | MB_ICONINFORMATION);

        return 0;

    }
    catch (const Win32Exception& ex) {
        std::cerr << "Win32Exception: " << ex.what() << "\n";
        return 2;
    }
    catch (const std::exception& ex) {
        std::cerr << "std::exception: " << ex.what() << "\n";
        return 3;
    }
}