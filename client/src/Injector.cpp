#include "Injector.hpp"

#include <TlHelp32.h>
#include <Windows.h>

#include <iostream>
#include <string>

// A minimal, benign x64 shellcode (XOR RAX,RAX; RET)
const unsigned char BENIGN_SHELLCODE[] = {0x48, 0x31, 0xC0, 0xC3};

DWORD FindFirstThread(DWORD pid)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return 0;
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hSnap, &te32))
    {
        do {
            if (te32.th32OwnerProcessID == pid)
            {
                CloseHandle(hSnap);
                return te32.th32ThreadID;
            }
        } while (Thread32Next(hSnap, &te32));
    }
    CloseHandle(hSnap);
    return 0;
}

bool Injector::Inject(unsigned long pid, InjectionMethod method, std::string& outMessage)
{
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc || hProc == INVALID_HANDLE_VALUE)
    {
        outMessage = "Error: Failed to open target process. PID: " + std::to_string(pid) + ", Win32 Error: " + std::to_string(GetLastError());
        return false;
    }

    LPVOID remoteMem = nullptr;
    bool success = false;

    switch (method)
    {
    case InjectionMethod::ClassicRwx:
    {
        outMessage = "Attempting Classic RWX injection...";
        remoteMem = VirtualAllocEx(hProc, NULL, sizeof(BENIGN_SHELLCODE), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteMem)
        {
            outMessage = "Classic RWX: VirtualAllocEx failed. Error: " + std::to_string(GetLastError());
            break;
        }
        if (!WriteProcessMemory(hProc, remoteMem, BENIGN_SHELLCODE, sizeof(BENIGN_SHELLCODE), NULL))
        {
            outMessage = "Classic RWX: WriteProcessMemory failed. Error: " + std::to_string(GetLastError());
            break;
        }
        HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) remoteMem, NULL, 0, NULL);
        if (!hThread)
        {
            outMessage = "Classic RWX: CreateRemoteThread failed. Error: " + std::to_string(GetLastError());
            break;
        }
        WaitForSingleObject(hThread, 2000);
        CloseHandle(hThread);
        outMessage = "Classic RWX injection successful. Check kernel logs.";
        success = true;
        break;
    }
    case InjectionMethod::StagedRwRx:
    {
        outMessage = "Attempting Staged RW -> RX injection...";
        remoteMem = VirtualAllocEx(hProc, NULL, sizeof(BENIGN_SHELLCODE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteMem)
        {
            outMessage = "Staged RW->RX: VirtualAllocEx failed. Error: " + std::to_string(GetLastError());
            break;
        }
        if (!WriteProcessMemory(hProc, remoteMem, BENIGN_SHELLCODE, sizeof(BENIGN_SHELLCODE), NULL))
        {
            outMessage = "Staged RW->RX: WriteProcessMemory failed. Error: " + std::to_string(GetLastError());
            break;
        }
        outMessage = "Payload written as RW. Waiting 5s for VAD baseline, then changing protection...";
        std::cout << "\n[INJECTOR] " << outMessage << std::flush;
        Sleep(5000);
        DWORD oldProtect;
        if (!VirtualProtectEx(hProc, remoteMem, sizeof(BENIGN_SHELLCODE), PAGE_EXECUTE_READ, &oldProtect))
        {
            outMessage = "Staged RW->RX: VirtualProtectEx failed. Error: " + std::to_string(GetLastError());
            break;
        }
        HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) remoteMem, NULL, 0, NULL);
        if (!hThread)
        {
            outMessage = "Staged RW->RX: CreateRemoteThread failed. Error: " + std::to_string(GetLastError());
            break;
        }
        WaitForSingleObject(hThread, 2000);
        CloseHandle(hThread);
        outMessage = "Staged RW->RX injection successful. Check kernel logs.";
        success = true;
        break;
    }
    case InjectionMethod::QueueUserApc:
    {
        outMessage = "Attempting Threadless injection via QueueUserAPC...";
        DWORD threadId = FindFirstThread(pid);
        if (!threadId)
        {
            outMessage = "QueueUserAPC: Could not find a thread in the target process.";
            break;
        }
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
        if (!hThread)
        {
            outMessage = "QueueUserAPC: Failed to open target thread. Error: " + std::to_string(GetLastError());
            break;
        }
        remoteMem = VirtualAllocEx(hProc, NULL, sizeof(BENIGN_SHELLCODE), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteMem)
        {
            outMessage = "QueueUserAPC: VirtualAllocEx failed.";
            CloseHandle(hThread);
            break;
        }
        if (!WriteProcessMemory(hProc, remoteMem, BENIGN_SHELLCODE, sizeof(BENIGN_SHELLCODE), NULL))
        {
            outMessage = "QueueUserAPC: Write failed.";
            CloseHandle(hThread);
            break;
        }
        if (QueueUserAPC((PAPCFUNC) remoteMem, hThread, 0) == 0)
        {
            outMessage = "QueueUserAPC failed. Error: " + std::to_string(GetLastError());
            CloseHandle(hThread);
            break;
        }
        CloseHandle(hThread);
        outMessage = "QueueUserAPC successful. Payload is queued.";
        success = true;
        remoteMem = nullptr; // Don't free the memory, the APC needs it
        break;
    }
    case InjectionMethod::ModuleStomp:
    {
        outMessage = "Module Stomping is not yet implemented.";
        break;
    }
    }

    if (remoteMem)
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return success;
}