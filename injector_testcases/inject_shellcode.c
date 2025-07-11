// clang-format off
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
// clang-format on

DWORD FindTargetPID(const wchar_t* targetName)
{
    PROCESSENTRY32W entry = {.dwSize = sizeof(entry)};
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snap == INVALID_HANDLE_VALUE)
    {
        printf("CreateToolhelp32Snapshot failed.\n");
        return 0;
    }

    while (Process32NextW(snap, &entry))
    {
        if (_wcsicmp(entry.szExeFile, targetName) == 0)
        {
            CloseHandle(snap);
            return entry.th32ProcessID;
        }
    }
    CloseHandle(snap);
    return 0;
}

int main()
{
    DWORD pid = FindTargetPID(L"gmod.exe");
    if (!pid)
    {
        printf("gmod.exe not found\n");
        return 1;
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc)
    {
        printf("Failed to open target process\n");
        return 1;
    }

    unsigned char shellcode[] = {0x48, 0x83, 0xEC, 0x28, 0x48, 0x31, 0xC0, 0x48, 0x83, 0xC4, 0x28, 0xC3};

    LPVOID remote = VirtualAllocEx(hProc, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote)
    {
        printf("Failed to allocate remote memory\n");
        return 1;
    }

    if (!WriteProcessMemory(hProc, remote, shellcode, sizeof(shellcode), NULL))
    {
        printf("Failed to write shellcode\n");
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) remote, NULL, 0, NULL);
    if (!hThread)
    {
        printf("CreateRemoteThread failed\n");
    }
    else
    {
        printf("Shellcode injected and running. @ %p\n", remote);
        CloseHandle(hThread);
    }

    CloseHandle(hProc);
    return 0;
}
