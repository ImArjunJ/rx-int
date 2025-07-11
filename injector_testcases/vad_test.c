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
    printf("Searching for gmod.exe...\n");
    DWORD pid = FindTargetPID(L"gmod.exe");
    if (!pid)
    {
        printf("Error: gmod.exe not found. Please ensure it is running.\n");
        system("pause");
        return 1;
    }
    printf("Found gmod.exe with PID: %lu\n", pid);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc)
    {
        printf("Error: Failed to open target process (is this program running as admin?)\n");
        system("pause");
        return 1;
    }

    unsigned char dummy_payload[] = {0x90, 0x90, 0x90, 0x90, 0xC3}; // NOP, NOP, NOP, NOP, RET
    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, sizeof(dummy_payload), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem)
    {
        printf("Error: Failed to allocate remote memory.\n");
        CloseHandle(hProc);
        system("pause");
        return 1;
    }
    printf("Allocated RW memory @ %p\n", remoteMem);

    if (!WriteProcessMemory(hProc, remoteMem, dummy_payload, sizeof(dummy_payload), NULL))
    {
        printf("Error: Failed to write to remote memory.\n");
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        system("pause");
        return 1;
    }
    printf("Wrote data to memory.\n\n");

    printf("The memory is now READ/WRITE.\n");
    printf("Press ENTER to change the memory to EXECUTABLE.\n");
    getchar();

    DWORD oldProtect;
    if (!VirtualProtectEx(hProc, remoteMem, sizeof(dummy_payload), PAGE_EXECUTE_READ, &oldProtect))
    {
        printf("Error: VirtualProtectEx failed.\n");
    }
    else
    {
        printf("\nSuccess! Memory protection changed to READ/EXECUTE.\n");
    }

    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProc);

    printf("\nTest complete. Press ENTER to exit.\n");
    getchar();
    return 0;
}