#include <windows.h>

DWORD WINAPI PayloadThread(LPVOID lpParameter)
{
    UNREFERENCED_PARAMETER(lpParameter);
    MessageBoxW(NULL, L"This DLL was successfully injected and executed!", L"RX-INT Test Payload", MB_OK | MB_ICONINFORMATION);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(lpReserved);

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        HANDLE hThread = CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
        if (hThread)
        {
            CloseHandle(hThread);
        }
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}