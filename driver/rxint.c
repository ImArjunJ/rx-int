
#include "rxint.h"
#include "import.h"
#include "xxhash.h"

#define DUMP_PATH L"\\??\\C:\\dumps\\dump_%llu.bin"
#define DUMP_TAG 'rxdm'
#define MAX_GMOD_PROCS 8
#define PROCESS_VM_READ (0x0010)
#define PROCESS_QUERY_INFORMATION (0x0400)
typedef struct _GmodCandidate
{
    HANDLE Pid;
    LARGE_INTEGER CreateTime;
    BOOLEAN Alive;
} GmodCandidate;

GmodCandidate g_GmodList[MAX_GMOD_PROCS] = {0};
ULONG g_GmodCount = 0;
HANDLE g_SelectedGmodPid = NULL;

volatile BOOLEAN g_StopVadThread = FALSE;
HANDLE g_VadThreadHandle = NULL;

VOID DumpPages(HANDLE pid, PVOID base, SIZE_T regionSize);
#define MAX_MODULES 128
#define SUSPICION_THRESHOLD 9

#define MAX_HASHES 1024
ULONGLONG g_HashCache[MAX_HASHES] = {0};
ULONG g_HashCount = 0;
FAST_MUTEX g_HashLock;

typedef struct _MODULE_RANGE
{
    PVOID BaseAddress;
    SIZE_T Size;
} MODULE_RANGE;

MODULE_RANGE g_KnownModules[MAX_MODULES];
ULONG g_ModuleCount = 0;
RTL_BITMAP g_Crc32Cache;

BOOLEAN IsAddressInModuleList(PVOID addr)
{
    for (ULONG i = 0; i < g_ModuleCount; ++i)
    {
        PVOID base = g_KnownModules[i].BaseAddress;
        SIZE_T size = g_KnownModules[i].Size;
        if ((ULONG_PTR) addr >= (ULONG_PTR) base && (ULONG_PTR) addr < (ULONG_PTR) base + size)
            return TRUE;
    }
    return FALSE;
}

VOID ExtractKnownModulesFromPeb(PEPROCESS proc)
{
    PPEB peb = PsGetProcessPeb(proc);
    if (!peb)
        return;

    __try
    {
        PPEB_LDR_DATA ldr = peb->Ldr;
        if (!ldr)
            return;

        PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
        PLIST_ENTRY curr = head->Flink;

        while (curr != head && g_ModuleCount < MAX_MODULES)
        {
            PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            g_KnownModules[g_ModuleCount].BaseAddress = entry->DllBase;
            g_KnownModules[g_ModuleCount].Size = entry->SizeOfImage;
            g_ModuleCount++;
            curr = curr->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

BOOLEAN HasPEHeader(PUCHAR buffer, SIZE_T size)
{
    if (size < sizeof(IMAGE_DOS_HEADER))
        return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER) buffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew > size - sizeof(IMAGE_NT_HEADERS))
        return FALSE;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS) (buffer + dos->e_lfanew);
    return nt->Signature == IMAGE_NT_SIGNATURE;
}

BOOLEAN IsDuplicateHash(ULONGLONG hash)
{
    BOOLEAN found = FALSE;
    ExAcquireFastMutex(&g_HashLock);

    for (ULONG i = 0; i < g_HashCount; ++i)
    {
        if (g_HashCache[i] == hash)
        {
            found = TRUE;
            break;
        }
    }

    if (!found && g_HashCount < MAX_HASHES)
    {
        g_HashCache[g_HashCount++] = hash;
    }

    ExReleaseFastMutex(&g_HashLock);
    return found;
}

VOID VadScannerThread(PVOID Context)
{
    HANDLE pid = (HANDLE) Context;
    PEPROCESS proc;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &proc)))
        PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

    if (!NT_SUCCESS(PsAcquireProcessExitSynchronization(proc)))
    {
        ObDereferenceObject(proc);
        PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
    }

    ExtractKnownModulesFromPeb(proc);

    KAPC_STATE state;

    while (!g_StopVadThread)
    {
        KeStackAttachProcess(proc, &state);

        PUCHAR addr = 0;
        SIZE_T ret = 0;
        MEMORY_BASIC_INFORMATION mbi;
        HANDLE ProcessHandle = ZwCurrentProcess();

        while (NT_SUCCESS(ZwQueryVirtualMemory(ProcessHandle, addr, 0, &mbi, sizeof(mbi), &ret)))
        {
            ULONG score = 0;

            if (mbi.Type == MEM_PRIVATE)
                score += 2;

            if ((mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY))
                score += 3;

            if (!IsAddressInModuleList(mbi.BaseAddress))
                score += 2;

            SIZE_T regionSize = mbi.RegionSize;
            if (regionSize <= 0x1000)
                score += 1;

            PUCHAR buffer = ExAllocatePoolWithTag(NonPagedPoolNx, regionSize, 'rxmm');
            if (buffer)
            {
                SIZE_T bytesRead = 0;
                if (NT_SUCCESS(MmCopyVirtualMemory(proc, mbi.BaseAddress, PsGetCurrentProcess(), buffer, regionSize, KernelMode, &bytesRead)))
                {
                    if (!HasPEHeader(buffer, bytesRead))
                        score += 1;

                    if (score >= SUSPICION_THRESHOLD)
                    {
                        ULONGLONG hash = XXH64(buffer, (size_t) bytesRead, 0x1337);

                        if (!IsDuplicateHash(hash))
                        {
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] Dumping suspicious region size=%lu @ %p - %lu\n",mbi.RegionSize, mbi.BaseAddress, score);
                            DumpPages(pid, mbi.BaseAddress, mbi.RegionSize);
                        }
                    }
                }
                ExFreePool(buffer);
            }

            addr = (PUCHAR) mbi.BaseAddress + mbi.RegionSize;
        }

        KeUnstackDetachProcess(&state);

        LARGE_INTEGER delay;
        delay.QuadPart = -3 * 1000 * 1000 * 10LL;
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    PsReleaseProcessExitSynchronization(proc);
    ObDereferenceObject(proc);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID StartVadScannerThread()
{
    HANDLE thread;
    NTSTATUS status = PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, VadScannerThread, g_SelectedGmodPid);
    if (NT_SUCCESS(status))
        g_VadThreadHandle = thread;
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    g_StopVadThread = TRUE;

    if (g_VadThreadHandle)
    {
        if (KeGetCurrentIrql() == PASSIVE_LEVEL)
        {
            PVOID threadObj = NULL;
            NTSTATUS status = ObReferenceObjectByHandle(g_VadThreadHandle, SYNCHRONIZE, *PsThreadType, KernelMode, &threadObj, NULL);

            if (NT_SUCCESS(status))
            {
                KeWaitForSingleObject(threadObj, Executive, KernelMode, FALSE, NULL);
                ObDereferenceObject(threadObj);
            }
            else
            {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] Failed to reference thread handle: 0x%X\n", status);
            }
        }

        ZwClose(g_VadThreadHandle);
        g_VadThreadHandle = NULL;
    }

    PsSetCreateProcessNotifyRoutineEx(OnProcessNotifyEx, TRUE);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] Driver unloaded\n");
}


VOID SelectStableGmodThread(PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);

    LARGE_INTEGER delay;
    delay.QuadPart = -3 * 1000 * 1000 * 10LL;
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    LARGE_INTEGER latest = {0};
    HANDLE bestPid = NULL;

    for (ULONG i = 0; i < g_GmodCount; ++i)
    {
        PEPROCESS proc;
        if (NT_SUCCESS(PsLookupProcessByProcessId(g_GmodList[i].Pid, &proc)))
        {
            ObDereferenceObject(proc);
            if (g_GmodList[i].CreateTime.QuadPart > latest.QuadPart)
            {
                latest = g_GmodList[i].CreateTime;
                bestPid = g_GmodList[i].Pid;
            }
        }
    }

    if (bestPid)
    {
        g_SelectedGmodPid = bestPid;
        StartVadScannerThread();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] Selected stable gmod.exe: PID %lu\n", (ULONG) (ULONG_PTR) bestPid);
    }
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] Failed to select any stable gmod.exe\n");
    }
}

VOID OnProcessNotifyEx(PEPROCESS Process, HANDLE Pid, PPS_CREATE_NOTIFY_INFO Info)
{
    UNREFERENCED_PARAMETER(Process);
    if (!Info || !Info->ImageFileName)
        return;
    if (!wcsstr(Info->ImageFileName->Buffer, L"gmod.exe"))
        return;
    if (g_GmodCount >= MAX_GMOD_PROCS)
        return;

    LARGE_INTEGER now;
    KeQuerySystemTime(&now);

    g_GmodList[g_GmodCount].Pid = Pid;
    g_GmodList[g_GmodCount].CreateTime = now;
    g_GmodList[g_GmodCount].Alive = TRUE;
    g_GmodCount++;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] Detected gmod.exe candidate: PID %lu\n", (ULONG) (ULONG_PTR) Pid);

    static BOOLEAN SelectionQueued = FALSE;
    if (!SelectionQueued)
    {
        SelectionQueued = TRUE;
        HANDLE thread;
        PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE) SelectStableGmodThread, NULL);
        if (thread)
            ZwClose(thread);
    }
}

VOID DumpPages(HANDLE pid, PVOID base, SIZE_T regionSize)
{
    PEPROCESS proc;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &proc)))
        return;

    KAPC_STATE state;
    KeStackAttachProcess(proc, &state);

    // Round size to nearest page size
    regionSize = (regionSize + 0xFFF) & ~0xFFF;

    PUCHAR userBase = (PUCHAR) base;
    PUCHAR kernelBuf = ExAllocatePoolWithTag(NonPagedPoolNx, regionSize, DUMP_TAG);

    if (!kernelBuf)
    {
        KeUnstackDetachProcess(&state);
        ObDereferenceObject(proc);
        return;
    }

    __try
    {
        ProbeForRead(userBase, regionSize, 1);
        RtlCopyMemory(kernelBuf, userBase, regionSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] RtlCopyMemory failed at 0x%p (regionSize: 0x%Ix)\n", base, regionSize);
        ExFreePoolWithTag(kernelBuf, DUMP_TAG);
        KeUnstackDetachProcess(&state);
        ObDereferenceObject(proc);
        return;
    }

    KeUnstackDetachProcess(&state);

    WCHAR filename[512];
    LARGE_INTEGER timestamp;
    KeQuerySystemTime(&timestamp);
    RtlStringCbPrintfW(filename, sizeof(filename), DUMP_PATH, timestamp.QuadPart);

    UNICODE_STRING path;
    RtlInitUnicodeString(&path, filename);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    HANDLE file;

    NTSTATUS status =
        ZwCreateFile(&file, GENERIC_WRITE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (NT_SUCCESS(status))
    {
        ZwWriteFile(file, NULL, NULL, NULL, &iosb, kernelBuf, (ULONG) regionSize, NULL, NULL);
        ZwClose(file);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] Dumped %llu bytes to %ws\n", (ULONGLONG) regionSize, filename);
    }
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] ZwCreateFile failed (Status: 0x%08X)\n", status);
    }

    ExFreePoolWithTag(kernelBuf, DUMP_TAG);
    ObDereferenceObject(proc);
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    ExInitializeFastMutex(&g_HashLock);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] DriverEntry\n");
    DriverObject->DriverUnload = DriverUnload;
    PsSetCreateProcessNotifyRoutineEx(OnProcessNotifyEx, FALSE);
    return STATUS_SUCCESS;
}
