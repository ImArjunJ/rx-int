#include "Detector.hpp"

#include "Reconstructor.hpp"
#include "Wrappers.hpp"


namespace rx
{
    Detector::Detector()
        : m_isStopping(false), m_vadThreadHandle(nullptr), m_selectionThreadHandle(nullptr), m_candidateCount(0), m_monitoredPid(nullptr), m_dumpHashCount(0), m_moduleCount(0),
          m_vadBaselineCount(0)
    {
        KeInitializeEvent(&m_stopEvent, NotificationEvent, FALSE);
        KeInitializeSpinLock(&m_candidateLock);
        ExInitializeFastMutex(&m_dumpHashLock);
    }

    NTSTATUS Detector::Start()
    {
        m_isStopping = false;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] rx-int driver loaded\n");
        return STATUS_SUCCESS;
    }

    void Detector::Stop()
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] rx-int driver unloaded\n");
        StopMonitoringProcess();
    }

    void Detector::OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, bool Create)
    {
        if (!Create || ProcessId != m_monitoredPid)
            return;

        HANDLE hThread;
        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        CLIENT_ID clientId = {ProcessId, ThreadId};
        NTSTATUS status = ZwOpenThread(&hThread, THREAD_QUERY_INFORMATION, &objAttr, &clientId);
        if (!NT_SUCCESS(status))
            return;

        PVOID startAddress = nullptr;
        ZwQueryInformationThread(hThread, ThreadInfoClass::ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), NULL);
        ZwClose(hThread);
        if (!startAddress)
            return;

        util::ProcessReference proc(ProcessId);
        if (!proc)
            return;

        util::ProcessAttacher attacher(proc.get());
        MEMORY_BASIC_INFORMATION mbi;
        status = ZwQueryVirtualMemory(ZwCurrentProcess(), startAddress, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
        if (NT_SUCCESS(status) && mbi.Type == MEM_PRIVATE && !IsAddressInModuleList(mbi.BaseAddress))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] thread: suspicious start @ %p. dumping... \n", startAddress);
            DumpPages(ProcessId, mbi.BaseAddress, mbi.RegionSize, m_knownModules, m_moduleCount);
        }
    }

    void Detector::VadScannerThread(PVOID StartContext)
    {
        auto* detector = static_cast<Detector*>(StartContext);
        HANDLE pid = detector->m_monitoredPid;

        util::ProcessReference proc(pid);
        if (!proc)
        {
            PsTerminateSystemThread(STATUS_INVALID_PARAMETER);
            return;
        }

        if (!NT_SUCCESS(PsAcquireProcessExitSynchronization(proc.get())))
        {
            PsTerminateSystemThread(STATUS_PROCESS_IS_TERMINATING);
            return;
        }

        detector->ExtractKnownModules(proc.get());
        detector->TakeVadSnapshot(proc.get(), detector->m_vadBaseline, detector->m_vadBaselineCount);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] vad: baseline complete for PID %p with %zu regions\n", pid, detector->m_vadBaselineCount);

        auto* currentSnapshot = new (PagedPool, util::POOL_TAG) util::kernel_array<MemoryRegionInfo, util::MAX_VAD_REGIONS>;
        if (!currentSnapshot)
        {
            PsReleaseProcessExitSynchronization(proc.get());
            PsTerminateSystemThread(STATUS_INSUFFICIENT_RESOURCES);
            return;
        }

        while (!detector->m_isStopping)
        {
            size_t currentSnapshotCount = 0;
            LARGE_INTEGER delay;
            delay.QuadPart = -30000000LL;
            KeWaitForSingleObject(&detector->m_stopEvent, Executive, KernelMode, FALSE, &delay);
            if (detector->m_isStopping)
                break;

            if (KeWaitForSingleObject(proc.get(), Executive, KernelMode, TRUE, &delay) != STATUS_TIMEOUT)
                break;

            detector->TakeVadSnapshot(proc.get(), *currentSnapshot, currentSnapshotCount);
            for (size_t i = 0; i < currentSnapshotCount; ++i)
            {
                auto& currentRegion = (*currentSnapshot)[i];
                bool foundInBaseline = false;
                for (size_t j = 0; j < detector->m_vadBaselineCount; ++j)
                {
                    auto& baselineRegion = detector->m_vadBaseline[j];
                    if (currentRegion.BaseAddress == baselineRegion.BaseAddress)
                    {
                        foundInBaseline = true;
                        if (IsExecutable(currentRegion.Protect) && !IsExecutable(baselineRegion.Protect))
                        {
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] vad: permission escalation to EXECUTE at %p! dumping...\n", currentRegion.BaseAddress);
                            detector->DumpPages(pid, currentRegion.BaseAddress, currentRegion.RegionSize, detector->m_knownModules, detector->m_moduleCount);
                        }
                        else if (IsExecutable(currentRegion.Protect) && currentRegion.ContentHash != baselineRegion.ContentHash)
                        {
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] vad: self-modifying code detected at %p! dumping...\n", currentRegion.BaseAddress);
                            detector->DumpPages(pid, currentRegion.BaseAddress, currentRegion.RegionSize, detector->m_knownModules, detector->m_moduleCount);
                        }
                        break;
                    }
                }
                if (!foundInBaseline && IsExecutable(currentRegion.Protect))
                {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] vad: new executable private region at %p! dumping...\n", currentRegion.BaseAddress);
                    detector->DumpPages(pid, currentRegion.BaseAddress, currentRegion.RegionSize, detector->m_knownModules, detector->m_moduleCount);
                }
            }
        }
        delete currentSnapshot;
        PsReleaseProcessExitSynchronization(proc.get());
        PsTerminateSystemThread(STATUS_SUCCESS);
    }

    void Detector::StartMonitoringProcess(HANDLE Pid)
    {
        if (m_monitoredPid)
            return;
        m_monitoredPid = Pid;
        KeClearEvent(&m_stopEvent);
        m_isStopping = false;

        NTSTATUS status = PsCreateSystemThread(&m_vadThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, VadScannerThread, this);
        if (!NT_SUCCESS(status))
        {
            m_vadThreadHandle = nullptr;
            m_monitoredPid = nullptr;
        }
    }

    void Detector::StopMonitoringProcess()
    {
        if (!m_monitoredPid)
            return;
        m_isStopping = true;
        if (m_vadThreadHandle)
        {
            KeSetEvent(&m_stopEvent, 0, FALSE);
            PVOID threadObject = nullptr;
            NTSTATUS status = ObReferenceObjectByHandle(m_vadThreadHandle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &threadObject, NULL);
            if (NT_SUCCESS(status))
            {
                KeWaitForSingleObject(threadObject, Executive, KernelMode, FALSE, NULL);
                ObDereferenceObject(threadObject);
            }
            ZwClose(m_vadThreadHandle);
            m_vadThreadHandle = nullptr;
        }
        m_monitoredPid = nullptr;

        {
            util::FastMutexGuard lock(&m_dumpHashLock);
            m_dumpHashCount = 0;
        }
        m_moduleCount = 0;
        m_vadBaselineCount = 0;
    }

    void Detector::GetCurrentStatus(PRXINT_STATUS_INFO StatusInfo) const
    {
        if (!StatusInfo)
            return;

        if (m_monitoredPid != nullptr)
        {
            StatusInfo->IsMonitoring = TRUE;
            StatusInfo->MonitoredPid = reinterpret_cast<ULONG>(m_monitoredPid);
        }
        else
        {
            StatusInfo->IsMonitoring = FALSE;
            StatusInfo->MonitoredPid = 0;
        }
    }

    void Detector::ExtractKnownModules(PEPROCESS Process)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] ekm: starting module enumeration via PEB\n");
        m_moduleCount = 0;

        util::ProcessAttacher attacher(Process);

        PPEB pPeb = PsGetProcessPeb(Process);
        if (!pPeb)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] ekm: could not get PEB pointer\n");
            return;
        }

        __try
        {
            if (!pPeb->Ldr || !pPeb->Ldr->InMemoryOrderModuleList.Flink)
            {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] ekm: PEB or ldr list is null\n");
                return;
            }

            PLIST_ENTRY head = &pPeb->Ldr->InMemoryOrderModuleList;
            PLIST_ENTRY curr = head->Flink;

            while (curr != head && m_moduleCount < m_knownModules.size())
            {
                auto* entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                if (entry && entry->DllBase && entry->SizeOfImage)
                {
                    auto& mod = m_knownModules[m_moduleCount];
                    mod.BaseAddress = entry->DllBase;
                    mod.Size = entry->SizeOfImage;

                    if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0)
                    {
                        RtlCopyMemory(mod.Path, entry->FullDllName.Buffer, min(entry->FullDllName.Length, sizeof(mod.Path) - sizeof(WCHAR)));
                        mod.Path[_countof(mod.Path) - 1] = L'\0'; // Ensure null termination
                    }
                    else
                    {
                        mod.Path[0] = L'\0';
                    }

                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  -> module %2zu: %-25wZ | base: %p | size: 0x%lX\n", m_moduleCount, &entry->BaseDllName, mod.BaseAddress,
                               mod.Size);

                    m_moduleCount++;
                }
                curr = curr->Flink;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] ekm: exception while walking PEB ldr list\n");
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] ekm: finished. stored %zu modules\n", m_moduleCount);
    }

    void Detector::TakeVadSnapshot(PEPROCESS Process, util::kernel_array<MemoryRegionInfo, util::MAX_VAD_REGIONS>& snapshot, size_t& count)
    {
        util::ProcessAttacher attacher(Process);
        count = 0;
        PUCHAR addr = nullptr;
        MEMORY_BASIC_INFORMATION mbi;

        while (NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), addr, MemoryBasicInformation, &mbi, sizeof(mbi), NULL)) && count < snapshot.size())
        {
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE)
            {
                auto& info = snapshot[count];
                info.BaseAddress = mbi.BaseAddress;
                info.RegionSize = mbi.RegionSize;
                info.Protect = mbi.Protect;
                info.ContentHash = 0;

                auto* buffer = static_cast<unsigned char*>(ExAllocatePoolWithTag(NonPagedPoolNx, mbi.RegionSize, util::POOL_TAG));
                if (buffer)
                {
                    SIZE_T bytesRead = 0;
                    if (NT_SUCCESS(MmCopyVirtualMemory(Process, mbi.BaseAddress, PsGetCurrentProcess(), buffer, mbi.RegionSize, KernelMode, &bytesRead)))
                    {
                        info.ContentHash = XXH64(buffer, bytesRead, 0x1337);
                    }
                    ExFreePool(buffer);
                }
                count++;
            }
            addr = static_cast<PUCHAR>(mbi.BaseAddress) + mbi.RegionSize;
        }
    }

    void Detector::DumpPages(HANDLE ProcessId, PVOID base, SIZE_T regionSize, const util::kernel_array<ModuleRange, util::MAX_MODULES>& modules, size_t moduleCount)
    {
        util::ProcessReference proc(ProcessId);
        if (!proc)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] dump: failed to get process reference for PID %p\n", ProcessId);
            return;
        }

        ExtractKnownModules(proc.get());
        if (IsAddressInModuleList(base))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] dump: suppressing dump for %p because it is part of a known module\n", base);
            return;
        }

        auto* buffer = static_cast<unsigned char*>(ExAllocatePoolWithTag(NonPagedPoolNx, regionSize, util::DUMP_TAG));
        if (!buffer)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] dump: failed to allocate %zu bytes for dump\n", regionSize);
            return;
        }

        SIZE_T totalBytesCopied = 0;
        util::ProcessAttacher attacher(proc.get());
        NTSTATUS status = MmCopyVirtualMemory(proc.get(), base, PsGetCurrentProcess(), buffer, regionSize, KernelMode, &totalBytesCopied);

        if (NT_SUCCESS(status) && totalBytesCopied > 0)
        {
            ULONGLONG hash = XXH64(buffer, totalBytesCopied, 0x1337);
            if (!IsDuplicateHash(hash))
            {
                WCHAR filename[512];
                LARGE_INTEGER timestamp;
                KeQuerySystemTime(&timestamp);
                RtlStringCbPrintfW(filename, sizeof(filename), util::DUMP_PATH, timestamp.QuadPart);

                UNICODE_STRING path;
                RtlInitUnicodeString(&path, filename);
                OBJECT_ATTRIBUTES oa;
                InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
                IO_STATUS_BLOCK iosb;
                HANDLE file;
                status = ZwCreateFile(&file, FILE_GENERIC_WRITE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
                if (NT_SUCCESS(status))
                {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] dump: writing %zu bytes from %p to %S\n", totalBytesCopied, base, filename);
                    ZwWriteFile(file, NULL, NULL, NULL, &iosb, buffer, (ULONG) totalBytesCopied, NULL, NULL);
                    ZwClose(file);
                }
                else
                {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] dump: failed to create file %S, status: 0x%X, util::DUMPPATH=%ls\n", filename, status,
                               util::DUMP_PATH);
                }

                ULONG reportSize = 0;
                PCHAR reportBuffer = Reconstructor::CreateImportReport(proc.get(), buffer, totalBytesCopied, base, m_knownModules, m_moduleCount, &reportSize);
                if (reportBuffer && reportSize > 0)
                {
                    WCHAR txt_filename[512];
                    RtlStringCbPrintfW(txt_filename, sizeof(txt_filename), L"\\SystemRoot\\Temp\\report_%llu.txt", timestamp.QuadPart);

                    UNICODE_STRING txt_path;
                    RtlInitUnicodeString(&txt_path, txt_filename);
                    OBJECT_ATTRIBUTES oa;
                    InitializeObjectAttributes(&oa, &txt_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
                    HANDLE hFile_txt;
                    IO_STATUS_BLOCK iosb_txt;
                    status = ZwCreateFile(&hFile_txt, FILE_GENERIC_WRITE, &oa, &iosb_txt, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
                    if (NT_SUCCESS(status))
                    {
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] dump: dumping import report to %S\n", txt_filename);
                        ZwWriteFile(hFile_txt, NULL, NULL, NULL, &iosb_txt, reportBuffer, reportSize, NULL, NULL);
                        ZwClose(hFile_txt);
                    }
                    ExFreePoolWithTag(reportBuffer, util::POOL_TAG);
                }
            }
            else
            {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] dump: duplicate hash, skipping dump for address %p\n", base);
            }
        }
        else
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] dump: failed to copy memory from %p, status: 0x%X\n", base, status);
        }
        ExFreePool(buffer);
    }

    bool Detector::IsAddressInModuleList(PVOID addr) const
    {
        for (size_t i = 0; i < m_moduleCount; ++i)
        {
            const auto& mod = m_knownModules[i];
            if ((uintptr_t) addr >= (uintptr_t) mod.BaseAddress && (uintptr_t) addr < ((uintptr_t) mod.BaseAddress + mod.Size))
            {
                return true;
            }
        }
        return false;
    }

    bool Detector::IsDuplicateHash(ULONGLONG hash)
    {
        util::FastMutexGuard lock(&m_dumpHashLock);
        for (size_t i = 0; i < m_dumpHashCount; ++i)
        {
            if (m_dumpHashes[i] == hash)
                return true;
        }
        if (m_dumpHashCount < m_dumpHashes.size())
        {
            m_dumpHashes[m_dumpHashCount++] = hash;
            return false;
        }
        return true;
    }

    bool Detector::IsExecutable(ULONG Protect)
    {
        return (Protect & PAGE_EXECUTE) || (Protect & PAGE_EXECUTE_READ) || (Protect & PAGE_EXECUTE_READWRITE) || (Protect & PAGE_EXECUTE_WRITECOPY);
    }
} // namespace rx