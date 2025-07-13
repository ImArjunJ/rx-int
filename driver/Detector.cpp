#include "Detector.hpp"

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
            DumpPages(ProcessId, mbi.BaseAddress, mbi.RegionSize);
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
        NTSTATUS status = detector->m_exportResolver.BuildSnapshot(proc.get(), detector->m_knownModules, detector->m_moduleCount);
        if (NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[RX-INT] Successfully built export snapshot.\n");
        }
        else
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] Failed to build export snapshot: 0x%X\n", status);
        }
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
                            detector->DumpPages(pid, currentRegion.BaseAddress, currentRegion.RegionSize);
                        }
                        else if (IsExecutable(currentRegion.Protect) && currentRegion.ContentHash != baselineRegion.ContentHash)
                        {
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] vad: self-modifying code detected at %p! dumping...\n", currentRegion.BaseAddress);
                            detector->DumpPages(pid, currentRegion.BaseAddress, currentRegion.RegionSize);
                        }
                        break;
                    }
                }
                if (!foundInBaseline && IsExecutable(currentRegion.Protect))
                {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] vad: new executable private region at %p! dumping...\n", currentRegion.BaseAddress);
                    detector->DumpPages(pid, currentRegion.BaseAddress, currentRegion.RegionSize);
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

    void Detector::DumpPages(HANDLE ProcessId, PVOID base, SIZE_T regionSize)
    {
        util::ProcessReference proc(ProcessId);
        if (!proc)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] Dump: Failed to get process reference for PID %p\n", ProcessId);
            return;
        }

        if (IsAddressInModuleList(base))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[RX-INT] Dump: Suppressing dump for %p as it is now part of a known module.\n", base);
            return;
        }

        auto* rawBuffer = static_cast<unsigned char*>(ExAllocatePoolWithTag(NonPagedPoolNx, regionSize, util::DUMP_TAG));
        if (!rawBuffer)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] Dump: Failed to allocate buffer for dump.\n");
            return;
        }

        SIZE_T totalBytesCopied = 0;
        NTSTATUS status = MmCopyVirtualMemory(proc.get(), base, PsGetCurrentProcess(), rawBuffer, regionSize, KernelMode, &totalBytesCopied);
        if (!NT_SUCCESS(status) || totalBytesCopied == 0)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] Dump: Failed to copy memory from %p, status: 0x%X\n", base, status);
            ExFreePoolWithTag(rawBuffer, util::DUMP_TAG);
            return;
        }

        ULONGLONG hash = XXH64(rawBuffer, totalBytesCopied, 0x1337);
        if (IsDuplicateHash(hash))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[RX-INT] Dump: Duplicate hash for region %p, skipping.\n", base);
            ExFreePoolWithTag(rawBuffer, util::DUMP_TAG);
            return;
        }

        LARGE_INTEGER timestamp;
        KeQuerySystemTime(&timestamp);

        WCHAR bin_filename[512];
        RtlStringCbPrintfW(bin_filename, sizeof(bin_filename), util::DUMP_PATH, timestamp.QuadPart);

        UNICODE_STRING bin_path;
        RtlInitUnicodeString(&bin_path, bin_filename);
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &bin_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        HANDLE hFile_bin;
        IO_STATUS_BLOCK iosb_bin;
        status = ZwCreateFile(&hFile_bin, FILE_GENERIC_WRITE, &oa, &iosb_bin, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (NT_SUCCESS(status))
        {
            ZwWriteFile(hFile_bin, NULL, NULL, NULL, &iosb_bin, rawBuffer, (ULONG) totalBytesCopied, NULL, NULL);
            ZwClose(hFile_bin);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] Dump: Successfully wrote %zu raw bytes to %S\n", totalBytesCopied, bin_filename);
        }

        const ULONG reportBufferSize = 16 * 1024;
        PCHAR reportBuffer = (PCHAR) ExAllocatePoolWithTag(NonPagedPoolNx, reportBufferSize, util::POOL_TAG);
        if (reportBuffer)
        {
            RtlZeroMemory(reportBuffer, reportBufferSize);
            ULONG currentOffset = 0;
            RtlStringCbPrintfA(reportBuffer, reportBufferSize, "[RX-INT] Import Analysis Report for region at %p (size: %zu)\r\n\r\n", base, totalBytesCopied);
            currentOffset = (ULONG) strlen(reportBuffer);

            for (size_t i = 0; i <= totalBytesCopied - sizeof(PVOID); i += sizeof(PVOID))
            {
                PVOID pointerValue = *(PVOID*) (rawBuffer + i);
                char symbolName[256] = {0};

                if (m_exportResolver.ResolveAddress(pointerValue, symbolName, sizeof(symbolName)))
                {
                    char tempLine[512];
                    RtlStringCbPrintfA(tempLine, sizeof(tempLine), "  [V_ADDR: 0x%p] contains pointer to -> %s\r\n", (unsigned char*) base + i, symbolName);

                    if (currentOffset + strlen(tempLine) < reportBufferSize)
                    {
                        RtlStringCbCatA(reportBuffer, reportBufferSize, tempLine);
                        currentOffset += (ULONG) strlen(tempLine);
                    }
                }
            }

            if (currentOffset > strlen("[RX-INT] Import Analysis Report for region at %p (size: %zu)\r\n\r\n"))
            {
                WCHAR txt_filename[512];
                RtlStringCbPrintfW(txt_filename, sizeof(txt_filename), L"\\SystemRoot\\Temp\\RX_REPORT_%llu.txt", timestamp.QuadPart);

                UNICODE_STRING txt_path;
                RtlInitUnicodeString(&txt_path, txt_filename);
                InitializeObjectAttributes(&oa, &txt_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
                HANDLE hFile_txt;
                IO_STATUS_BLOCK iosb_txt;
                status = ZwCreateFile(&hFile_txt, FILE_GENERIC_WRITE, &oa, &iosb_txt, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
                if (NT_SUCCESS(status))
                {
                    ZwWriteFile(hFile_txt, NULL, NULL, NULL, &iosb_txt, reportBuffer, currentOffset, NULL, NULL);
                    ZwClose(hFile_txt);
                }
            }
            ExFreePoolWithTag(reportBuffer, util::POOL_TAG);
        }

        ExFreePoolWithTag(rawBuffer, util::DUMP_TAG);
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