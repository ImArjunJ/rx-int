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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] C++ Detector started successfully.\n");
        return STATUS_SUCCESS;
    }

    void Detector::Stop()
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] C++ Detector stopping...\n");
        StopMonitoringProcess();
    }

    void Detector::OnProcessNotify(PEPROCESS Process, HANDLE Pid, PPS_CREATE_NOTIFY_INFO Info)
    {
        UNREFERENCED_PARAMETER(Process);
        if (m_isStopping)
            return;

        if (Info) // Process Creation
        {
            if (!Info->ImageFileName || !wcsstr(Info->ImageFileName->Buffer, L"gmod.exe"))
                return;

            util::SpinLockGuard lock(&m_candidateLock);
            if (m_candidateCount >= m_candidates.size())
                return;

            auto& newCandidate = m_candidates[m_candidateCount];
            newCandidate.Pid = Pid;
            KeQuerySystemTime(&newCandidate.CreateTime);
            newCandidate.Alive = true;
            m_candidateCount++;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] Found candidate gmod.exe PID %p\n", Pid);

            if (!m_monitoredPid)
            {
                auto* workContext = static_cast<SelectionWorkContext*>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(SelectionWorkContext), util::POOL_TAG));
                if (workContext)
                {
                    workContext->pDetector = this;
                    ExInitializeWorkItem(&workContext->WorkItem, SelectionWorkItemRoutine, workContext);
                    ExQueueWorkItem(&workContext->WorkItem, DelayedWorkQueue);
                }
            }
        }
        else // Process Termination
        {
            util::SpinLockGuard lock(&m_candidateLock);
            for (size_t i = 0; i < m_candidateCount; ++i)
            {
                if (m_candidates[i].Pid == Pid)
                {
                    m_candidates[i].Alive = false;
                    break;
                }
            }

            if (Pid == m_monitoredPid)
            {
                StopMonitoringProcess();
            }
        }
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
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] THREAD: Suspicious start @ %p. Dumping.\n", startAddress);
            DumpPages(ProcessId, mbi.BaseAddress, mbi.RegionSize);
        }
    }
    void Detector::SelectionWorkItemRoutine(PVOID Context)
    {
        auto* workContext = static_cast<SelectionWorkContext*>(Context);
        auto* detector = workContext->pDetector;

        ExFreePoolWithTag(workContext, util::POOL_TAG);

        HANDLE selectionThreadHandle;
        NTSTATUS status = PsCreateSystemThread(&selectionThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, SelectionThread, detector);
        if (NT_SUCCESS(status))
        {
            ZwClose(selectionThreadHandle);
        }
    }

    void Detector::SelectionThread(PVOID StartContext)
    {
        auto* detector = static_cast<Detector*>(StartContext);

        LARGE_INTEGER delay;
        delay.QuadPart = -50000000LL; // 5 seconds
        KeDelayExecutionThread(KernelMode, FALSE, &delay);

        HANDLE bestPid = nullptr;
        {
            util::SpinLockGuard lock(&detector->m_candidateLock);
            LARGE_INTEGER latest = {0};
            for (size_t i = 0; i < detector->m_candidateCount; ++i)
            {
                if (detector->m_candidates[i].Alive && detector->m_candidates[i].CreateTime.QuadPart > latest.QuadPart)
                {
                    latest = detector->m_candidates[i].CreateTime;
                    bestPid = detector->m_candidates[i].Pid;
                }
            }
        }
        bestPid = detector->m_candidates[0].Pid;
        if (bestPid)
        {
            detector->StartMonitoringProcess(bestPid);
        }

        PsTerminateSystemThread(STATUS_SUCCESS);
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] VAD: Baseline complete for PID %p with %zu regions.\n", pid, detector->m_vadBaselineCount);

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
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] VAD: Permission escalation to EXECUTE at %p! Dumping.\n", currentRegion.BaseAddress);
                            detector->DumpPages(pid, currentRegion.BaseAddress, currentRegion.RegionSize);
                        }
                        else if (IsExecutable(currentRegion.Protect) && currentRegion.ContentHash != baselineRegion.ContentHash)
                        {
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] VAD: Self-modifying code detected at %p! Dumping.\n", currentRegion.BaseAddress);
                            detector->DumpPages(pid, currentRegion.BaseAddress, currentRegion.RegionSize);
                        }
                        break;
                    }
                }
                if (!foundInBaseline && IsExecutable(currentRegion.Protect))
                {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] VAD: New executable private region at %p! Dumping.\n", currentRegion.BaseAddress);
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
    }

    void Detector::ExtractKnownModules(PEPROCESS Process)
    {
        util::ProcessAttacher attacher(Process);
        m_moduleCount = 0;
        ULONG modulesSize = 0;
        NTSTATUS status = ZwQueryInformationProcess(ZwCurrentProcess(), ProcessInfoClass::ProcessModules, NULL, 0, &modulesSize);
        if (status != STATUS_INFO_LENGTH_MISMATCH)
            return;

        auto* modules = static_cast<RTL_PROCESS_MODULES*>(ExAllocatePoolWithTag(PagedPool, modulesSize, util::POOL_TAG));
        if (!modules)
            return;

        status = ZwQueryInformationProcess(ZwCurrentProcess(), ProcessInfoClass::ProcessModules, modules, modulesSize, &modulesSize);
        if (NT_SUCCESS(status))
        {
            for (ULONG i = 0; i < modules->NumberOfModules && m_moduleCount < m_knownModules.size(); ++i)
            {
                auto& entry = m_knownModules[m_moduleCount];
                entry.BaseAddress = modules->Modules[i].ImageBase;
                entry.Size = modules->Modules[i].ImageSize;
                m_moduleCount++;
            }
        }
        ExFreePool(modules);
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
            return;

        auto* buffer = static_cast<unsigned char*>(ExAllocatePoolWithTag(NonPagedPoolNx, regionSize, util::DUMP_TAG));
        if (!buffer)
            return;

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
                if (NT_SUCCESS(ZwCreateFile(&file, FILE_GENERIC_WRITE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
                {
                    ZwWriteFile(file, NULL, NULL, NULL, &iosb, buffer, (ULONG) totalBytesCopied, NULL, NULL);
                    ZwClose(file);
                }
            }
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