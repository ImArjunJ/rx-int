#pragma once

#include "Common.hpp"
#include "Ioctl.hpp"
#include "ExportResolver.hpp"

namespace rx
{
    class Detector;
    extern Detector* g_Detector;

    struct ProcessCandidate
    {
        HANDLE Pid;
        LARGE_INTEGER CreateTime;
        bool Alive = true;
    };

    struct MemoryRegionInfo
    {
        PVOID BaseAddress;
        SIZE_T RegionSize;
        ULONG Protect;
        ULONGLONG ContentHash;
    };

    struct SelectionWorkContext
    {
        Detector* pDetector;
        WORK_QUEUE_ITEM WorkItem;
    };

    class Detector
    {
    public:
        Detector();
        ~Detector() = default;

        NTSTATUS Start();
        void Stop();

        void OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, bool Create);

        void StartMonitoringProcess(HANDLE Pid);
        void StopMonitoringProcess();
        void GetCurrentStatus(PRXINT_STATUS_INFO StatusInfo) const;

    private:
        static void VadScannerThread(PVOID StartContext);
        void ExtractKnownModules(PEPROCESS Process);
        void TakeVadSnapshot(PEPROCESS Process, util::kernel_array<MemoryRegionInfo, util::MAX_VAD_REGIONS>& snapshot, size_t& count);
        void DumpPages(HANDLE ProcessId, PVOID base, SIZE_T regionSize);
        bool IsAddressInModuleList(PVOID addr) const;
        bool IsDuplicateHash(ULONGLONG hash);
        static bool IsExecutable(ULONG Protect);

    private:
        ExportResolver m_exportResolver;

        bool m_isStopping;
        KEVENT m_stopEvent;
        HANDLE m_vadThreadHandle;
        HANDLE m_selectionThreadHandle;

        // Use a SpinLock because OnProcessNotify can be called at DISPATCH_LEVEL
        KSPIN_LOCK m_candidateLock;
        util::kernel_array<ProcessCandidate, util::MAX_CANDIDATE_PROCESSES> m_candidates;
        size_t m_candidateCount;

        HANDLE m_monitoredPid;

        FAST_MUTEX m_dumpHashLock;
        util::kernel_array<ULONGLONG, util::MAX_DUMP_HASHES> m_dumpHashes;
        size_t m_dumpHashCount;

        util::kernel_array<ModuleRange, util::MAX_MODULES> m_knownModules;
        size_t m_moduleCount;

        util::kernel_array<MemoryRegionInfo, util::MAX_VAD_REGIONS> m_vadBaseline;
        size_t m_vadBaselineCount;
    };
} // namespace rx