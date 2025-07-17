#include "Memory.hpp"
#include "Wrappers.hpp"
#include <ntifs.h>


namespace rx::mem
{
    constexpr ULONG MAX_TRACKED_ALLOCATIONS = 8192;

    struct TRACKED_ALLOCATION
    {
        PVOID Address;
        SIZE_T Size;
        ULONG Tag;
        POOL_TYPE PoolType;
    };

    static util::kernel_array<TRACKED_ALLOCATION, MAX_TRACKED_ALLOCATIONS> g_allocationTable;
    static FAST_MUTEX g_memoryTableLock;
    static volatile LONGLONG g_pagedBytesUsed = 0;
    static volatile LONGLONG g_nonPagedBytesUsed = 0;

    static ULONG HashPointer(PVOID Ptr)
    {
        return (ULONG) (((ULONG_PTR) Ptr >> 4) % MAX_TRACKED_ALLOCATIONS);
    }

    void Initialize()
    {
        ExInitializeFastMutex(&g_memoryTableLock);
        RtlZeroMemory(g_allocationTable.data(), sizeof(g_allocationTable));
    }

    PVOID Allocate(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag)
    {
        PVOID p = ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
        if (!p)
        {
            return nullptr;
        }

        util::FastMutexGuard lock(&g_memoryTableLock);

        ULONG startIndex = HashPointer(p);
        ULONG currentIndex = startIndex;

        do {
            if (g_allocationTable[currentIndex].Address == nullptr)
            {
                g_allocationTable[currentIndex].Address = p;
                g_allocationTable[currentIndex].Size = NumberOfBytes;
                g_allocationTable[currentIndex].Tag = Tag;
                g_allocationTable[currentIndex].PoolType = PoolType;

                if (PoolType == PagedPool)
                {
                    InterlockedAdd64(&g_pagedBytesUsed, NumberOfBytes);
                }
                else
                {
                    InterlockedAdd64(&g_nonPagedBytesUsed, NumberOfBytes);
                }

                return p;
            }
            currentIndex = (currentIndex + 1) % MAX_TRACKED_ALLOCATIONS;
        } while (currentIndex != startIndex);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] mem: hash table is full, allocation at %p will not be tracked\n", p);
        return p;
    }

    void Free(PVOID P, ULONG Tag)
    {
        if (!P)
            return;

        util::FastMutexGuard lock(&g_memoryTableLock);

        ULONG startIndex = HashPointer(P);
        ULONG currentIndex = startIndex;

        do {
            if (g_allocationTable[currentIndex].Address == P)
            {
                SIZE_T size = g_allocationTable[currentIndex].Size;
                POOL_TYPE poolType = g_allocationTable[currentIndex].PoolType;

                if (poolType == PagedPool)
                {
                    InterlockedAdd64(&g_pagedBytesUsed, -(LONGLONG) size);
                }
                else
                {
                    InterlockedAdd64(&g_nonPagedBytesUsed, -(LONGLONG) size);
                }

                RtlZeroMemory(&g_allocationTable[currentIndex], sizeof(TRACKED_ALLOCATION));

                ExFreePoolWithTag(P, Tag);
                return;
            }
            currentIndex = (currentIndex + 1) % MAX_TRACKED_ALLOCATIONS;
        } while (currentIndex != startIndex);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] mem: attempted to free untracked memory at %p\n", P);
        ExFreePoolWithTag(P, Tag);
    }

    void GetUsage(RXINT_MEMORY_STATS& stats)
    {
        stats.PagedBytes = InterlockedOr64(&g_pagedBytesUsed, 0);
        stats.NonPagedBytes = InterlockedOr64(&g_nonPagedBytesUsed, 0);
    }
} // namespace rx::mem