#pragma once
#include <ntifs.h>
#include <ntstrsafe.h>
#include "Ioctl.hpp"
namespace rx::mem
{
    void Initialize();
    PVOID Allocate(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag);
    void Free(PVOID P, ULONG Tag);
    void GetUsage(RXINT_MEMORY_STATS& stats);
} // namespace rx::mem