#pragma once
#include "Common.hpp"

namespace rx
{
    class Reconstructor
    {
    public:
        static PCHAR CreateImportReport(PEPROCESS Process, PUCHAR DumpedRegion, SIZE_T RegionSize, PVOID RegionBaseAddress,
                                        const util::kernel_array<ModuleRange, util::MAX_MODULES>& modules, size_t moduleCount, PULONG ReportSize);

    private:
        static bool ResolveAddressToSymbol(PEPROCESS Process, PVOID Address, const util::kernel_array<ModuleRange, util::MAX_MODULES>& modules, size_t moduleCount,
                                           char* OutSymbolName, size_t SymbolNameSize);
    };
} // namespace rx