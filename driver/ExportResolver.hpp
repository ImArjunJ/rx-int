#pragma once
#include "Common.hpp"

namespace rx
{
    struct ExportedSymbol
    {
        PVOID Address;
        char Name[128];
        char ForwarderName[128];
    };

    struct ModuleExports
    {
        wchar_t ModuleName[64];
        PVOID ModuleBase;
        ExportedSymbol* Symbols;
        size_t SymbolCount = 0;
    };

    class ExportResolver
    {
    public:
        ExportResolver();
        ~ExportResolver();
        NTSTATUS BuildSnapshot(PEPROCESS Process, const util::kernel_array<ModuleRange, util::MAX_MODULES>& modules, size_t moduleCount);
        void ClearSnapshot();

        bool ResolveAddress(PVOID Address, char* OutSymbolName, size_t SymbolNameSize) const;

    private:
        util::kernel_array<ModuleExports, util::MAX_MODULES> m_exportSnapshot;
        size_t m_snapshotModuleCount = 0;
    };
} // namespace rx