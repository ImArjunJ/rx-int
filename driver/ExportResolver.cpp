#include "ExportResolver.hpp"

#include <ntstrsafe.h>

#include "Wrappers.hpp"

namespace rx
{
    NTSTATUS ExportResolver::BuildSnapshot(PEPROCESS Process, const util::kernel_array<ModuleRange, util::MAX_MODULES>& modules, size_t moduleCount)
    {
        m_snapshotModuleCount = 0;
        if (!Process)
            return STATUS_INVALID_PARAMETER;

        for (size_t i = 0; i < moduleCount && m_snapshotModuleCount < m_exportSnapshot.size(); ++i)
        {
            const auto& mod = modules[i];
            auto& modExports = m_exportSnapshot[m_snapshotModuleCount];
            modExports.ModuleBase = mod.BaseAddress;
            const wchar_t* lastSlash = wcsrchr(mod.Path, L'\\');
            RtlStringCbCopyW(modExports.ModuleName, sizeof(modExports.ModuleName), lastSlash ? lastSlash + 1 : mod.Path);

            pe::IMAGE_DOS_HEADER dosHeader = {0};
            pe::IMAGE_NT_HEADERS ntHeaders = {0};
            SIZE_T bytesRead = 0;

            if (!NT_SUCCESS(MmCopyVirtualMemory(Process, mod.BaseAddress, PsGetCurrentProcess(), &dosHeader, sizeof(dosHeader), KernelMode, &bytesRead))
                || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
                continue;
            if (!NT_SUCCESS(
                    MmCopyVirtualMemory(Process, (unsigned char*) mod.BaseAddress + dosHeader.e_lfanew, PsGetCurrentProcess(), &ntHeaders, sizeof(ntHeaders), KernelMode, &bytesRead))
                || ntHeaders.Signature != IMAGE_NT_SIGNATURE)
                continue;

            auto exportDirEntry = ntHeaders.OptionalHeader.DataDirectory[0];
            if (exportDirEntry.VirtualAddress == 0 || exportDirEntry.Size == 0)
                continue;

            pe::IMAGE_EXPORT_DIRECTORY exportDir = {0};
            if (!NT_SUCCESS(MmCopyVirtualMemory(Process, (unsigned char*) mod.BaseAddress + exportDirEntry.VirtualAddress, PsGetCurrentProcess(), &exportDir, sizeof(exportDir), KernelMode,
                                                &bytesRead)))
                continue;

            PULONG pAddrOfFunctions = (PULONG) ExAllocatePoolWithTag(NonPagedPoolNx, exportDir.NumberOfFunctions * sizeof(ULONG), util::POOL_TAG);
            PULONG pAddrOfNames = (PULONG) ExAllocatePoolWithTag(NonPagedPoolNx, exportDir.NumberOfNames * sizeof(ULONG), util::POOL_TAG);
            PUSHORT pAddrOfOrdinals = (PUSHORT) ExAllocatePoolWithTag(NonPagedPoolNx, exportDir.NumberOfNames * sizeof(USHORT), util::POOL_TAG);

            if (!pAddrOfFunctions || !pAddrOfNames || !pAddrOfOrdinals)
            {
                continue;
            }

            MmCopyVirtualMemory(Process, (unsigned char*) mod.BaseAddress + exportDir.AddressOfFunctions, PsGetCurrentProcess(), pAddrOfFunctions,
                                exportDir.NumberOfFunctions * sizeof(ULONG), KernelMode, &bytesRead);
            MmCopyVirtualMemory(Process, (unsigned char*) mod.BaseAddress + exportDir.AddressOfNames, PsGetCurrentProcess(), pAddrOfNames, exportDir.NumberOfNames * sizeof(ULONG),
                                KernelMode, &bytesRead);
            MmCopyVirtualMemory(Process, (unsigned char*) mod.BaseAddress + exportDir.AddressOfNameOrdinals, PsGetCurrentProcess(), pAddrOfOrdinals,
                                exportDir.NumberOfNames * sizeof(USHORT), KernelMode, &bytesRead);

            for (ULONG j = 0; j < exportDir.NumberOfFunctions && modExports.SymbolCount < modExports.Symbols.size(); ++j)
            {
                ULONG functionRva = pAddrOfFunctions[j];
                if (functionRva == 0)
                    continue;

                auto& symbol = modExports.Symbols[modExports.SymbolCount];
                symbol.Address = (unsigned char*) mod.BaseAddress + functionRva;

                if (functionRva >= exportDirEntry.VirtualAddress && functionRva < exportDirEntry.VirtualAddress + exportDirEntry.Size)
                {
                    MmCopyVirtualMemory(Process, (unsigned char*) mod.BaseAddress + functionRva, PsGetCurrentProcess(), symbol.ForwarderName, sizeof(symbol.ForwarderName) - 1, KernelMode,
                                        &bytesRead);
                }
                else
                {
                    for (ULONG k = 0; k < exportDir.NumberOfNames; ++k)
                    {
                        if (pAddrOfOrdinals[k] == j)
                        {
                            MmCopyVirtualMemory(Process, (unsigned char*) mod.BaseAddress + pAddrOfNames[k], PsGetCurrentProcess(), symbol.Name, sizeof(symbol.Name) - 1, KernelMode,
                                                &bytesRead);
                            break;
                        }
                    }
                }
                modExports.SymbolCount++;
            }
            m_snapshotModuleCount++;

            ExFreePoolWithTag(pAddrOfFunctions, util::POOL_TAG);
            ExFreePoolWithTag(pAddrOfNames, util::POOL_TAG);
            ExFreePoolWithTag(pAddrOfOrdinals, util::POOL_TAG);
        }
        return STATUS_SUCCESS;
    }

    bool ExportResolver::ResolveAddress(PVOID Address, char* OutSymbolName, size_t SymbolNameSize) const
    {
        for (size_t i = 0; i < m_snapshotModuleCount; ++i)
        {
            const auto& modExports = m_exportSnapshot[i];
            if ((ULONG_PTR) Address >= (ULONG_PTR) modExports.ModuleBase && (ULONG_PTR) Address < ((ULONG_PTR) modExports.ModuleBase + 0xFFFFFFF)) // Heuristic size
            {
                for (size_t j = 0; j < modExports.SymbolCount; ++j)
                {
                    const auto& symbol = modExports.Symbols[j];
                    if (symbol.Address == Address)
                    {
                        if (symbol.ForwarderName[0] != '\0')
                        {
                            RtlStringCbPrintfA(OutSymbolName, SymbolNameSize, "%S (forwarded to -> %s)", modExports.ModuleName, symbol.ForwarderName);
                        }
                        else
                        {
                            RtlStringCbPrintfA(OutSymbolName, SymbolNameSize, "%S!%s", modExports.ModuleName, symbol.Name[0] ? symbol.Name : "<unnamed>");
                        }
                        return true;
                    }
                }
            }
        }
        return false;
    }
} // namespace rx