#include "Reconstructor.hpp"

#include <ntstrsafe.h>

#include "Wrappers.hpp"

namespace rx
{
    bool Reconstructor::ResolveAddressToSymbol(PEPROCESS Process, PVOID Address, const util::kernel_array<ModuleRange, util::MAX_MODULES>& modules, size_t moduleCount,
                                               char* OutSymbolName, size_t SymbolNameSize)
    {
        for (size_t i = 0; i < moduleCount; ++i)
        {
            const auto& mod = modules[i];
            if ((ULONG_PTR) Address >= (ULONG_PTR) mod.BaseAddress && (ULONG_PTR) Address < ((ULONG_PTR) mod.BaseAddress + mod.Size))
            {
                PUCHAR modBase = (PUCHAR) mod.BaseAddress;

                pe::IMAGE_DOS_HEADER dosHeader = {0};
                pe::IMAGE_NT_HEADERS ntHeaders = {0};
                SIZE_T bytesRead = 0;

                if (!NT_SUCCESS(MmCopyVirtualMemory(Process, modBase, PsGetCurrentProcess(), &dosHeader, sizeof(dosHeader), KernelMode, &bytesRead)))
                    continue;
                if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
                    continue;
                if (!NT_SUCCESS(MmCopyVirtualMemory(Process, modBase + dosHeader.e_lfanew, PsGetCurrentProcess(), &ntHeaders, sizeof(ntHeaders), KernelMode, &bytesRead)))
                    continue;
                if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
                    continue;

                auto exportDirEntry = ntHeaders.OptionalHeader.DataDirectory[0];
                if (exportDirEntry.VirtualAddress == 0 || exportDirEntry.Size == 0)
                    continue;

                pe::IMAGE_EXPORT_DIRECTORY exportDir = {0};
                if (!NT_SUCCESS(
                        MmCopyVirtualMemory(Process, modBase + exportDirEntry.VirtualAddress, PsGetCurrentProcess(), &exportDir, sizeof(exportDir), KernelMode, &bytesRead)))
                    continue;

                PULONG pAddrOfFunctions = (PULONG) ExAllocatePoolWithTag(NonPagedPoolNx, exportDir.NumberOfFunctions * sizeof(ULONG), util::POOL_TAG);
                PULONG pAddrOfNames = (PULONG) ExAllocatePoolWithTag(NonPagedPoolNx, exportDir.NumberOfNames * sizeof(ULONG), util::POOL_TAG);
                PUSHORT pAddrOfOrdinals = (PUSHORT) ExAllocatePoolWithTag(NonPagedPoolNx, exportDir.NumberOfNames * sizeof(USHORT), util::POOL_TAG);

                if (!pAddrOfFunctions || !pAddrOfNames || !pAddrOfOrdinals)
                {
                    if (pAddrOfFunctions)
                        ExFreePoolWithTag(pAddrOfFunctions, util::POOL_TAG);
                    if (pAddrOfNames)
                        ExFreePoolWithTag(pAddrOfNames, util::POOL_TAG);
                    if (pAddrOfOrdinals)
                        ExFreePoolWithTag(pAddrOfOrdinals, util::POOL_TAG);
                    continue;
                }

                MmCopyVirtualMemory(Process, modBase + exportDir.AddressOfFunctions, PsGetCurrentProcess(), pAddrOfFunctions, exportDir.NumberOfFunctions * sizeof(ULONG),
                                    KernelMode, &bytesRead);
                MmCopyVirtualMemory(Process, modBase + exportDir.AddressOfNames, PsGetCurrentProcess(), pAddrOfNames, exportDir.NumberOfNames * sizeof(ULONG), KernelMode,
                                    &bytesRead);
                MmCopyVirtualMemory(Process, modBase + exportDir.AddressOfNameOrdinals, PsGetCurrentProcess(), pAddrOfOrdinals, exportDir.NumberOfNames * sizeof(USHORT),
                                    KernelMode, &bytesRead);

                ULONG_PTR rva = (ULONG_PTR) Address - (ULONG_PTR) mod.BaseAddress;
                bool found = false;

                for (ULONG j = 0; j < exportDir.NumberOfFunctions; ++j)
                {
                    if (pAddrOfFunctions[j] == rva)
                    {
                        char funcName[128] = "<unnamed_export>";
                        for (ULONG k = 0; k < exportDir.NumberOfNames; ++k)
                        {
                            if (pAddrOfOrdinals[k] == j)
                            {
                                if (!NT_SUCCESS(
                                        MmCopyVirtualMemory(Process, modBase + pAddrOfNames[k], PsGetCurrentProcess(), funcName, sizeof(funcName) - 1, KernelMode, &bytesRead)))
                                {
                                    break;
                                }
                                funcName[sizeof(funcName) - 1] = '\0';
                                break;
                            }
                        }

                        const wchar_t* lastSlash = wcsrchr(mod.Path, L'\\');
                        const wchar_t* moduleName = lastSlash ? lastSlash + 1 : mod.Path;

                        RtlStringCbPrintfA(OutSymbolName, SymbolNameSize, "%S", moduleName);

                        size_t currentLen = 0;
                        RtlStringCchLengthA(OutSymbolName, SymbolNameSize, &currentLen);
                        RtlStringCbCatA(OutSymbolName, SymbolNameSize, "!");

                        RtlStringCchLengthA(OutSymbolName, SymbolNameSize, &currentLen);
                        RtlStringCbCatA(OutSymbolName, SymbolNameSize, funcName);
                        found = true;
                        break;
                    }
                }

                ExFreePoolWithTag(pAddrOfFunctions, util::POOL_TAG);
                ExFreePoolWithTag(pAddrOfNames, util::POOL_TAG);
                ExFreePoolWithTag(pAddrOfOrdinals, util::POOL_TAG);
                return found;
            }
        }
        return false;
    }

    PCHAR Reconstructor::CreateImportReport(PEPROCESS Process, PUCHAR DumpedRegion, SIZE_T RegionSize, PVOID RegionBaseAddress,
                                            const util::kernel_array<ModuleRange, util::MAX_MODULES>& modules, size_t moduleCount, PULONG ReportSize)
    {
        *ReportSize = 0;
        const ULONG reportBufferSize = 16 * 1024; // 16KB for the report
        PCHAR reportBuffer = (PCHAR) ExAllocatePoolWithTag(NonPagedPoolNx, reportBufferSize, util::POOL_TAG);
        if (!reportBuffer)
            return nullptr;

        RtlZeroMemory(reportBuffer, reportBufferSize);
        ULONG currentOffset = 0;

        RtlStringCbPrintfA(reportBuffer, reportBufferSize, "[RX-INT] Import Analysis Report for region at %p (size: %zu)\r\n\r\n", RegionBaseAddress, RegionSize);
        currentOffset = (ULONG) strlen(reportBuffer);

        for (size_t i = 0; i <= RegionSize - sizeof(PVOID); i += sizeof(PVOID))
        {
            PVOID pointerValue = *(PVOID*) (DumpedRegion + i);

            char symbolName[256];
            if (ResolveAddressToSymbol(Process, pointerValue, modules, moduleCount, symbolName, sizeof(symbolName)))
            {
                char tempLine[512];
                RtlStringCbPrintfA(tempLine, sizeof(tempLine), "  [V_ADDR: 0x%p] contains pointer to -> %s\r\n", (unsigned char*) RegionBaseAddress + i, symbolName);

                if (currentOffset + strlen(tempLine) < reportBufferSize)
                {
                    RtlStringCbCatA(reportBuffer, reportBufferSize, tempLine);
                    currentOffset = (ULONG) strlen(reportBuffer);
                }
            }
        }

        *ReportSize = currentOffset;
        return reportBuffer;
    }
} // namespace rx