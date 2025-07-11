#pragma once

#include <ntifs.h>
#include <ntstrsafe.h>

#include "xxhash.h"

#define THREAD_QUERY_INFORMATION (0x0040)

namespace rx::util
{
    constexpr const wchar_t* DUMP_PATH = L"\\SystemRoot\\Temp\\dump_%llu.bin";
    constexpr ULONG DUMP_TAG = 'rxdm';
    constexpr ULONG POOL_TAG = 'rxmm';
    constexpr ULONG MAX_CANDIDATE_PROCESSES = 8;
    constexpr ULONG MAX_VAD_REGIONS = 4096;
    constexpr ULONG MAX_MODULES = 256;
    constexpr ULONG MAX_DUMP_HASHES = 1024;

    template <typename T, size_t N>
    class kernel_array
    {
    public:
        using value_type = T;
        using size_type = size_t;
        using reference = T&;
        using const_reference = const T&;
        using pointer = T*;
        using const_pointer = const T*;

        constexpr reference operator[](size_type pos)
        {
            return m_data[pos];
        }

        constexpr const_reference operator[](size_type pos) const
        {
            return m_data[pos];
        }

        constexpr pointer data() noexcept
        {
            return m_data;
        }
        constexpr const_pointer data() const noexcept
        {
            return m_data;
        }

        [[nodiscard]] constexpr size_type size() const noexcept
        {
            return N;
        }

        constexpr T* begin() noexcept
        {
            return m_data;
        }
        constexpr const T* begin() const noexcept
        {
            return m_data;
        }
        constexpr const T* cbegin() const noexcept
        {
            return m_data;
        }

        constexpr T* end() noexcept
        {
            return m_data + N;
        }
        constexpr const T* end() const noexcept
        {
            return m_data + N;
        }
        constexpr const T* cend() const noexcept
        {
            return m_data + N;
        }

    private:
        T m_data[N];
    };
} // namespace rx::util

enum class ThreadInfoClass : int
{
    ThreadQuerySetWin32StartAddress = 9
};

enum class ProcessInfoClass : int
{
    ProcessModules = 11
};

extern "C"
{
    NTSTATUS ZwQueryInformationThread(_In_ HANDLE ThreadHandle, _In_ ThreadInfoClass ThreadInformationClass, _Out_ PVOID ThreadInformation, _In_ ULONG ThreadInformationLength,
                                      _Out_opt_ PULONG ReturnLength);

    NTSTATUS ZwQueryInformationProcess(_In_ HANDLE ProcessHandle, _In_ ProcessInfoClass ProcessInformationClass, _Out_ PVOID ProcessInformation,
                                       _In_ ULONG ProcessInformationLength, _Out_opt_ PULONG ReturnLength);

    NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);

    NTSTATUS MmCopyVirtualMemory(PEPROCESS FromProcess, PVOID FromAddress, PEPROCESS ToProcess, PVOID ToAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
                                 PSIZE_T NumberOfBytesCopied);

    NTSYSAPI NTSTATUS NTAPI ZwOpenThread(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess, _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ PCLIENT_ID ClientId);
    NTKERNELAPI NTSTATUS PsAcquireProcessExitSynchronization(_In_ PEPROCESS Process);

    NTKERNELAPI VOID PsReleaseProcessExitSynchronization(_In_ PEPROCESS Process);
}

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    PVOID Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    _Field_size_(NumberOfModules) RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

inline void* operator new(size_t size, POOL_TYPE pool, ULONG tag)
{
    return ExAllocatePoolWithTag(pool, size, tag);
}
inline void operator delete(void* p)
{
    if (p)
        ExFreePoolWithTag(p, rx::util::POOL_TAG);
}
inline void operator delete(void* p, size_t size)
{
    UNREFERENCED_PARAMETER(size);
    if (p)
        ExFreePoolWithTag(p, rx::util::POOL_TAG);
}
