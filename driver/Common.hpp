#pragma once

#include "Memory.hpp"
#include "xxhash.h"


#define THREAD_QUERY_INFORMATION (0x0040)
#define MEM_IMAGE 0x01000000

namespace rx
{
    struct ModuleRange
    {
        PVOID BaseAddress;
        SIZE_T Size;
        wchar_t Path[260];
    };

    namespace util
    {
        inline wchar_t DUMP_PATH[260] = L"\\SystemRoot\\Temp\\dump_%llu.bin";
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

    } // namespace util
} // namespace rx

namespace rx::pe
{
#define IMAGE_DOS_SIGNATURE 0x5A4D    // MZ
#define IMAGE_NT_SIGNATURE 0x00004550 // PE00
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_DLL 0x2000

// Section Characteristics
#define IMAGE_SCN_CNT_CODE 0x00000020
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_WRITE 0x80000000

    typedef struct _IMAGE_DOS_HEADER
    {
        USHORT e_magic;
        USHORT e_cblp;
        USHORT e_cp;
        USHORT e_crlc;
        USHORT e_cparhdr;
        USHORT e_minalloc;
        USHORT e_maxalloc;
        USHORT e_ss;
        USHORT e_sp;
        USHORT e_csum;
        USHORT e_ip;
        USHORT e_cs;
        USHORT e_lfarlc;
        USHORT e_ovno;
        USHORT e_res[4];
        USHORT e_oemid;
        USHORT e_oeminfo;
        USHORT e_res2[10];
        LONG e_lfanew;
    } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

    typedef struct _IMAGE_FILE_HEADER
    {
        USHORT Machine;
        USHORT NumberOfSections;
        ULONG TimeDateStamp;
        ULONG PointerToSymbolTable;
        ULONG NumberOfSymbols;
        USHORT SizeOfOptionalHeader;
        USHORT Characteristics;
    } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

    typedef struct _IMAGE_DATA_DIRECTORY
    {
        ULONG VirtualAddress;
        ULONG Size;
    } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

    typedef struct _IMAGE_OPTIONAL_HEADER64
    {
        USHORT Magic;
        UCHAR MajorLinkerVersion;
        UCHAR MinorLinkerVersion;
        ULONG SizeOfCode;
        ULONG SizeOfInitializedData;
        ULONG SizeOfUninitializedData;
        ULONG AddressOfEntryPoint;
        ULONG BaseOfCode;
        ULONGLONG ImageBase;
        ULONG SectionAlignment;
        ULONG FileAlignment;
        USHORT MajorOperatingSystemVersion;
        USHORT MinorOperatingSystemVersion;
        USHORT MajorImageVersion;
        USHORT MinorImageVersion;
        USHORT MajorSubsystemVersion;
        USHORT MinorSubsystemVersion;
        ULONG Win32VersionValue;
        ULONG SizeOfImage;
        ULONG SizeOfHeaders;
        ULONG CheckSum;
        USHORT Subsystem;
        USHORT DllCharacteristics;
        ULONGLONG SizeOfStackReserve;
        ULONGLONG SizeOfStackCommit;
        ULONGLONG SizeOfHeapReserve;
        ULONGLONG SizeOfHeapCommit;
        ULONG LoaderFlags;
        ULONG NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

    typedef struct _IMAGE_NT_HEADERS64
    {
        ULONG Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

    typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;
    typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
    typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;

    typedef struct _IMAGE_SECTION_HEADER
    {
        UCHAR Name[8];
        union
        {
            ULONG PhysicalAddress;
            ULONG VirtualSize;
        } Misc;
        ULONG VirtualAddress;
        ULONG SizeOfRawData;
        ULONG PointerToRawData;
        ULONG PointerToRelocations;
        ULONG PointerToLinenumbers;
        USHORT NumberOfRelocations;
        USHORT NumberOfLinenumbers;
        ULONG Characteristics;
    } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

    typedef struct _IMAGE_EXPORT_DIRECTORY
    {
        DWORD Characteristics;
        DWORD TimeDateStamp;
        unsigned short MajorVersion;
        unsigned short MinorVersion;
        DWORD Name;
        DWORD Base;
        DWORD NumberOfFunctions;
        DWORD NumberOfNames;
        DWORD AddressOfFunctions;    // RVA from base of image
        DWORD AddressOfNames;        // RVA from base of image
        DWORD AddressOfNameOrdinals; // RVA from base of image
    } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

#define IMAGE_FIRST_SECTION(ntheader) \
    ((pe::PIMAGE_SECTION_HEADER)((ULONG_PTR) (ntheader) + FIELD_OFFSET(pe::IMAGE_NT_HEADERS, OptionalHeader) + ((ntheader))->FileHeader.SizeOfOptionalHeader))
} // namespace rx::pe

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

    NTSTATUS NTAPI ZwProtectVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _Inout_ PSIZE_T RegionSize, _In_ ULONG NewProtect, _Out_ PULONG OldProtect);
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

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAware : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

inline void* operator new(size_t size, POOL_TYPE pool, ULONG tag)
{
    return rx::mem::Allocate(pool, size, tag);
}
inline void operator delete(void* p)
{
    if (p)
        rx::mem::Free(p, rx::util::POOL_TAG);
}
inline void operator delete(void* p, size_t size)
{
    UNREFERENCED_PARAMETER(size);
    if (p)
        rx::mem::Free(p, rx::util::POOL_TAG);
}
