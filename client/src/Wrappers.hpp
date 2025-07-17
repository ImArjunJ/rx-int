// clang-format off
#include <windows.h>
#include <TlHelp32.h>
#include <winternl.h>
// clang-format on

#include <format>
#include <string>

namespace
{
    typedef LONG NTSTATUS;

    using f_NtCreateSection = NTSTATUS(NTAPI*)(OUT PHANDLE SectionHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
                                               IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG SectionPageAttributes, IN ULONG AllocationAttributes,
                                               IN HANDLE FileHandle OPTIONAL);

    using f_NtMapViewOfSection = NTSTATUS(NTAPI*)(IN HANDLE SectionHandle, IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG_PTR ZeroBits, IN SIZE_T CommitSize,
                                                  IN OUT PLARGE_INTEGER SectionOffset OPTIONAL, IN OUT PSIZE_T ViewSize, IN ULONG InheritDisposition, IN ULONG AllocationType,
                                                  IN ULONG Win32Protect);

    using f_NtUnmapViewOfSection = NTSTATUS(NTAPI*)(IN HANDLE ProcessHandle, IN PVOID BaseAddress);

    constexpr ULONG ViewUnmap = 2;

} // namespace

class SafeHandle
{
public:
    SafeHandle(HANDLE handle = INVALID_HANDLE_VALUE) : m_handle(handle)
    {
    }
    ~SafeHandle()
    {
        if (isValid())
        {
            CloseHandle(m_handle);
        }
    }

    SafeHandle(const SafeHandle&) = delete;
    SafeHandle& operator=(const SafeHandle&) = delete;

    SafeHandle(SafeHandle&& other) noexcept : m_handle(other.m_handle)
    {
        other.m_handle = INVALID_HANDLE_VALUE;
    }
    SafeHandle& operator=(SafeHandle&& other) noexcept
    {
        if (this != &other)
        {
            if (isValid())
            {
                CloseHandle(m_handle);
            }
            m_handle = other.m_handle;
            other.m_handle = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    operator HANDLE() const
    {
        return m_handle;
    }
    HANDLE get() const
    {
        return m_handle;
    }
    bool isValid() const
    {
        return m_handle != INVALID_HANDLE_VALUE && m_handle != NULL;
    }

private:
    HANDLE m_handle;
};

class RemoteMemory
{
public:
    RemoteMemory(HANDLE process, LPVOID address, SIZE_T size) : m_process(process), m_address(address), m_size(size)
    {
    }
    ~RemoteMemory()
    {
        if (m_process && m_address)
        {
            VirtualFreeEx(m_process, m_address, 0, MEM_RELEASE);
        }
    }

    RemoteMemory(const RemoteMemory&) = delete;
    RemoteMemory& operator=(const RemoteMemory&) = delete;

    RemoteMemory(RemoteMemory&& other) noexcept : m_process(other.m_process), m_address(other.m_address), m_size(other.m_size)
    {
        other.m_process = nullptr;
        other.m_address = nullptr;
    }
    RemoteMemory& operator=(RemoteMemory&& other) noexcept
    {
        if (this != &other)
        {
            if (m_process && m_address)
            {
                VirtualFreeEx(m_process, m_address, 0, MEM_RELEASE);
            }
            m_process = other.m_process;
            m_address = other.m_address;
            m_size = other.m_size;
            other.m_process = nullptr;
            other.m_address = nullptr;
        }
        return *this;
    }

    LPVOID get() const
    {
        return m_address;
    }
    SIZE_T size() const
    {
        return m_size;
    }
    bool isValid() const
    {
        return m_address != nullptr;
    }

private:
    HANDLE m_process;
    LPVOID m_address;
    SIZE_T m_size;
};

inline std::string format_win32_error(const std::string& function_name, DWORD error_code)
{
    return std::format("{0} failed. win32 error: {1}", function_name, error_code);
}

inline DWORD FindFirstThread(DWORD pid)
{
    SafeHandle hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!hSnap.isValid())
        return 0;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hSnap, &te32))
    {
        do {
            if (te32.th32OwnerProcessID == pid)
            {
                return te32.th32ThreadID;
            }
        } while (Thread32Next(hSnap, &te32));
    }
    return 0;
}

inline bool GetRemoteModuleInfo(const SafeHandle& hProc, const std::wstring& moduleName, MODULEENTRY32W& outModuleInfo)
{
    DWORD pid = GetProcessId(hProc.get());
    SafeHandle hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
    if (!hSnap.isValid())
    {
        return false;
    }

    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(hSnap, &me32))
    {
        do {
            if (_wcsicmp(me32.szModule, moduleName.c_str()) == 0)
            {
                outModuleInfo = me32;
                return true;
            }
        } while (Module32NextW(hSnap, &me32));
    }
    return false;
}