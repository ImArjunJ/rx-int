#include "Driver.hpp"

#include "Ioctl.hpp"

Driver::Driver()
{
    m_hDevice = CreateFileW(RXINT_SYMBOLIC_LINK, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

Driver::~Driver()
{
    if (m_hDevice != INVALID_HANDLE_VALUE)
    {
        CloseHandle(m_hDevice);
    }
}

bool Driver::IsLoaded() const
{
    return m_hDevice != INVALID_HANDLE_VALUE;
}

bool Driver::StartMonitoring(unsigned long pid, const std::wstring& dumpPath)
{
    if (!IsLoaded())
        return false;

    RXINT_MONITOR_INFO info = {0};
    info.ProcessId = pid;
    wcscpy_s(info.DumpPath, _countof(info.DumpPath), dumpPath.c_str());
    MessageBoxW(NULL, info.DumpPath, L"Dump Path", MB_OK);

    DWORD bytesReturned = 0;
    return DeviceIoControl(m_hDevice, IOCTL_RXINT_START_MONITORING, &info, sizeof(info), NULL, 0, &bytesReturned, NULL);
}

bool Driver::StopMonitoring()
{
    if (!IsLoaded())
        return false;
    DWORD bytesReturned = 0;
    return DeviceIoControl(m_hDevice, IOCTL_RXINT_STOP_MONITORING, NULL, 0, NULL, 0, &bytesReturned, NULL);
}

bool Driver::GetStatus(DriverState& state)
{
    if (!IsLoaded())
    {
        state.Status = DriverStatus::NotLoaded;
        return false;
    }

    RXINT_STATUS_INFO info = {0};
    DWORD bytesReturned = 0;

    if (DeviceIoControl(m_hDevice, IOCTL_RXINT_GET_STATUS, NULL, 0, &info, sizeof(info), &bytesReturned, NULL) && bytesReturned == sizeof(info))
    {
        if (info.IsMonitoring)
        {
            state.Status = DriverStatus::Monitoring;
            state.MonitoredPid = info.MonitoredPid;
        }
        else
        {
            state.Status = DriverStatus::Idle;
            state.MonitoredPid = 0;
        }
        return true;
    }

    state.Status = DriverStatus::NotLoaded;
    return false;
}