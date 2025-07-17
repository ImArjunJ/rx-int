#pragma once
#define NOMINMAX
#include <Windows.h>

#include <string>

#include "Common.hpp"
#include "Ioctl.hpp"

class Driver
{
public:
    Driver();
    ~Driver();

    bool IsLoaded() const;

    bool StartMonitoring(unsigned long pid, const std::wstring& dumpPath);
    bool StopMonitoring();

    bool GetStatus(DriverState& state);
    bool GetMemoryStats(RXINT_MEMORY_STATS& stats);

private:
    HANDLE m_hDevice;
};