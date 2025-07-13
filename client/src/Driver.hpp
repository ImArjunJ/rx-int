#pragma once
#define NOMINMAX
#include <Windows.h>

#include <string>

#include "Common.hpp"

class Driver
{
public:
    Driver();
    ~Driver();

    bool IsLoaded() const;

    bool StartMonitoring(unsigned long pid, const std::wstring& dumpPath);
    bool StopMonitoring();

    bool GetStatus(DriverState& state);

private:
    HANDLE m_hDevice;
};