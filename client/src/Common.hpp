#pragma once

enum class DriverStatus
{
    NotLoaded,
    Idle,
    Monitoring
};

struct DriverState
{
    DriverStatus Status = DriverStatus::NotLoaded;
    unsigned long MonitoredPid = 0;
};