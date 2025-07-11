#include "Detector.hpp"

namespace rx
{
    void OnProcessNotifyEx(PEPROCESS Process, HANDLE Pid, PPS_CREATE_NOTIFY_INFO Info);
    void OnThreadNotifyEx(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create);
} // namespace rx