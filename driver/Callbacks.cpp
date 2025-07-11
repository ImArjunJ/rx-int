#include "Callbacks.hpp"

rx::Detector* rx::g_Detector = nullptr;

namespace rx
{

    void OnProcessNotifyEx(PEPROCESS Process, HANDLE Pid, PPS_CREATE_NOTIFY_INFO Info)
    {
        if (g_Detector)
        {
            g_Detector->OnProcessNotify(Process, Pid, Info);
        }
    }

    void OnThreadNotifyEx(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
    {
        if (g_Detector)
        {
            g_Detector->OnThreadNotify(ProcessId, ThreadId, Create);
        }
    }
} // namespace rx