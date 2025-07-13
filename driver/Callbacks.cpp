#include "Callbacks.hpp"

rx::Detector* rx::g_Detector = nullptr;

namespace rx
{
    void OnThreadNotifyEx(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
    {
        if (g_Detector)
        {
            g_Detector->OnThreadNotify(ProcessId, ThreadId, Create);
        }
    }
} // namespace rx