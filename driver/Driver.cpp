#include "Callbacks.hpp"
#include "Detector.hpp"

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] DriverEntry started.\n");

    rx::g_Detector = new (NonPagedPool, rx::util::POOL_TAG) rx::Detector();
    if (!rx::g_Detector)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    rx::g_Detector->Start();

    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(rx::OnProcessNotifyEx, FALSE);
    if (!NT_SUCCESS(status))
    {
        delete rx::g_Detector;
        rx::g_Detector = nullptr;
        return status;
    }

    status = PsSetCreateThreadNotifyRoutine(rx::OnThreadNotifyEx);
    if (!NT_SUCCESS(status))
    {
        PsSetCreateProcessNotifyRoutineEx(rx::OnProcessNotifyEx, TRUE);
        delete rx::g_Detector;
        rx::g_Detector = nullptr;
        return status;
    }

    DriverObject->DriverUnload = [](PDRIVER_OBJECT)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] Unload routine called.\n");
        if (rx::g_Detector)
        {
            PsRemoveCreateThreadNotifyRoutine(rx::OnThreadNotifyEx);
            PsSetCreateProcessNotifyRoutineEx(rx::OnProcessNotifyEx, TRUE);
            rx::g_Detector->Stop();
            delete rx::g_Detector;
            rx::g_Detector = nullptr;
        }
    };

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] Driver loaded successfully.\n");
    return STATUS_SUCCESS;
}