#include "Callbacks.hpp"
#include "Detector.hpp"
#include "Ioctl.hpp"

NTSTATUS RxInt_DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    rx::g_Detector = new (NonPagedPool, rx::util::POOL_TAG) rx::Detector();
    if (!rx::g_Detector)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    rx::g_Detector->Start();

    PDEVICE_OBJECT pDeviceObject = nullptr;
    UNICODE_STRING devName = RTL_CONSTANT_STRING(RXINT_DEVICE_NAME);
    NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
    if (!NT_SUCCESS(status))
    {
        delete rx::g_Detector;
        rx::g_Detector = nullptr;
        return status;
    }

    UNICODE_STRING symLink = RTL_CONSTANT_STRING(RXINT_SYMBOLIC_LINK);
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(pDeviceObject);
        delete rx::g_Detector;
        rx::g_Detector = nullptr;
        return status;
    }

    status = PsSetCreateThreadNotifyRoutine(rx::OnThreadNotifyEx);
    if (!NT_SUCCESS(status))
    {
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(pDeviceObject);
        delete rx::g_Detector;
        rx::g_Detector = nullptr;
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = [](PDEVICE_OBJECT, PIRP Irp)
    {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    };
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RxInt_DeviceControl;

    DriverObject->DriverUnload = [](PDRIVER_OBJECT DriverObject)
    {
        UNICODE_STRING symLink = RTL_CONSTANT_STRING(RXINT_SYMBOLIC_LINK);
        IoDeleteSymbolicLink(&symLink);

        PsRemoveCreateThreadNotifyRoutine(rx::OnThreadNotifyEx);

        if (rx::g_Detector)
        {
            rx::g_Detector->Stop();
            delete rx::g_Detector;
            rx::g_Detector = nullptr;
        }

        IoDeleteDevice(DriverObject->DeviceObject);
    };

    return STATUS_SUCCESS;
}

NTSTATUS RxInt_DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR bytesIO = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_RXINT_START_MONITORING:
    {
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(RXINT_MONITOR_INFO))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        auto* info = (PRXINT_MONITOR_INFO) Irp->AssociatedIrp.SystemBuffer;
        info->DumpPath[259] = L'\0';
        bool valid = true;
        size_t len = wcsnlen(info->DumpPath, 259);
        if (len == 0 || len > 255)
            valid = false;
        if (wcsstr(info->DumpPath, L"%llu") == nullptr)
            valid = false;
        if (!valid)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] ioctl: invalid DumpPath %ls\n", info->DumpPath);
            wcsncpy(rx::util::DUMP_PATH, L"\\SystemRoot\\Temp\\dump_%llu.bin", 259);
            rx::util::DUMP_PATH[259] = L'\0';
        }
        else
        {
            wcsncpy(rx::util::DUMP_PATH, info->DumpPath, 259);
            rx::util::DUMP_PATH[259] = L'\0';
        }
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] ioctl: started monitoring for pid %lu @ %ls\n", info->ProcessId, info->DumpPath);
        rx::g_Detector->StartMonitoringProcess(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(info->ProcessId)));
        break;
    }

    case IOCTL_RXINT_STOP_MONITORING:
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RX-INT] ioctl: stopped monitoring\n");
        rx::g_Detector->StopMonitoringProcess();
        break;
    }
    case IOCTL_RXINT_GET_STATUS:
    {
        if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(RXINT_STATUS_INFO))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        auto* outBuffer = (PRXINT_STATUS_INFO) Irp->AssociatedIrp.SystemBuffer;

        rx::g_Detector->GetCurrentStatus(outBuffer);

        bytesIO = sizeof(RXINT_STATUS_INFO);
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesIO;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}