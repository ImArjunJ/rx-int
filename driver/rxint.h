#pragma once

#include <ntifs.h>
#include <ntstrsafe.h>

NTKERNELAPI
NTSTATUS
PsLookupThreadByThreadId(_In_ HANDLE ThreadId, _Out_ PETHREAD* Thread);

NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Out_ PEPROCESS* Process);

NTKERNELAPI
NTSTATUS
PsAcquireProcessExitSynchronization(_In_ PEPROCESS Process);

NTKERNELAPI
VOID PsReleaseProcessExitSynchronization(_In_ PEPROCESS Process);

NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);

typedef NTSTATUS (*PsGetThreadStartAddress_t)(PETHREAD, PVOID*);

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject);
VOID OnProcessNotifyEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
VOID OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create);
BOOLEAN IsSuspiciousRegion(HANDLE pid, PVOID addr);
VOID DumpPages(HANDLE pid, PVOID base);

NTSTATUS
MmCopyVirtualMemory(PEPROCESS FromProcess, PVOID FromAddress, PEPROCESS ToProcess, PVOID ToAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T NumberOfBytesCopied);
