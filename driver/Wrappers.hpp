#pragma once

#include "Common.hpp"

namespace rx::util
{
    class SpinLockGuard
    {
    public:
        explicit SpinLockGuard(PKSPIN_LOCK lock) : m_lock(lock)
        {
            KeAcquireSpinLock(m_lock, &m_oldIrql);
        }
        ~SpinLockGuard()
        {
            KeReleaseSpinLock(m_lock, m_oldIrql);
        }
        SpinLockGuard(const SpinLockGuard&) = delete;
        SpinLockGuard& operator=(const SpinLockGuard&) = delete;

    private:
        PKSPIN_LOCK m_lock;
        KIRQL m_oldIrql;
    };

    class FastMutexGuard
    {
    public:
        explicit FastMutexGuard(PFAST_MUTEX mutex) : m_mutex(mutex)
        {
            ExAcquireFastMutex(m_mutex);
        }
        ~FastMutexGuard()
        {
            ExReleaseFastMutex(m_mutex);
        }
        FastMutexGuard(const FastMutexGuard&) = delete;
        FastMutexGuard& operator=(const FastMutexGuard&) = delete;

    private:
        PFAST_MUTEX m_mutex;
    };

    class ProcessAttacher
    {
    public:
        explicit ProcessAttacher(PEPROCESS process) : m_process(process)
        {
            if (m_process)
                KeStackAttachProcess(m_process, &m_apcState);
        }
        ~ProcessAttacher()
        {
            if (m_process)
                KeUnstackDetachProcess(&m_apcState);
        }
        ProcessAttacher(const ProcessAttacher&) = delete;
        ProcessAttacher& operator=(const ProcessAttacher&) = delete;

    private:
        PEPROCESS m_process;
        KAPC_STATE m_apcState;
    };

    class ProcessReference
    {
    public:
        explicit ProcessReference(HANDLE pid) : m_process(nullptr)
        {
            if (pid)
                PsLookupProcessByProcessId(pid, &m_process);
        }
        ~ProcessReference()
        {
            if (m_process)
                ObDereferenceObject(m_process);
        }
        PEPROCESS get() const
        {
            return m_process;
        }
        operator bool() const
        {
            return m_process != nullptr;
        }
        ProcessReference(const ProcessReference&) = delete;
        ProcessReference& operator=(const ProcessReference&) = delete;

    private:
        PEPROCESS m_process;
    };
} // namespace rx::util