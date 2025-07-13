#pragma once
#include <Windows.h>

#include <string>

enum class InjectionMethod
{
    ClassicRwx,
    StagedRwRx,
    ManualMapErase,
    QueueUserApc,
    ModuleStomp
};

class Injector
{
public:
    static bool Inject(unsigned long pid, InjectionMethod method, std::string& outMessage);
};