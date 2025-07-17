#pragma once
#include <windows.h>

#include <array>
#include <string>


enum class InjectionMethod
{
    ClassicRwx,
    StagedRwRx,
    QueueUserApc,
    ModuleStomp,
    VadEvasion,
    VadEvasionPuts
};

constexpr std::array<BYTE, 4> BENIGN_SHELLCODE = {0x48, 0x31, 0xC0, 0xC3};
struct PutsPayloadData
{
    using pPuts = int(WINAPIV*)(const char*);
    pPuts fnPuts;
    char message[128];
};

class Injector
{
public:
    static bool Inject(unsigned long pid, InjectionMethod method, std::string& outMessage);
};