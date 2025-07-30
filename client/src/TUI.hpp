#pragma once
#include <windows.h>

#include <string>

#include "Common.hpp"
#include "Driver.hpp"
#include "Injector.hpp"
#include "Ioctl.hpp"

class TUI
{
public:
    TUI();
    ~TUI();
    void Run();

private:
    void ProcessInput();
    void UpdateState();
    void Render();

    void ClearBuffer();
    void DrawString(int x, int y, const std::wstring& str, WORD attributes);
    void DrawMenuItem(int y, char key, const std::wstring& text);

    void RenderMainMenu();
    void RenderAttachMenu();
    void RenderInjectionMenu();

    void HandleMainMenuInput(const KEY_EVENT_RECORD& keyEvent);
    void HandleAttachInput(const KEY_EVENT_RECORD& keyEvent);
    void HandleInjectionInput(const KEY_EVENT_RECORD& keyEvent);

private:
    HANDLE m_hConsole;
    HANDLE m_hInput;
    CHAR_INFO* m_backBuffer;
    COORD m_bufferSize;
    bool m_isRunning;

    DriverState m_driverState;
    RXINT_MEMORY_STATS m_memStats;
    std::wstring m_inputBuffer;
    std::wstring m_inputBuffer2; // second input field (dump path)
    std::wstring m_currentMessage;

    enum class UIState
    {
        MainMenu,
        AttachGetPid,
        AttachGetDumpPath,
        Injection,
        InjectionSubmenu
    };
    UIState m_uiState;
    InjectionMethod m_injectionMethod;
    Driver m_driver;
};