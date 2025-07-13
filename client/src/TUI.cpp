#include "TUI.hpp"

#include <windows.h>

#include "Driver.hpp"

TUI::TUI() : m_isRunning(true), m_uiState(UIState::MainMenu), m_hConsole(INVALID_HANDLE_VALUE), m_hInput(INVALID_HANDLE_VALUE), m_backBuffer(nullptr)
{
    m_hConsole = CreateConsoleScreenBuffer(GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CONSOLE_TEXTMODE_BUFFER, NULL);
    m_hInput = GetStdHandle(STD_INPUT_HANDLE);
    SetConsoleActiveScreenBuffer(m_hConsole);
    SetConsoleMode(m_hInput, ENABLE_EXTENDED_FLAGS | ENABLE_WINDOW_INPUT);

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(m_hConsole, &csbi);
    m_bufferSize = csbi.dwSize;

    m_backBuffer = new CHAR_INFO[m_bufferSize.X * m_bufferSize.Y];
    SetConsoleTitleW(L"RX-INT Control");

    CONSOLE_CURSOR_INFO cursorInfo = {1, FALSE};
    SetConsoleCursorInfo(m_hConsole, &cursorInfo);
}

TUI::~TUI()
{
    if (m_backBuffer)
        delete[] m_backBuffer;
    if (m_hConsole != INVALID_HANDLE_VALUE)
        CloseHandle(m_hConsole);
}

void TUI::Run()
{
    MainLoop();
}

void TUI::MainLoop()
{
    while (m_isRunning)
    {
        UpdateState();
        ProcessInput();
        Render();
        Sleep(16);
    }
}

void TUI::ProcessInput()
{
    DWORD numEvents = 0;
    if (!GetNumberOfConsoleInputEvents(m_hInput, &numEvents) || numEvents == 0)
        return;

    INPUT_RECORD record[1];
    DWORD numRead;
    if (ReadConsoleInput(m_hInput, record, 1, &numRead) && numRead > 0)
    {
        if (record[0].EventType == KEY_EVENT && record[0].Event.KeyEvent.bKeyDown)
        {
            switch (m_uiState)
            {
            case UIState::MainMenu:
                HandleMainMenuInput(record[0].Event.KeyEvent);
                break;
            case UIState::AttachGetPid:
            case UIState::AttachGetDumpPath:
                HandleAttachInput(record[0].Event.KeyEvent);
                break;
            case UIState::Injection:
                HandleInjectionInput(record[0].Event.KeyEvent);
                break;
            case UIState::InjectionSubmenu:
                HandleInjectionInput(record[0].Event.KeyEvent);
                break;
            }
        }
    }
}

void TUI::UpdateState()
{
    Driver driver;
    driver.GetStatus(m_driverState);
}

void TUI::Render()
{
    ClearBuffer();

    std::wstring status_text;
    WORD status_color = 0x0F;
    switch (m_driverState.Status)
    {
    case DriverStatus::NotLoaded:
        status_text = L"Driver Inactive";
        status_color = FOREGROUND_RED | FOREGROUND_INTENSITY;
        break;
    case DriverStatus::Idle:
        status_text = L"Idle";
        status_color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        break;
    case DriverStatus::Monitoring:
        status_text = L"Monitoring PID " + std::to_wstring(m_driverState.MonitoredPid);
        status_color = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        break;
    }
    DrawMenuItem(1, '+', L"rx-int - ");
    DrawString(14, 1, status_text, status_color);

    switch (m_uiState)
    {
    case UIState::MainMenu:
        RenderMainMenu();
        break;
    case UIState::AttachGetPid:
    case UIState::AttachGetDumpPath:
        RenderAttachMenu();
        break;
    case UIState::Injection:
        RenderInjectionMenu();
        break;
    case UIState::InjectionSubmenu:
        RenderInjectionMenu();
        break;
    }

    DrawString(1, m_bufferSize.Y - 2, m_currentMessage, 0x07);

    SMALL_RECT writeRegion = {0, 0, static_cast<SHORT>(m_bufferSize.X - 1), static_cast<SHORT>(m_bufferSize.Y - 1)};
    WriteConsoleOutputW(m_hConsole, m_backBuffer, m_bufferSize, {0, 0}, &writeRegion);
}

void TUI::ClearBuffer()
{
    for (int i = 0; i < m_bufferSize.X * m_bufferSize.Y; ++i)
    {
        m_backBuffer[i].Char.UnicodeChar = L' ';
        m_backBuffer[i].Attributes = 0x00;
    }
}

void TUI::DrawString(int x, int y, const std::wstring& str, WORD attributes)
{
    if (y >= m_bufferSize.Y || x >= m_bufferSize.X)
        return;
    for (size_t i = 0; i < str.length(); ++i)
    {
        int offset = x + (int) i + y * m_bufferSize.X;
        if (x + (int) i < m_bufferSize.X)
        {
            m_backBuffer[offset].Char.UnicodeChar = str[i];
            m_backBuffer[offset].Attributes = attributes;
        }
    }
}

void TUI::DrawMenuItem(int y, char key, const std::wstring& text)
{
    DrawString(1, y, L"[", 0x0F);
    DrawString(2, y, std::wstring(1, key), 0x0B);
    DrawString(3, y, L"] " + text, 0x0F);
}

void TUI::RenderMainMenu()
{
    std::wstring attachText = (m_driverState.Status == DriverStatus::Monitoring) ? L"Detach from Process" : L"Attach to Process";

    DrawMenuItem(3, '1', L"Injection Suite");
    DrawMenuItem(4, '2', attachText);
    DrawMenuItem(5, '3', L"Exit");

    DrawString(1, m_bufferSize.Y - 3, L"Select an option using the number keys...", 0x08);
}

void TUI::RenderInjectionMenu()
{
    DrawString(1, 3, L"--- Injection Suite ---", 0x0B);

    if (m_uiState == UIState::Injection)
    {
        DrawMenuItem(5, '1', L"Classic RWX Injection");
        DrawMenuItem(6, '2', L"Staged RW->RX Injection");
        DrawMenuItem(7, '3', L"Manual Map (Header Erase)");
        DrawMenuItem(8, '4', L"Threadless (QueueUserAPC)");
        DrawMenuItem(9, '5', L"Module Stomping (Not Implemented)");
        DrawString(1, 11, L"[ESC] Return to Main Menu", 0x08);
        m_currentMessage = L"Select injection type...";
    }
    else
    {
        std::wstring methodText = (m_injectionMethod == InjectionMethod::ClassicRwx) ? L"Classic RWX" : L"Staged RW->RX";
        DrawString(1, 3, L"--- Injecting: " + methodText + L" ---", 0x0B);
        DrawString(1, 5, L"Enter Target PID, then press ENTER:", 0x0F);
        DrawString(1, 6, L"> " + m_inputBuffer, 0x0B);
    }
}

void TUI::HandleMainMenuInput(const KEY_EVENT_RECORD& keyEvent)
{
    m_currentMessage.clear();
    switch (keyEvent.uChar.AsciiChar)
    {
    case '1':
        m_uiState = UIState::Injection;
        m_inputBuffer.clear();
        break;
    case '2':
        if (m_driverState.Status == DriverStatus::Monitoring)
        {
            Driver d;
            d.StopMonitoring();
            UpdateState();
        }
        else
        {
            m_uiState = UIState::AttachGetPid;
        }
        m_inputBuffer.clear();
        break;
    case '3':
        m_isRunning = false;
        break;
    }
}

void TUI::RenderAttachMenu()
{
    if (m_uiState == UIState::AttachGetPid)
    {
        DrawString(1, 3, L"Enter PID to monitor, then press ENTER:", 0x0F);
        DrawString(1, 4, L"> " + m_inputBuffer, 0x0B);
    }
    else
    {
        DrawString(1, 3, L"Enter PID to monitor: " + m_inputBuffer, 0x07); // Show the entered PID in gray
        DrawString(1, 4, L"Enter dump path format (or blank for default), then press ENTER:", 0x0F);
        DrawString(1, 5, L"> " + m_inputBuffer2, 0x0B);
    }
    DrawString(1, 7, L"[ESC] Return to Main Menu", 0x08);
}
#include <iostream>
void TUI::HandleAttachInput(const KEY_EVENT_RECORD& keyEvent)
{
    if (keyEvent.wVirtualKeyCode == VK_ESCAPE)
    {
        m_uiState = UIState::MainMenu;
        m_inputBuffer.clear();
        m_inputBuffer2.clear();
        return;
    }

    if (m_uiState == UIState::AttachGetPid)
    {
        if (keyEvent.wVirtualKeyCode == VK_RETURN)
        {
            if (m_inputBuffer.empty())
            {
                m_currentMessage = L"PID cannot be empty.";
                return;
            }
            m_uiState = UIState::AttachGetDumpPath;
        }
        else if (keyEvent.wVirtualKeyCode == VK_BACK && !m_inputBuffer.empty())
        {
            m_inputBuffer.pop_back();
        }
        else if (isprint(static_cast<unsigned char>(keyEvent.uChar.AsciiChar)))
        {
            m_inputBuffer += keyEvent.uChar.AsciiChar;
        }
    }
    else
    {
        if (keyEvent.wVirtualKeyCode == VK_RETURN)
        {
            try
            {
                unsigned long pid = std::stoul(m_inputBuffer);

                std::wstring dumpPath = m_inputBuffer2;

                if (dumpPath.empty())
                {
                    dumpPath = L"\\SystemRoot\\Temp\\dump_%llu.bin";
                }

                Driver driver;
                if (driver.StartMonitoring(pid, dumpPath))
                {
                    m_driverState.Status = DriverStatus::Monitoring;
                    m_driverState.MonitoredPid = pid;
                    m_currentMessage = L"Successfully attached to PID " + std::to_wstring(pid);
                }
                else
                {
                    m_currentMessage = L"Failed to start monitoring PID " + std::to_wstring(pid) + L". (Is driver loaded? Is the PID correct?)";
                }

                m_uiState = UIState::MainMenu;
                m_inputBuffer.clear();
                m_inputBuffer2.clear();
            }
            catch (...)
            {
                m_inputBuffer.clear();
                m_inputBuffer2.clear();
                m_currentMessage = L"Invalid PID entered.";
                m_uiState = UIState::MainMenu;
            }
        }
        else if (keyEvent.wVirtualKeyCode == VK_BACK && !m_inputBuffer2.empty())
        {
            m_inputBuffer2.pop_back();
        }
        else if (isprint(static_cast<unsigned char>(keyEvent.uChar.AsciiChar)))
        {
            m_inputBuffer2 += keyEvent.uChar.AsciiChar;
        }
    }
}

void TUI::HandleInjectionInput(const KEY_EVENT_RECORD& keyEvent)
{
    if (keyEvent.wVirtualKeyCode == VK_ESCAPE)
    {
        m_uiState = UIState::MainMenu;
        m_inputBuffer.clear();
        return;
    }

    if (m_uiState == UIState::Injection)
    {
        switch (keyEvent.uChar.AsciiChar)
        {
        case '1':
            m_injectionMethod = InjectionMethod::ClassicRwx;
            m_uiState = UIState::InjectionSubmenu;
            break;
        case '2':
            m_injectionMethod = InjectionMethod::StagedRwRx;
            m_uiState = UIState::InjectionSubmenu;
            break;
        case '3':
            m_injectionMethod = InjectionMethod::ManualMapErase;
            m_uiState = UIState::InjectionSubmenu;
            break;
        case '4':
            m_injectionMethod = InjectionMethod::QueueUserApc;
            m_uiState = UIState::InjectionSubmenu;
            break;
        case '5':
            m_injectionMethod = InjectionMethod::ModuleStomp;
            m_uiState = UIState::InjectionSubmenu;
            break;
        }
        m_inputBuffer.clear();
    }
    else if (m_uiState == UIState::InjectionSubmenu)
    {
        if (keyEvent.wVirtualKeyCode == VK_RETURN)
        {
            if (m_inputBuffer.empty())
            {
                m_currentMessage = L"PID cannot be empty.";
                m_uiState = UIState::MainMenu;
                return;
            }
            try
            {
                unsigned long pid = std::stoul(m_inputBuffer);
                std::string resultMsg;
                Injector::Inject(pid, m_injectionMethod, resultMsg);
                m_currentMessage.assign(resultMsg.begin(), resultMsg.end());
                m_uiState = UIState::MainMenu;
                m_inputBuffer.clear();
            }
            catch (...)
            {
                m_inputBuffer.clear();
                m_currentMessage = L"Invalid PID.";
                m_uiState = UIState::MainMenu;
            }
        }
        else if (keyEvent.wVirtualKeyCode == VK_BACK && !m_inputBuffer.empty())
        {
            m_inputBuffer.pop_back();
        }
        else if (isprint(static_cast<unsigned char>(keyEvent.uChar.AsciiChar)))
        {
            m_inputBuffer += keyEvent.uChar.AsciiChar;
        }
    }
}