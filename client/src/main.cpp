#include <iostream>

#include "TUI.hpp"

int main()
{
    try
    {
        TUI client;
        client.Run();
    }
    catch (const std::exception& e)
    {
        HANDLE h_out = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(h_out, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::cerr << "\n\nFATAL ERROR: " << e.what() << std::endl;
        return 1;
    }
    catch (...)
    {
        HANDLE h_out = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(h_out, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::cerr << "\n\nAn unknown fatal error occurred." << std::endl;
        return 1;
    }
    return 0;
}