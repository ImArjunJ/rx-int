#include <windows.h>

#include <iostream>

int main()
{
    std::cout << "--- Dummy Target Process ---\n";
    std::cout << "PID: " << GetCurrentProcessId() << "\n";
    std::cout << "Waiting for injection. This window will remain open.\n";
    std::cout << "Press Enter in this window to exit cleanly.\n";

    // Wait indefinitely until the user presses Enter.
    std::cin.get();

    return 0;
}