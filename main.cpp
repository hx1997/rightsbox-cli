#include <iostream>
#include <windows.h>

#include "Dispatcher.h"

int main() {
    SetConsoleTitle(L"RightsBox");
    DispatchRoutineEntry();
    return 0;
}