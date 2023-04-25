#include"headers.h"
#include "functions.h"

int main() {

    while (true) {
        string processName = "";

        cout << "Enter the process name, i.e. notepad.exe" << endl;
        cout << endl << "Process name: ";
        cin >> processName;

        wstring WprocessName(processName.begin(), processName.end());
        const wchar_t* WprocessNameptr = WprocessName.c_str();

        DWORD pid = GetProcessIdByName(WprocessNameptr);

        if (!(pid == 0)) {

            cout << endl << "PID: " << pid << endl;

            PrintPEB(pid);
            PEparser(pid);

            cout << endl << endl;
        }
        else {
            cout << endl << "no PID found for the entered process name, make sure to run the corresponding program first, then try again, if not the case check the spelling" << endl;
        }
    }

    return 0;
}
