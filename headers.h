#include <windows.h>
#include <winnt.h>
#include <tlhelp32.h>
#include <cstring>
#include <iostream>
#include <processthreadsapi.h>
#include <winternl.h>
#include <ntstatus.h>
#include <psapi.h>
#include <dbghelp.h>
#include <winnt.h>
#include <stdlib.h>
#include <shlwapi.h>
#include <iostream>
#include <iomanip>
#include <string>




//ntdll library is needed to use NtQueryInformationProcess
#pragma comment(lib, "ntdll.lib") 
//imagehelp library is needed to use ImageNtHeader
#pragma comment(lib, "imagehlp.lib")

//Shlwapi.lib library is needed to use PathFindFileNameW
#pragma comment(lib, "Shlwapi.lib") 