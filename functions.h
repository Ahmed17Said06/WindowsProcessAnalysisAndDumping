#include"headers.h"
using namespace std;

DWORD GetProcessIdByName(const wchar_t* name);
HANDLE GetProcessHandle(DWORD pid);
void PrintPEB(DWORD pid);
DWORD RVAToOffset(PIMAGE_DOS_HEADER pDosHeader, DWORD dwRVA);
void PEparser(DWORD pid);