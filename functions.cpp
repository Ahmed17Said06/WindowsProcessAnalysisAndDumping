//https://learn.microsoft.com/en-us/windows/win32/toolhelp/process-walking
//https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
//https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
//https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32
//https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
//https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next
//https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
//https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
//https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
//https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmodulefilenameexa
//https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
//https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfilesize
//https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
//https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
//https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-imagentheader
//https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile

#include"headers.h"
using namespace std;

DWORD GetProcessIdByName(const wchar_t* name)
{
    // Take a snapshot of the current system state
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    // Iterate over the running processes in the snapshot
    PROCESSENTRY32 process;
    process.dwSize = sizeof(process);
    BOOL success = Process32First(snapshot, &process);
    DWORD pid = 0;

    while (success) {
        // Check if the process name matches the target name
        if (_wcsicmp(process.szExeFile, name) == 0) {
            // Found the target process, get its PID
            pid = process.th32ProcessID;
            break;
        }

        // Move on to the next process in the snapshot
        success = Process32Next(snapshot, &process);
    }

    // Clean up the snapshot handle
    CloseHandle(snapshot);

    return pid;
}

HANDLE GetProcessHandle(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);

    if (hProcess == NULL) {
        printf("Failed to open process (error %lu)\n", GetLastError());
        exit;
    }

    return hProcess;

}

void PrintPEB(DWORD pid)
{
    HANDLE hProcess = GetProcessHandle(pid);

    PROCESS_BASIC_INFORMATION pbi{};
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);

    if (status != STATUS_SUCCESS) {
        printf("Failed to query process information (error %lu)\n", status);
        CloseHandle(hProcess);
        exit;
    }

    PEB peb;
    SIZE_T bytesRead;
    BOOL success = ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead);

    if (!success || bytesRead != sizeof(peb)) {
        printf("Failed to read PEB (error %lu)\n", GetLastError());
        CloseHandle(hProcess);
        exit;
    }

    // Print PEB members
    cout << endl << "PEB Members:" << endl;


    bool InheritedAddressSpace = (peb.Reserved1[0] != 0);
    if (InheritedAddressSpace) {
        cout << "  InheritedAddressSpace: " << "Yes" << endl;
    }
    else {
        cout << "  InheritedAddressSpace: " << "No" << endl;
    }

    bool ReadImageFileExecOptions = (peb.Reserved1[1] != 0);
    if (ReadImageFileExecOptions) {
        cout << "  ReadImageFileExecOptions: " << "Yes" << endl;
    }
    else {
        cout << "  ReadImageFileExecOptions: " << "No" << endl;
    }

    if (peb.BeingDebugged) {
        cout << "  BeingDebugged: " << "yes" << endl;
    }
    else {
        cout << "  BeingDebugged: " << "No" << endl;
    }

    cout << "  ImageBaseAddress: " << peb.Reserved3[1] << endl;

    cout << "  Ldr: " << peb.Ldr << endl;

    cout << "  ProcessParameters: " << peb.ProcessParameters << endl;

    cout << "  SessionId: " << peb.SessionId << endl;



    cout << endl << "DLLs Base Address:" << endl;
    // Traverse the linked list of loaded modules to print its base address
    PEB_LDR_DATA* ldrData = peb.Ldr;
    if (!ldrData) {
        cerr << "Failed to get LdrData" << endl;
        exit;
    }

    LDR_DATA_TABLE_ENTRY* ldrEntry = NULL;
    for (LIST_ENTRY* pListEntry = ldrData->InMemoryOrderModuleList.Flink; pListEntry != &ldrData->InMemoryOrderModuleList; pListEntry = pListEntry->Flink) {
        // Get the LDR_DATA_TABLE_ENTRY structure for each module
        ldrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (!ldrEntry) {
            cerr << "Failed to get LdrEntry" << endl;
            exit;
        }

        // Print the module name and base address    
        wcout << "   " << left << setw(20) << PathFindFileNameW(ldrEntry->FullDllName.Buffer) << "     -      " << ldrEntry->DllBase << endl;
    }

    CloseHandle(hProcess);
}

DWORD RVAToOffset(PIMAGE_DOS_HEADER pDosHeader, DWORD dwRVA) {

    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((LPBYTE)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
    DWORD i, dwSectionSize, dwSectionVA, dwSectionOffset;

    for (i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++, pSectionHeader++) {
        dwSectionSize = pSectionHeader->Misc.VirtualSize;
        dwSectionVA = pSectionHeader->VirtualAddress;
        dwSectionOffset = pSectionHeader->PointerToRawData;

        if (dwRVA >= dwSectionVA && dwRVA < (dwSectionVA + dwSectionSize)) {
            return (dwSectionOffset + (dwRVA - dwSectionVA));
        }
    }

    return 0;
}

void PEparser(DWORD pid)
{
    HANDLE hProcess = GetProcessHandle(pid);

    // Get the full path of the executable file that started the process
    TCHAR filename[MAX_PATH];
    if (GetModuleFileNameEx(hProcess, NULL, filename, MAX_PATH) > 0)
    {
        wcout << endl << "Executable file path: " << filename << endl;
    }
    else
    {
        cerr << endl << "Failed to get the executable file path" << endl;
    }
    // Open the executable file
    HANDLE hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Error: failed to open file\n");
        exit;
    }
    // Allocate memory to hold the contents of the file
    LPVOID lpFileData = VirtualAlloc(NULL, GetFileSize(hFile, NULL), MEM_COMMIT, PAGE_READWRITE);
    if (lpFileData == NULL)
    {
        printf("Error: failed to allocate memory\n");
        CloseHandle(hFile);
        exit;
    }
    // Read the contents of the file into the allocated memory
    DWORD dwBytesRead;
    if (!ReadFile(hFile, lpFileData, GetFileSize(hFile, NULL), &dwBytesRead, NULL))
    {
        printf("Error: failed to read file\n");
        VirtualFree(lpFileData, 0, MEM_RELEASE);
        CloseHandle(hFile);
        exit;
    }

    // Get a pointer to the image DOS header in memory
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileData;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("Error: invalid DOS header\n");
        UnmapViewOfFile(lpFileData);
        CloseHandle(lpFileData);
        CloseHandle(hFile);
        exit;
    }
    // Print some information about the DOS header
    printf("\nPE DOS Header:\n");
    printf("  e_magic      DOS Signature:                  %04X\n", pDosHeader->e_magic);
    printf("  e_cblp       Bytes on Last Page:             %04X\n", pDosHeader->e_cblp);
    printf("  e_cp         Pages in File:                  %04X\n", pDosHeader->e_cp);
    printf("  e_crlc       Relocations:                    %04X\n", pDosHeader->e_crlc);
    printf("  e_cparhdr    Paragraphs in Header:           %04X\n", pDosHeader->e_cparhdr);
    printf("  e_minalloc   Minimum Extra Paragraphs:       %04X\n", pDosHeader->e_minalloc);
    printf("  e_maxalloc   Maximum Extra Paragraphs:       %04X\n", pDosHeader->e_maxalloc);
    printf("  e_ss         Initial SS Value:               %04X\n", pDosHeader->e_ss);
    printf("  e_sp         Initial SP Value:               %04X\n", pDosHeader->e_sp);
    printf("  e_csum       Checksum:                       %04X\n", pDosHeader->e_csum);
    printf("  e_ip         Initial IP Value:               %04X\n", pDosHeader->e_ip);
    printf("  e_cs         Initial CS Value:               %04X\n", pDosHeader->e_cs);
    printf("  e_lfarlc     File Address of Reloc Table:    %04X\n", pDosHeader->e_lfarlc);
    printf("  e_ovno       Overlay Number:                 %04X\n", pDosHeader->e_ovno);
    printf("  e_oemid      OEM Identifier:                 %04X\n", pDosHeader->e_oemid);
    printf("  e_oeminfo    OEM Info:                       %04X\n", pDosHeader->e_oeminfo);
    printf("  e_lfanew     File Address of New Exe Header: %08X\n", pDosHeader->e_lfanew);


    // Get a pointer to the image header in memory
    PIMAGE_NT_HEADERS pNtHeader = ImageNtHeader(lpFileData);
    if (pNtHeader == NULL)
    {
        printf("Error: invalid file format\n");
        VirtualFree(lpFileData, 0, MEM_RELEASE);
        CloseHandle(hFile);
        exit;
    }

    // Print file signature
    printf("\nPE File Signature:              %08X\n", pNtHeader->Signature);
    // Print file header
    printf("\nPE File Header:\n");
    printf("  Machine:                      %04X\n", pNtHeader->FileHeader.Machine);
    printf("  Number of Sections:           %04X\n", pNtHeader->FileHeader.NumberOfSections);
    printf("  Time Stamp:                   %08X\n", pNtHeader->FileHeader.TimeDateStamp);
    printf("  Pointer to Symbol Directory:  %08X\n", pNtHeader->FileHeader.PointerToSymbolTable);
    printf("  Number of Symbols:            %08X\n", pNtHeader->FileHeader.NumberOfSymbols);
    printf("  Size of Optional Header:      %04X\n", pNtHeader->FileHeader.SizeOfOptionalHeader);
    printf("  Characteristics:              %04X\n", pNtHeader->FileHeader.Characteristics);

    // Print optional header
    printf("\nPE Optional Header:\n");
    printf("  Magic:                        %04X\n", pNtHeader->OptionalHeader.Magic);
    printf("  Linker Version:               %02X.%02X\n", pNtHeader->OptionalHeader.MajorLinkerVersion, pNtHeader->OptionalHeader.MinorLinkerVersion);
    printf("  Size of Code:                 %08X\n", pNtHeader->OptionalHeader.SizeOfCode);
    printf("  Size of Initialized Data:     %08X\n", pNtHeader->OptionalHeader.SizeOfInitializedData);
    printf("  Size of Uninitialized Data:   %08X\n", pNtHeader->OptionalHeader.SizeOfUninitializedData);
    printf("  Entry Point Address:          %08X\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
    printf("  Base of Code:                 %08X\n", pNtHeader->OptionalHeader.BaseOfCode);
    printf("  Image Base:                   %016llX\n", pNtHeader->OptionalHeader.ImageBase);
    printf("  Section Alignment:            %08X\n", pNtHeader->OptionalHeader.SectionAlignment);
    printf("  File Alignment:               %08X\n", pNtHeader->OptionalHeader.FileAlignment);
    printf("  Operating System Version:     %04X.%04X\n", pNtHeader->OptionalHeader.MajorOperatingSystemVersion, pNtHeader->OptionalHeader.MinorOperatingSystemVersion);
    printf("  Image Version:                %04X.%04X\n", pNtHeader->OptionalHeader.MajorImageVersion, pNtHeader->OptionalHeader.MinorImageVersion);
    printf("  Subsystem Version:            %04X.%04X\n", pNtHeader->OptionalHeader.MajorSubsystemVersion, pNtHeader->OptionalHeader.MinorSubsystemVersion);
    printf("  Win32 Version Value:          %08X\n", pNtHeader->OptionalHeader.Win32VersionValue);
    printf("  Size of Image:                %08X\n", pNtHeader->OptionalHeader.SizeOfImage);
    printf("  Size of Headers:              %08X\n", pNtHeader->OptionalHeader.SizeOfHeaders);
    printf("  Checksum:                     %08X\n", pNtHeader->OptionalHeader.CheckSum);
    printf("  Subsystem:                    %04X\n", pNtHeader->OptionalHeader.Subsystem);
    printf("  DLL Characteristics:          %04X\n", pNtHeader->OptionalHeader.DllCharacteristics);
    printf("  Size of Stack Reserve:        %016llX\n", pNtHeader->OptionalHeader.SizeOfStackReserve);
    printf("  Size of Stack Commit:         %016llX\n", pNtHeader->OptionalHeader.SizeOfStackCommit);
    printf("  Size of Heap Reserve:         %016llX\n", pNtHeader->OptionalHeader.SizeOfHeapReserve);
    printf("  Size of Heap Commit:          %016llX\n", pNtHeader->OptionalHeader.SizeOfHeapCommit);
    printf("  Loader Flags:                 %08X\n", pNtHeader->OptionalHeader.LoaderFlags);
    printf("  Number of RVA and Sizes:      %08X\n", pNtHeader->OptionalHeader.NumberOfRvaAndSizes);

    // Print Data Directories
    printf("  Data Directories:\n");
    printf("    Export Directory RVA:            %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    printf("    Export Directory Size:           %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
    printf("    Import Directory RVA:            %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    printf("    Import Directory Size:           %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
    printf("    Resource Directory RVA:          %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
    printf("    Resource Directory Size:         %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
    printf("    Exception Directory RVA:         %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
    printf("    Exception Directory Size:        %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);
    printf("    Security Directory RVA:          %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress);
    printf("    Security Directory Size:         %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
    printf("    Base Relocation Directory RVA:   %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    printf("    Base Relocation Directory Size:  %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
    printf("    Debug Directory RVA:             %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
    printf("    Debug Directory Size:            %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
    printf("    Architecture-Specific Data RVA:  %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress);
    printf("    Architecture-Specific Data Size: %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size);
    printf("    Global Pointer Register RVA:     %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress);
    printf("    Global Pointer Register Size:    %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size);
    printf("    TLS Directory RVA:               %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    printf("    TLS Directory Size:              %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);
    printf("    Configuration Directory RVA:     %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
    printf("    Configuration Directory Size:    %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size);
    printf("    Bound Import Directory RVA:      %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress);
    printf("    Bound Import Directory Size:     %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size);
    printf("    Import Address Directory RVA:    %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
    printf("    Import Address Directory Size:   %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
    printf("    Delay Import Directory RVA:      %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
    printf("    Delay Import Directory Size:     %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size);
    printf("    .Net MetaData Directory RVA:     %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress);
    printf("    .Net MetaData Directory Size:    %08X\n", pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size);


    // Export directory
    // get a pointer to the Export Directory
    DWORD exportDirRVA = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportDirOffset = RVAToOffset(pDosHeader, exportDirRVA);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)pDosHeader + exportDirOffset);

    // print the Export Directory information
    if (exportDirOffset == 0)
    {
        printf("\nThis PE doesn't have Export Directory\n");
    }
    else {
        printf("\nExport Directory Information:\n");
        printf("  Characteristics:       %08X\n", pExportDir->Characteristics);
        printf("  TimeDateStamp:         %08X\n", pExportDir->TimeDateStamp);
        printf("  MajorVersion:          %04X\n", pExportDir->MajorVersion);
        printf("  MinorVersion:          %04X\n", pExportDir->MinorVersion);
        printf("  Name:                  %08X\n", pExportDir->Name);
        printf("  Base:                  %08X\n", pExportDir->Base);
        printf("  NumberOfFunctions:     %08X\n", pExportDir->NumberOfFunctions);
        printf("  NumberOfNames:         %08X\n", pExportDir->NumberOfNames);
        printf("  AddressOfFunctions:    %08X\n", pExportDir->AddressOfFunctions);
        printf("  AddressOfNames:        %08X\n", pExportDir->AddressOfNames);
        printf("  AddressOfNameOrdinals: %08X\n", pExportDir->AddressOfNameOrdinals);

    }
    // Close the process handle
    VirtualFree(lpFileData, 0, MEM_RELEASE);
    CloseHandle(hFile);
    CloseHandle(hProcess);

}
