# WindowsProcessAnalysisAndDumping
A Windows process memory parser that opens a running process i.e. “notepad.exe” or any .exe and parse the .exe PEB data structure and extract the PEB fields.


In Windows operating systems, a process is a running instance of a program. Each process has its own virtual address space, which is isolated from other processes. The Process Environment Block (PEB) is a data structure used by Windows to store information about a process. The PEB contains a variety of data, including the process's environment variables, command line arguments, and module handles. The PEB is used by the Windows loader to set up the process's initial state, and it can be accessed by the process itself to retrieve information about its own execution context. The PEB is an important data structure for understanding how Windows processes work, and it is often used in malware analysis and reverse engineering.
 
In the demo develop a Windows process memory parser that opens a running process i.e. “notepad.exe” or any .exe and parse the .exe PEB data structure and extract the PEB fields.
In order to  access “notepad.exe” find the process Id (PID) and get a handle to it using Windows API “OpenProcess” or you can traverse the Windows process list using the APIs “CreateToolhelp32Snapshot”, Process32First and Process32Next to find our “notepad.exe” process.
Once you get a handle to “notepad.exe”
	• Print the basic information of "notepad.exe" process from the PEB data structure.
	• Parse the “notepad.exe” Portable Executable Header in memory and extract the NT and DOS headers and exported/import functions. Research the following data structure that contains this information such as PIMAGE_NT_HEADERS.  PIMAGE_EXPORT_DIRECTORY and PIMAGE_DOS_HEADER
	• Use the PEB to find the base address of loaded “kernel32.dll” and all other Dlls loaded by “notepad.exe”. You need to iterate through data structures internal to the Windows loader such as PTEB, PLIST_ENTRY, PEB_LDR_DATA and LDR_DATA_TABLE_ENTRY. >>> https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#process_basic_information
 
API documentation:
	1. https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
	2. https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data#remarks
	3. https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
	4. https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory
  5. https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
