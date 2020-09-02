#pragma once
#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

/*   Redefine CLIENT_ID to avoid conflict   */
typedef struct _CLIENT_ID_R
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID_R, *PCLIENT_ID_R;

NTSTATUS NTAPI LdrGetDllHandle ( 	
    IN PWSTR           DllPath OPTIONAL,
	IN PULONG          DllCharacteristics OPTIONAL,
	IN PUNICODE_STRING DllName,
	OUT PVOID *  	   DllHandle );

NTSTATUS NTAPI LdrGetProcedureAddress(
    IN PVOID  	    BaseAddress,
	IN PANSI_STRING Name,
	IN ULONG  	    Ordinal,
	OUT PVOID *     ProcedureAddress ); 	

NTSTATUS NtOpenProcess(
    OUT PHANDLE           ProcessHandle,
    IN ACCESS_MASK        DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID_R       ClientId OPTIONAL
);

NTSTATUS NtCreateSection(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle
);

NTSTATUS NtMapViewOfSection(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID           *BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    int             InheritDisposition, // Made this an int to save finding the definition
    ULONG           AllocationType,
    ULONG           Win32Protect
);

NTSTATUS NtUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID  BaseAddress
);

NTSTATUS NtCreateThreadEx(
    OUT PHANDLE               hThread,
    IN ACCESS_MASK            DesiredAccess,
    IN LPVOID                 ObjectAttributes,
    IN HANDLE                 ProcessHandle,
    IN LPTHREAD_START_ROUTINE lpStartAddress,
    IN LPVOID                 lpParameter,
    IN BOOL                   CreateSuspended,
    IN ULONG                  StackZeroBits,
    IN ULONG                  SizeOfStackCommit,
    IN ULONG                  SizeOfStackReserve,
    OUT LPVOID                lpBytesBuffer
);

// NTSTATUS NtQueueApcThread(
//     HANDLE          ThreadHandle,
//     PIO_APC_ROUTINE ApcRoutine,
//     PVOID           NormalContext,
//     PVOID           SystemArgument1,
//     PVOID           SystemArgument2 
// );

NTSTATUS NtQueueApcThread(
    HANDLE           ThreadHandle, 
    PIO_APC_ROUTINE  ApcRoutine, 
    PVOID            ApcRoutineContext OPTIONAL, 
    PIO_STATUS_BLOCK ApcStatusBlock OPTIONAL, 
    ULONG            ApcReserved OPTIONAL
);

NTAPI NtAlertResumeThread(
    IN HANDLE ThreadHandle,
    OUT PULONG SuspendCount
);

/*   Find the address of a loaded module by name   */
UINT_PTR FindDLLAddress(wchar_t* searchDLL) {

	PPEB Peb = NULL;
	PPEB_LDR_DATA Loader = NULL;
	PLIST_ENTRY Head = NULL;
	PLIST_ENTRY Current = NULL;

	// Get PEB address from GS:0x60 register
	Peb = (PPEB)__readgsqword(0x60);

	// PPEB_LDR_DATA contains information about the loaded modules for the process
	Loader = (PPEB_LDR_DATA)(PBYTE)Peb->Ldr;

	// The head of a doubly-linked list that contains the loaded modules for the process
	Head = &Loader->InMemoryOrderModuleList;

	Current = Head->Flink;

	do {
		// Retrieve address of InMemoryOrderLinks from Current, casted to PLDR_DATA_TABLE_ENTRY, using CONTAINING_RECORD macro
		PLDR_DATA_TABLE_ENTRY dllEntry = CONTAINING_RECORD(Current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		// Get the full DLL path as Unicode string
		wchar_t* dllName = (wchar_t*)dllEntry->FullDllName.Buffer;

		// Get the module base address
		UINT_PTR dllAddress = (UINT_PTR)dllEntry->DllBase;

		// Check if current DLL matches search DLL
		wchar_t* result = wcsstr(dllName, searchDLL);

		if (result != NULL)
		{
			return dllAddress;
		}

		// Move to the next module
		Current = Current->Flink;
	} while (Current != Head);
    printf( "[!] Failed to find %ws!\n", searchDLL );

	return 0;
}