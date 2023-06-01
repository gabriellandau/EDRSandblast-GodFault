#pragma once

#include <Windows.h>

HANDLE GetDriverHandle_GodFault();
VOID CloseDriverHandle_GodFault();
VOID WriteMemoryPrimitive_GodFault(SIZE_T Size, DWORD64 Address, PVOID Buffer);
VOID ReadMemoryPrimitive_GodFault(SIZE_T Size, DWORD64 Address, PVOID Buffer);
