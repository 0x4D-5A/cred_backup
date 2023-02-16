#pragma once
#include <Windows.h>
#if !defined(_DEBUG)
#define MINICRT_BUILD
#endif
#include "minicrt\minicrt.h"

typedef struct __UNICODE_STRING_
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;

typedef LPVOID (WINAPI* HeapAlloc_)(
     HANDLE hHeap,
     DWORD  dwFlags,
     SIZE_T dwBytes
);

typedef LPVOID (WINAPI* HeapReAlloc_)(
     HANDLE                 hHeap,
     DWORD                  dwFlags,
     LPVOID lpMem,
     SIZE_T                 dwBytes
);

typedef BOOL (WINAPI* HeapFree_)(
     HANDLE                 hHeap,
     DWORD                  dwFlags,
     LPVOID lpMem
);

typedef HANDLE (WINAPI* HeapCreate_)(
    DWORD  flOptions,
    SIZE_T dwInitialSize,
    SIZE_T dwMaximumSize
);

typedef BOOL (WINAPI* HeapDestroy_)(
    HANDLE hHeap
);

typedef void (WINAPI* ExitProcess_)(
    UINT uExitCode
);

extern HeapAlloc_ pHeapAlloc;
extern HeapReAlloc_ pHeapReAlloc;
extern HeapFree_ pHeapFree;

#define MemAlloc(Size)					pHeapAlloc(hHeap, HEAP_ZERO_MEMORY, Size);
#define MemReAlloc(Buffer, NewSize)		pHeapReAlloc(hHeap, HEAP_ZERO_MEMORY, Buffer, NewSize)
#define MemFree(Buffer)					pHeapFree(hHeap, 0, Buffer);
