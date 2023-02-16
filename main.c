#include "global.h"
#include "credman.h"

HANDLE hHeap = NULL;
HANDLE StdHandle = NULL;

extern HeapCreate_ pHeapCreate;
extern HeapDestroy_ pHeapDestroy;
extern ExitProcess_ pExitProcess;

#define ws_stdout L"stdout"

int __cdecl main()
{
    WCHAR ws_Message[MAX_PATH * sizeof(WCHAR)];
    LPWSTR* szArglist = NULL;
    LPWSTR lpAppName, lpSaveTo;
    DWORD dwCharsWritten;

    int nArgs;

    do {

        szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
        if (!szArglist)
            break;

        StdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!StdHandle)
            break;

        SetConsoleOutputCP(CP_UTF8);

        lpAppName = szArglist[0];

        if (nArgs != 2) {
            wcscpy(ws_Message, L"Usage:\n");
            wcscat(ws_Message, lpAppName);
            wcscat(ws_Message, L" stdout/file\n\nExample:\n");

            wcscat(ws_Message, lpAppName);
            wcscat(ws_Message, L" stdout\n");

            wcscat(ws_Message, lpAppName);
            wcscat(ws_Message, L" log.txt");

            WriteConsoleW(StdHandle, ws_Message, wcslen(ws_Message), &dwCharsWritten, NULL);
            break;
        }

        lpSaveTo = szArglist[1];
        
        if (wcsncmp(lpSaveTo, ws_stdout, wcslen(ws_stdout)) == 0)
            lpSaveTo = NULL;

        if (!bResolveFunctions())
            break;

        hHeap = pHeapCreate(0, 0x10000, 0);
        if (!hHeap)
            break;

        doBackup(lpSaveTo);

    } while (FALSE);

    if (szArglist)
        LocalFree(szArglist);

    if (hHeap) {
        pHeapDestroy(hHeap);
        pExitProcess(0);
    }
      
    return 0;
}

