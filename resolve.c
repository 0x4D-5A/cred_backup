#include "resolve.h"

static ULONG_PTR pebAddress;
static LdrLoadDll_ pLdrLoadDll;

HMODULE hNtdll = NULL;

HMODULE WINAPI ImageBaseAddress(void)
{
    return (HMODULE)(ULONG_PTR)((_PPEB)pebAddress)->lpImageBaseAddress;
}

static DWORD64 djb2(PBYTE str) /* cse.yorku.ca/~oz/hash.html */
{
    DWORD64 hash = DJB2_KEY;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c;

    return hash;
}

static DWORD64 w_djb2(PWSTR str)
{
    DWORD64 hash = DJB2_KEY;
    int c;

    while (c = *str++) {

        // lowercase
        if (c >= 'A' && c <= 'Z')
            c += 0x20;

        hash = ((hash << 5) + hash) + c;
    }
 
    return hash;
}

HMODULE WINAPI ModuleBaseAddress(const DWORD64 dwModuleName)
{
    PLDR_DATA_TABLE_ENTRY pLdrEntry;
    PLIST_ENTRY pListHead, pListEntry;
    HMODULE hModule = NULL;
    PPEB_LDR_DATA pLdrData;
    _PPEB pPEB;

    do {

        if (!pebAddress) {
            #ifdef _M_X64
                        pebAddress = __readgsqword(0x60);
            #elif _M_IX86
                        pebAddress = __readfsdword(0x30);
            #endif
        }

        if (!pebAddress)
            break;

        pPEB = (_PPEB)pebAddress;
        pLdrData = pPEB->pLdr;

        pListHead = &(pLdrData->InLoadOrderModuleList);
        pListEntry = pListHead->Flink;

        while (pListHead != pListEntry) {

            pLdrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if (dwModuleName == w_djb2(pLdrEntry->BaseDllName.Buffer)) {
                hModule = (HMODULE)pLdrEntry->DllBase;
                break;
            }

            //Next entry
            pListEntry = pListEntry->Flink;
        }

    } while (FALSE);

    return hModule;
}

HMODULE WINAPI LdrLoadDll(LPWSTR lpLibFileName, const BOOL bAllreadyLoaded)
{
    HMODULE hModule = NULL;
    UNICODE_STRING pModuleFileName;
    unsigned int cbLibFileName;

    do {

        if (bAllreadyLoaded) {
            hModule = ModuleBaseAddress(w_djb2(lpLibFileName));
            if (hModule)
                break;
        }

        cbLibFileName = wcslen(lpLibFileName);
        if (!cbLibFileName)
            break;

        pModuleFileName.Buffer = lpLibFileName;
        pModuleFileName.Length = (USHORT)(cbLibFileName * sizeof(WCHAR));
        pModuleFileName.MaximumLength = pModuleFileName.Length + sizeof(WCHAR);

        if (pLdrLoadDll(NULL, 0, &pModuleFileName, &hModule) != ERROR_SUCCESS)
            hModule = NULL;

    } while (FALSE);

    return hModule;
}


FARPROC WINAPI resolve_function(const HMODULE hModule, const DWORD64 dwProcName) 
{
    PIMAGE_DOS_HEADER image_dos_header;
    PIMAGE_NT_HEADERS image_nt_headers;
    PIMAGE_EXPORT_DIRECTORY image_export_directory;
    PCHAR fwFunction, fwFunctionName = NULL;
    PDWORD dwExportName, dwFuncAddress;
    LPVOID FuncAddress = NULL;
    DWORD i, cbFwFunction, cbForwardedLibName;
    HMODULE hForwarded;
    PBYTE lpFuncName;
    PWORD wOrdinals;

    char szForwardedLibraryName[256];
    wchar_t wLibraryname[256 * sizeof(WCHAR)];

    do {

        image_dos_header = (PIMAGE_DOS_HEADER)hModule;
        if (image_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
            break;
        
        image_nt_headers = (PIMAGE_NT_HEADERS)((PCHAR)hModule + image_dos_header->e_lfanew);
        if (image_nt_headers->Signature != IMAGE_NT_SIGNATURE)
            break;

        image_export_directory = (PIMAGE_EXPORT_DIRECTORY)((PCHAR)hModule + image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        if ((!image_export_directory->NumberOfFunctions) || image_export_directory->NumberOfFunctions > 4096)
            break;
        
        //Resolve functions exported by name
        dwExportName = (PDWORD)(image_export_directory->AddressOfNames + (PCHAR)hModule);
        wOrdinals = (PWORD)(image_export_directory->AddressOfNameOrdinals + (PCHAR)hModule);
        dwFuncAddress = (PDWORD)(image_export_directory->AddressOfFunctions + (PCHAR)hModule);

        for (i = 0; i < image_export_directory->NumberOfNames; i++) {
            lpFuncName = (PBYTE)(dwExportName[i] + (PCHAR)hModule);

            if (djb2(lpFuncName) == dwProcName) {
                FuncAddress = (FARPROC)((PCHAR)hModule + dwFuncAddress[wOrdinals[i]]);
                break;
            }
        }

        if (!FuncAddress)
            break;

        //Handle forwarded functions
        fwFunction = (PCHAR)FuncAddress;
        
        cbFwFunction = (DWORD)strlen(fwFunction) + 1;
        if (cbFwFunction >= 256)
            break;

        memcpy(szForwardedLibraryName, fwFunction, cbFwFunction);

        for (i = 0; i < cbFwFunction; i++)
        {
            if (szForwardedLibraryName[i] == '.')
            {
                szForwardedLibraryName[i] = 0x0;
                fwFunctionName = &(fwFunction[i + 1]);
                break;
            }
        }

        if (!fwFunctionName) //Function not forwarded
            break;
     
        //Convert LibraryName to wchar
        cbForwardedLibName = i;

        for (i = 0; i < cbForwardedLibName; i++)
        {
            wLibraryname[i] = szForwardedLibraryName[i];
        }
        wLibraryname[cbForwardedLibName] = 0x0;

        wcscat(wLibraryname, L".dll");

        hForwarded = LdrLoadDll(wLibraryname, TRUE);
        if (!hForwarded) {
            FuncAddress = NULL;
            break;
        }

        FuncAddress = resolve_function(hForwarded, djb2(fwFunctionName));

    } while (FALSE);

    return FuncAddress;
}

BOOL bInitResolve(void)
{
    BOOL bRet = FALSE;

    do {

        hNtdll = ModuleBaseAddress(0x377D2B522D3B5ED); //ntdll.dll
        if (!hNtdll)
            break;

        pLdrLoadDll = (LdrLoadDll_)resolve_function(hNtdll, 0x726C7A370307DB23); //LdrLoadDll
        if (!pLdrLoadDll)
            break;

        bRet = TRUE;
    } while (FALSE);

    return bRet;
}
