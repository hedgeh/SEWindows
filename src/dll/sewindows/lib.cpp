#include "stdafx.h"
#include "lib.h"
#include <atlstr.h>
#include <tlhelp32.h>
#include <strsafe.h>
#include <Fltuser.h>

#ifndef PSAPI_VERSION
#define PSAPI_VERSION 1
#endif
#include <psapi.h>

#pragma comment(lib,"Psapi.lib")
#pragma comment(lib,"Advapi32.lib") 
#pragma comment(lib,"User32.lib")
#pragma comment(lib,"fltLib.lib")

#pragma warning(disable : 4996)

static ACCESS_MASK ProcessQueryAccess;
static ACCESS_MASK ProcessAllAccess;
static ACCESS_MASK ThreadQueryAccess;
static ACCESS_MASK ThreadSetAccess;
static ACCESS_MASK ThreadAllAccess;
static ULONG		WindowsVersion;
static fn_NtQuerySystemInformation		NtQuerySystemInformation = NULL;
static fn_NtQueryInformationProcess		NtQueryInformationProcess = NULL;
static fn_RtlConvertSidToUnicodeString  RtlConvertSidToUnicodeString = NULL;

static FILE_PATH_TABLE					g_file_path_table[26];
static REG_PATH_TABLE					g_reg_path_table[5];

FORCEINLINE PVOID get_proc_address(
	_In_ PWSTR LibraryName,
	_In_ PSTR ProcName
	)
{
	HMODULE module;

	module = GetModuleHandle(LibraryName);

	if (module)
		return GetProcAddress(module, ProcName);
	else
		return NULL;
}

BOOLEAN get_windows_directory(WCHAR* windows_path)
{
	WCHAR temp_path[MAX_PATH];
	WCHAR cDiskSymbol[] = L"c:";
	if (!GetWindowsDirectoryW(temp_path, MAX_PATH))
	{
		return FALSE;
	}
	cDiskSymbol[0] = temp_path[0];

	if (!QueryDosDeviceW(cDiskSymbol, temp_path, MAX_PATH))
	{
		return FALSE;
	}
	if (temp_path[wcslen(temp_path) - 1] == L'\\')
	{
		temp_path[wcslen(temp_path) - 1] = L'\0';
	}
	wcscpy_s(windows_path, MAX_PATH, temp_path);
	return TRUE;
}

BOOLEAN build_file_path_table()
{
	RtlZeroMemory(&g_file_path_table, sizeof(FILE_PATH_TABLE)* 26);

	WCHAR drv = 0;
	WCHAR cDiskSymbol[] = _T("A:");
	TCHAR szBuf[MAX_PATH] = { 0 };

	for (drv = _T('A'); drv <= _T('Z'); drv++)
	{
		cDiskSymbol[0] = drv;
		if (!QueryDosDevice(cDiskSymbol, szBuf, MAX_PATH))
		{
			continue;
		}
		wcscpy(g_file_path_table[drv - 'A'].dos_name, cDiskSymbol);
		wcscpy(g_file_path_table[drv - 'A'].nt_name, szBuf);
	}
	return TRUE;
}



BOOLEAN register_get_user_sid(WCHAR* sz_user_name)
{
	HANDLE			hToken = NULL;
	BOOLEAN			bResult = FALSE;
	DWORD			dwSize = 0;
	PTOKEN_USER		pTokenUser = NULL;
	UNICODE_STRING	stringSid;
	WCHAR			stringSidBuffer[MAX_PATH];
	NTSTATUS		status;
	__try
	{
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		{
			bResult = FALSE;
			__leave;
		}

		if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize))
		{
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			{
				bResult = FALSE;
				__leave;
			}
		}
		pTokenUser = (PTOKEN_USER)malloc(dwSize);
		if (pTokenUser == NULL)
		{
			bResult = FALSE;
			__leave;
		}

		if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize))
		{
			bResult = FALSE;
			__leave;
		}

		stringSid.Buffer = stringSidBuffer;
		stringSid.MaximumLength = sizeof(stringSidBuffer);

		status = RtlConvertSidToUnicodeString(
			&stringSid,
			pTokenUser->User.Sid,
			FALSE
			);
		if (NT_SUCCESS(status))
		{
			StringCbCopyNW(sz_user_name, MAX_PATH*sizeof(WCHAR), stringSid.Buffer, stringSid.Length);
			bResult = TRUE;
		}
	}
	__finally
	{
		if (pTokenUser != NULL)
			free(pTokenUser);
	}

	return bResult;
}


BOOLEAN build_reg_path_table()
{
	BOOLEAN ret;
	WCHAR   user_sid[MAX_PATH];
	ret = register_get_user_sid(user_sid);
	if (!ret)
	{
		return FALSE; 
	}

	wcscpy(g_reg_path_table[0].destPath, L"HKEY_CLASSES_ROOT");
	wcscpy(g_reg_path_table[0].srcPath, L"\\Registry\\Machine\\SOFTWARE\\Classes");
	g_reg_path_table[0].dstlen = (ULONG)wcslen(g_reg_path_table[0].destPath);
	g_reg_path_table[0].srclen = (ULONG)wcslen(g_reg_path_table[0].srcPath);

	wcscpy(g_reg_path_table[1].destPath, L"HKEY_CURRENT_USER\\Software\\Classes");
	wcscpy(g_reg_path_table[1].srcPath, L"\\Registry\\User\\");
	wcscat(g_reg_path_table[1].srcPath, user_sid);
	wcscat(g_reg_path_table[1].srcPath, L"_Classes");
	g_reg_path_table[1].dstlen = (ULONG)wcslen(g_reg_path_table[1].destPath);
	g_reg_path_table[1].srclen = (ULONG)wcslen(g_reg_path_table[1].srcPath);

	wcscpy(g_reg_path_table[2].destPath, L"HKEY_CURRENT_USER");
	wcscpy(g_reg_path_table[2].srcPath, L"\\Registry\\User\\");
	wcscat(g_reg_path_table[2].srcPath, user_sid);
	g_reg_path_table[2].dstlen = (ULONG)wcslen(g_reg_path_table[2].destPath);
	g_reg_path_table[2].srclen = (ULONG)wcslen(g_reg_path_table[2].srcPath);

	wcscpy(g_reg_path_table[3].destPath, L"HKEY_LOCAL_MACHINE");
	wcscpy(g_reg_path_table[3].srcPath, L"\\Registry\\Machine");
	g_reg_path_table[3].dstlen = (ULONG)wcslen(g_reg_path_table[3].destPath);
	g_reg_path_table[3].srclen = (ULONG)wcslen(g_reg_path_table[3].srcPath);

	wcscpy(g_reg_path_table[4].destPath, L"HKEY_USERS");
	wcscpy(g_reg_path_table[4].srcPath, L"\\Registry\\User");
	g_reg_path_table[4].dstlen = (ULONG)wcslen(g_reg_path_table[4].destPath);
	g_reg_path_table[4].srclen = (ULONG)wcslen(g_reg_path_table[4].srcPath);

	return TRUE;
}

CString trans_reg_path(const WCHAR * path)
{
	int i;
	WCHAR str[MAX_PATH];
	for (i = 0; i < 5; i++)
	{
		if (0 == _wcsnicmp(path, g_reg_path_table[i].srcPath, g_reg_path_table[i].srclen) && wcslen(path) != g_reg_path_table[i].srclen)
		{
			break;
		}
	}
	if (i >= 5)
	{
		return path;
	}

	str[0] = L'\0';
	wcscpy_s(str, MAX_PATH, g_reg_path_table[i].destPath);
	wcscat_s(str, MAX_PATH, path + g_reg_path_table[i].srclen);

	return str;
}

BOOLEAN init_lib(VOID)
{
	OSVERSIONINFO	versionInfo;
	ULONG			majorVersion;
	ULONG			minorVersion;

	NtQuerySystemInformation = (fn_NtQuerySystemInformation)get_proc_address(L"Ntdll.dll", "NtQuerySystemInformation");
	NtQueryInformationProcess = (fn_NtQueryInformationProcess)get_proc_address(L"Ntdll.dll", "NtQueryInformationProcess");
	RtlConvertSidToUnicodeString = (fn_RtlConvertSidToUnicodeString)get_proc_address(L"Ntdll.dll", "RtlConvertSidToUnicodeString");

	build_file_path_table();
	if (!build_reg_path_table())
	{
		return FALSE;
			 
	}
	versionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	if (!(GetVersionEx(&versionInfo)))
	{
		WindowsVersion = WINDOWS_NEW;
		return FALSE;
	}
	majorVersion = versionInfo.dwMajorVersion;
	minorVersion = versionInfo.dwMinorVersion;

	if (majorVersion == 5 && minorVersion < 1 || majorVersion < 5)
	{
		WindowsVersion = WINDOWS_ANCIENT;
	}
	/* Windows XP */
	else if (majorVersion == 5 && minorVersion == 1)
	{
		WindowsVersion = WINDOWS_XP;
	}
	/* Windows Server 2003 */
	else if (majorVersion == 5 && minorVersion == 2)
	{
		WindowsVersion = WINDOWS_SERVER_2003;
	}
	/* Windows Vista, Windows Server 2008 */
	else if (majorVersion == 6 && minorVersion == 0)
	{
		WindowsVersion = WINDOWS_VISTA;
	}
	/* Windows 7, Windows Server 2008 R2 */
	else if (majorVersion == 6 && minorVersion == 1)
	{
		WindowsVersion = WINDOWS_7;
	}
	/* Windows 8 */
	else if (majorVersion == 6 && minorVersion == 2)
	{
		WindowsVersion = WINDOWS_8;
	}
	/* Windows 8.1 */
	else if (majorVersion == 6 && minorVersion == 3)
	{
		WindowsVersion = WINDOWS_81;
	}
	else if (majorVersion == 6 && minorVersion > 3 || majorVersion > 6)
	{
		WindowsVersion = WINDOWS_NEW;
	}

	if (WindowsVersion >= WINDOWS_VISTA)
	{
		ProcessQueryAccess = PROCESS_QUERY_LIMITED_INFORMATION;
		ProcessAllAccess = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1fff;
		ThreadQueryAccess = THREAD_QUERY_LIMITED_INFORMATION;
		ThreadSetAccess = THREAD_SET_LIMITED_INFORMATION;
		ThreadAllAccess = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xfff;
	}
	else
	{
		ProcessQueryAccess = PROCESS_QUERY_INFORMATION;
		ProcessAllAccess = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xfff;
		ThreadQueryAccess = THREAD_QUERY_INFORMATION;
		ThreadSetAccess = THREAD_SET_INFORMATION;
		ThreadAllAccess = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3ff;
	}

	return TRUE;
}

BOOLEAN get_proc_user_by_pid(DWORD pid, WCHAR* sz_user_name)
{
	HANDLE			hToken = NULL;
	BOOLEAN			bResult = FALSE;
	DWORD			dwSize = 0;
	TCHAR			szUserName[256] = { 0 };
	TCHAR			szDomain[256] = { 0 };
	DWORD			dwDomainSize = 256;
	DWORD			dwNameSize = 256;
	SID_NAME_USE    snu;
	PTOKEN_USER		pTokenUser = NULL;


	HANDLE hProcess = OpenProcess(ProcessQueryAccess, FALSE, pid);
	if (hProcess == NULL)
	{
		return FALSE;
	}

	__try
	{
		if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
		{
			bResult = FALSE;
			//	printf("OpenProcessToken error: %u\n", GetLastError());
			__leave;
		}

		if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize))
		{
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			{
				bResult = FALSE;
				//		printf("GetTokenInformation error: %u\n", GetLastError());
				__leave;
			}
		}
		pTokenUser = (PTOKEN_USER)malloc(dwSize);
		if (pTokenUser == NULL)
		{
			bResult = FALSE;
			__leave;
		}

		if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize))
		{
			bResult = FALSE;
			__leave;
		}

		if (LookupAccountSid(NULL, pTokenUser->User.Sid, szUserName, &dwNameSize, szDomain, &dwDomainSize, &snu) != 0)
		{
			if (dwNameSize + dwDomainSize < MAX_PATH - 1)
			{
				_tcscpy_s(sz_user_name, MAX_PATH, szDomain);
				_tcscat_s(sz_user_name, MAX_PATH, _T("\\"));
				_tcscat_s(sz_user_name, MAX_PATH, szUserName);
				bResult = TRUE;
				__leave;
			}
		}
	}
	__finally
	{
		if (pTokenUser != NULL)
			free(pTokenUser);

		if (hProcess)
		{
			CloseHandle(hProcess);
		}
	}

	return bResult;
}

BOOLEAN is_short_name_path(const WCHAR * wszFileName)
{
	const WCHAR *p = wszFileName;

	while (*p != L'\0')
	{
		if (*p == L'~')
		{
			return TRUE;
		}
		p++;
	}

	return FALSE;
}

BOOLEAN trans_file_path_ex(const WCHAR* src, WCHAR* dest)
{
	WCHAR c;
	WCHAR windows_dir[MAX_PATH];
	if (src == NULL || dest == NULL || wcslen(src) == 0)
	{
		return FALSE;
	}
	if (_tcsnicmp(src, _T("\\??\\"), _tcslen(_T("\\??\\"))) == 0)
	{
		wcscpy_s(dest, MAX_PATH, &src[_tcslen(_T("\\??\\"))]);
		return TRUE;
	}
	if (_tcsnicmp(src, _T("\\Device\\HarddiskVolume"), _tcslen(_T("\\Device\\HarddiskVolume"))) == 0)
	{
		for (c = L'A'; c <= L'Z'; c++)
		{
			if (wcslen(g_file_path_table[c - 'A'].nt_name) >0 && _wcsnicmp(src, g_file_path_table[c - 'A'].nt_name, wcslen(g_file_path_table[c - 'A'].nt_name)) == 0)
			{
				wcscpy(dest, g_file_path_table[c - 'A'].dos_name);
				wcscat(dest, &src[_tcslen(g_file_path_table[c - 'A'].nt_name)]);
				break;
			}
			else
			{
				continue;
			}
		}

		if (c <= L'Z')
		{
			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}

	if (_wcsnicmp(src, L"\\SystemRoot", wcslen(L"\\SystemRoot")) == 0)
	{
		GetWindowsDirectory(windows_dir, MAX_PATH);
		wcscpy(dest, windows_dir);
		wcscat(dest, &src[wcslen(L"\\SystemRoot")]);
		return TRUE;
	}

	return FALSE;
}

CString trans_file_path(const WCHAR* src)
{
	WCHAR dest[MAX_PATH];
	CString str_src;
	CString str_long;
	BOOLEAN ret = FALSE;
	if (trans_file_path_ex(src, dest))
	{
		str_src = dest;
	}
	else
	{
		str_src = src;
	}

	if (is_short_name_path(str_src))
	{
		ret = get_long_file_name(str_src, str_long);
	}

	if (ret)
	{
		return str_long;
	}
	else
	{
		return str_src;
	}
}

BOOLEAN get_proc_path_by_pid_vista(
	_In_ HANDLE ProcessId,
	_Out_ WCHAR* sz_proc_path 
	)
{
	NTSTATUS						status;
	SYSTEM_PROCESS_ID_INFORMATION	processIdInfo;

	WCHAR buffer[MAX_PATH];
	
	processIdInfo.ProcessId = ProcessId;
	processIdInfo.ImageName.Length = 0;
	processIdInfo.ImageName.MaximumLength = MAX_PATH*sizeof(WCHAR);
	processIdInfo.ImageName.Buffer = buffer;

	status = NtQuerySystemInformation(
		SystemProcessIdInformation,
		&processIdInfo,
		sizeof(SYSTEM_PROCESS_ID_INFORMATION),
		NULL
		);

	if (!NT_SUCCESS(status))
	{
		return FALSE;
	}
	StringCbCopyNW(sz_proc_path, sizeof(WCHAR)*MAX_PATH, processIdInfo.ImageName.Buffer, processIdInfo.ImageName.Length);
	return TRUE;
}

BOOLEAN get_proc_path_by_pid_xp(
	_In_ HANDLE process_handle,
	_Out_ WCHAR* sz_proc_path
	)
{
	NTSTATUS status;
	PVOID buffer;
	ULONG returnLength = 0;
	PUNICODE_STRING fileName=NULL;

	NtQueryInformationProcess(
		process_handle,
		ProcessImageFileName,
		NULL,
		0,
		&returnLength
		);
	buffer = malloc(returnLength);
	if (buffer == NULL)
	{
		return FALSE;
	}
	status = NtQueryInformationProcess(
		process_handle,
		ProcessImageFileName,
		buffer,
		returnLength,
		&returnLength
		);

	if (NT_SUCCESS(status))
	{
		fileName = (PUNICODE_STRING)buffer;
	}
	if (fileName)
	{
		StringCbCopyNW(sz_proc_path, sizeof(WCHAR)*MAX_PATH, fileName->Buffer, fileName->Length);
	}
	free(buffer);
	return TRUE;
}


BOOLEAN get_proc_path_by_pid(DWORD pid, WCHAR* sz_proc_path)
{
	BOOLEAN		bRet = FALSE;
	WCHAR		tmp_path[MAX_PATH] = {0};
	HANDLE hProcess = OpenProcess(ProcessQueryAccess, FALSE, pid);
	
	if (WindowsVersion >= WINDOWS_VISTA)
	{
		bRet = get_proc_path_by_pid_vista((HANDLE)pid, tmp_path);
	}
	else
	{
		if (hProcess)
		{
			bRet = get_proc_path_by_pid_xp(hProcess, tmp_path);
		}
	}
	if (bRet)
	{
		StringCbCopyW(sz_proc_path, MAX_PATH*sizeof(WCHAR), trans_file_path(tmp_path));
	}
	
	if (hProcess)
	{
		CloseHandle(hProcess);
	}
	
	return bRet;
}

BOOL set_privilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES	tp;
	LUID				luid;
	HANDLE				hToken;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		//		printf("OpenProcessToken failed: %u\n", GetLastError());
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
	{
		//		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		//	printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		//	printf("The token does not have the specified privilege. \n");
		return FALSE;
	}
	//printf("success privilege. \n");
	return TRUE;
}

BOOLEAN get_long_file_name(const CString& sFilename, CString& sLongFilename)
{
	WIN32_FIND_DATA fd;
	HANDLE hFind = FindFirstFile(sFilename, &fd);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		FindClose(hFind);
		sLongFilename = fd.cFileName;
	}
	else
		return FALSE;

	int nSlash = sFilename.ReverseFind(_T('\\'));
	CString sTemp(sFilename);
	while (nSlash != -1)
	{
		sTemp = sTemp.Left(nSlash);

		if (sTemp.GetLength() != 2)
		{
			HANDLE hFind = FindFirstFile(sTemp, &fd);
			if (hFind != INVALID_HANDLE_VALUE)
			{
				FindClose(hFind);
				sLongFilename = CString(fd.cFileName) + _T("\\") + sLongFilename;
			}
			else
			{
				sLongFilename = sTemp + _T("\\") + sLongFilename;
				sTemp.Empty();
			}
		}
		else
		{
			sLongFilename = sTemp + _T("\\") + sLongFilename;
			sTemp.Empty();
		}

		nSlash = sTemp.ReverseFind(_T('\\'));
	}

	return TRUE;
}

//BOOLEAN delete_unprotected_sewin(const TCHAR* lpszServiceName)
//{
//	SC_HANDLE        schManager;
//	SC_HANDLE        schService;
//	SERVICE_STATUS    svcStatus;
//
//	TCHAR		szTempStr[MAX_PATH];
//	HKEY		hKey = NULL;
//	DWORD		dwData = 0;
//
//	_tcscpy_s(szTempStr, MAX_PATH, _T("SYSTEM\\CurrentControlSet\\Services\\"));
//	_tcscat_s(szTempStr, MAX_PATH, lpszServiceName);
//
//	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szTempStr, 0, _T(""), REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, (LPDWORD)&dwData) != ERROR_SUCCESS)
//	{
//	//	printf("RegCreateKeyEx err\n");
//		return FALSE;
//	}
//
//	RegCloseKey(hKey);
//
//	schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
//	if (NULL == schManager)
//	{
//		return FALSE;
//	}
//	schService = OpenService(schManager, lpszServiceName, SERVICE_ALL_ACCESS);
//	if (NULL == schService)
//	{
//		CloseServiceHandle(schManager);
//		return FALSE;
//	}
//	ControlService(schService, SERVICE_CONTROL_STOP, &svcStatus);
//
//	if (!DeleteService(schService))
//	{
//		CloseServiceHandle(schService);
//		CloseServiceHandle(schManager);
//		return FALSE;
//	}
//	CloseServiceHandle(schService);
//	CloseServiceHandle(schManager);
//	return TRUE;
//}

ULONG get_the_top_altitude()
{
	BYTE	buffer[200] = { 0 };
	DWORD	len = 0;
	HANDLE  handle;
	PFILTER_AGGREGATE_BASIC_INFORMATION p_info = NULL;
	TCHAR	sz_altitude[50];
//	TCHAR	sz_service_name[50];
	ULONG   altitude = 0;
	HRESULT  ret = FilterFindFirst(FilterAggregateBasicInformation, buffer, sizeof(buffer), &len, &handle);
	if (ret != S_OK)
	{
		return altitude;
	}

	do
	{
		p_info = (PFILTER_AGGREGATE_BASIC_INFORMATION)buffer;
		if (FLTFL_AGGREGATE_INFO_IS_MINIFILTER == p_info->Flags)
		{
			/*StringCbCopy(sz_altitude, p_info->Type.MiniFilter.FilterAltitudeLength + sizeof(TCHAR), (TCHAR*)((ULONG_PTR)buffer + p_info->Type.MiniFilter.FilterAltitudeBufferOffset));
			StringCbCopy(sz_service_name, p_info->Type.MiniFilter.FilterNameLength + sizeof(TCHAR), (TCHAR*)((ULONG_PTR)buffer + p_info->Type.MiniFilter.FilterNameBufferOffset));
			if (_tcsnicmp(sz_service_name, _T("sewindows"), _tcslen(_T("sewindows"))) == 0)
			{
				delete_unprotected_sewin(sz_service_name);
			}*/

			altitude = max(_tcstoul(sz_altitude, NULL, 10), altitude);
		}
		ret = FilterFindNext(handle, FilterAggregateBasicInformation, buffer, sizeof(buffer), &len);
	} while (ret == S_OK);
	if (altitude == 0)
	{
		return  30000;
	}
	return  altitude + 10;
}

CString get_module_path()
{
	HMODULE		hModule = NULL;
	TCHAR		szBuff[MAX_PATH];
	CString		strRetun = _T("");

	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)&get_the_top_altitude, &hModule);
	GetModuleFileName(hModule, szBuff, MAX_PATH);
	strRetun.Format(_T("%s"), szBuff);
	int pos = strRetun.ReverseFind(_T('\\'));
	if (pos != -1)
	{
		strRetun = strRetun.Left(pos);
	}
	return strRetun;
}
