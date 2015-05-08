// monitor.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "monitor.h"
#include <StrSafe.h>
#include  <malloc.h>
#include <winioctl.h>
#pragma comment(lib,"User32.lib")

#define		SymboliclinkName		L"\\\\.\\xpsewindows"
#define		IOCTL_FROM_R3MSG		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1100, METHOD_BUFFERED, FILE_ANY_ACCESS) 

BOOLEAN DeviceIoControlSendMsg(void* cur_info, DWORD cur_len, void* ret_info, DWORD ret_len)
{
	HANDLE		DeviceHandle = 0;
	BOOLEAN		bobo = 0;
	DWORD		ret = 0;

	DeviceHandle = CreateFile(SymboliclinkName, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (DeviceHandle == INVALID_HANDLE_VALUE)
	{
		goto goto_error_pass;
	}

	bobo = DeviceIoControl(
		DeviceHandle, IOCTL_FROM_R3MSG,
		cur_info, cur_len,
		ret_info, ret_len,
		&ret,
		NULL);

	CloseHandle(DeviceHandle);

	if (bobo == FALSE)
	{
		goto goto_error_pass;
	}
	if (ret_len != ret)
	{
		goto goto_error_pass;
	}
	return TRUE;
goto_error_pass:
	return FALSE;
}

BOOLEAN	 rule_match( HIPS_RULE_NODE* pHrn)
{
	BOOLEAN bPermit = TRUE;

	if (!DeviceIoControlSendMsg(pHrn, sizeof(HIPS_RULE_NODE), pHrn, sizeof(HIPS_RULE_NODE)))
	{
		bPermit = TRUE;
	}
	else
	{
		if (pHrn->is_dir)
		{
			bPermit = TRUE;
		}
		else
		{
			bPermit = FALSE;
		}
	}
	return bPermit;
}

SC_HANDLE WINAPI fake_CreateServiceW(
	_In_        SC_HANDLE    hSCManager,
	_In_        LPCWSTR     lpServiceName,
	_In_opt_    LPCWSTR     lpDisplayName,
	_In_        DWORD        dwDesiredAccess,
	_In_        DWORD        dwServiceType,
	_In_        DWORD        dwStartType,
	_In_        DWORD        dwErrorControl,
	_In_opt_    LPCWSTR     lpBinaryPathName,
	_In_opt_    LPCWSTR     lpLoadOrderGroup,
	_Out_opt_   LPDWORD      lpdwTagId,
	_In_opt_    LPCWSTR     lpDependencies,
	_In_opt_    LPCWSTR     lpServiceStartName,
	_In_opt_    LPCWSTR     lpPassword
	)
{
	HIPS_RULE_NODE	hrn;

	RtlZeroMemory(&hrn,sizeof(hrn));
	hrn.major_type = SERVICE_OP;
	if (dwServiceType == SERVICE_FILE_SYSTEM_DRIVER || dwServiceType == SERVICE_KERNEL_DRIVER)
	{
		hrn.minor_type = OP_SERVICE_DRIVER;
	}
	else
	{
		hrn.minor_type = OP_SERVICE_CREATE;
	}
	hrn.sub_pid = (HANDLE)GetCurrentProcessId();
	wcscpy_s(hrn.des_path, MAXPATHLEN,lpBinaryPathName);
	wcscpy_s(hrn.service_name, MAXPATHLEN, lpServiceName);


	if (!rule_match(&hrn))
	{
		return NULL;
	}

	return real_CreateServiceW
		(            
		hSCManager,
		lpServiceName,
		lpDisplayName,
		dwDesiredAccess,
		dwServiceType,
		dwStartType,
		dwErrorControl,
		lpBinaryPathName,
		lpLoadOrderGroup,
		lpdwTagId,
		lpDependencies,
		lpServiceStartName,
		lpPassword
		);
}

PWSTR Ansi2Unicode(PCSTR str)
{
	int len = 0;
	if (!str)
	{
		return NULL;
	}
	len = strlen(str);
	int unicodeLen = ::MultiByteToWideChar(CP_ACP,
		0,
		str,
		-1,
		NULL,
		0);
	wchar_t * pUnicode;
	pUnicode = (wchar_t*)malloc((unicodeLen + 1)*sizeof(WCHAR));
	if (!pUnicode)
	{
		return NULL;
	}
	memset(pUnicode, 0, (unicodeLen + 1)*sizeof(WCHAR));
	::MultiByteToWideChar(CP_ACP,
		0,
		str,
		-1,
		(LPWSTR)pUnicode,
		unicodeLen);
	return pUnicode;
}

SC_HANDLE WINAPI fake_CreateServiceA(
	_In_        SC_HANDLE    hSCManager,
	_In_        LPCSTR     lpServiceName,
	_In_opt_    LPCSTR     lpDisplayName,
	_In_        DWORD        dwDesiredAccess,
	_In_        DWORD        dwServiceType,
	_In_        DWORD        dwStartType,
	_In_        DWORD        dwErrorControl,
	_In_opt_    LPCSTR     lpBinaryPathName,
	_In_opt_    LPCSTR     lpLoadOrderGroup,
	_Out_opt_   LPDWORD      lpdwTagId,
	_In_opt_    LPCSTR     lpDependencies,
	_In_opt_    LPCSTR     lpServiceStartName,
	_In_opt_    LPCSTR     lpPassword
	)
{
	SC_HANDLE   handle = NULL;
	LPCWSTR     lpServiceNameW = Ansi2Unicode(lpServiceName);
	LPCWSTR     lpDisplayNameW = Ansi2Unicode(lpDisplayName);
	LPCWSTR     lpBinaryPathNameW = Ansi2Unicode(lpBinaryPathName);
	LPCWSTR     lpLoadOrderGroupW = Ansi2Unicode(lpLoadOrderGroup);
	LPCWSTR     lpDependenciesW = Ansi2Unicode(lpDependencies);
	LPCWSTR     lpServiceStartNameW = Ansi2Unicode(lpServiceStartName);
	LPCWSTR     lpPasswordW = Ansi2Unicode(lpPassword);

	handle = fake_CreateServiceW
	(    
		hSCManager,
		lpServiceNameW,
		lpDisplayNameW,
		dwDesiredAccess,
		dwServiceType,
		dwStartType,
		dwErrorControl,
		lpBinaryPathNameW,
		lpLoadOrderGroupW,
		lpdwTagId,
		lpDependenciesW,
		lpServiceStartNameW,
		lpPasswordW
	);

	if (lpServiceNameW)
	{
		free((void*)lpServiceNameW);
	}

	if (lpDisplayNameW)
	{
		free((void*)lpDisplayNameW);
	}
	if (lpBinaryPathNameW)
	{
		free((void*)lpBinaryPathNameW);
	}
	if (lpLoadOrderGroupW)
	{
		free((void*)lpLoadOrderGroupW);
	}
	if (lpDependenciesW)
	{
		free((void*)lpDependenciesW);
	}
	if (lpServiceStartNameW)
	{
		free((void*)lpServiceStartNameW);
	}
	if (lpPasswordW)
	{
		free((void*)lpPasswordW);
	}
	return handle;
}

SC_HANDLE WINAPI fake_OpenServiceW(
	_In_            SC_HANDLE               hSCManager,
	_In_            LPCWSTR                lpServiceName,
	_In_            DWORD                   dwDesiredAccess
	)
{

	HIPS_RULE_NODE	hrn;
	BOOLEAN			bDeny = FALSE;

	RtlZeroMemory(&hrn, sizeof(hrn));
	hrn.major_type = SERVICE_OP;
	hrn.sub_pid = (HANDLE)GetCurrentProcessId();
	wcscpy_s(hrn.service_name, MAXPATHLEN, lpServiceName);


	if ((dwDesiredAccess & SERVICE_CHANGE_CONFIG) || 
		(dwDesiredAccess & SERVICE_PAUSE_CONTINUE) || 
		(dwDesiredAccess & SERVICE_START) || 
		(dwDesiredAccess & SERVICE_STOP))
	{
		hrn.minor_type = OP_SERVICE_CHANGE;
		if (!rule_match(&hrn))
		{
			dwDesiredAccess &= ~SERVICE_CHANGE_CONFIG;
			dwDesiredAccess &= ~SERVICE_PAUSE_CONTINUE;
			dwDesiredAccess &= ~SERVICE_START;
			dwDesiredAccess &= ~SERVICE_STOP;
		}
	}

	if (dwDesiredAccess & DELETE)
	{
		RtlZeroMemory(&hrn, sizeof(hrn));
		hrn.major_type = SERVICE_OP;
		hrn.sub_pid = (HANDLE)GetCurrentProcessId();
		wcscpy_s(hrn.service_name, MAXPATHLEN, lpServiceName);
		hrn.minor_type = OP_SERVICE_DELETE;
		if (!rule_match(&hrn))
		{
			dwDesiredAccess &= ~DELETE;
		}
	}

	return real_OpenServiceW(hSCManager, lpServiceName,dwDesiredAccess);
}


SC_HANDLE WINAPI fake_OpenServiceA(
	_In_            SC_HANDLE               hSCManager,
	_In_            LPCSTR                lpServiceName,
	_In_            DWORD                   dwDesiredAccess
	)
{
	SC_HANDLE   handle = NULL;
	LPCWSTR     lpServiceNameW = Ansi2Unicode(lpServiceName);

	handle = fake_OpenServiceW(hSCManager, lpServiceNameW, dwDesiredAccess);

	if (lpServiceNameW)
	{
		free((void*)lpServiceNameW);
	}
	return handle;
}


BOOL WINAPI fake_EndTask(
	_In_ HWND hWnd,
	_In_ BOOL fShutDown,
	_In_ BOOL fForce
	)
{
	DWORD			pid = 0;
	DWORD			tid = 0;
	HIPS_RULE_NODE	hrn;
	BOOLEAN			bDeny = FALSE;

	tid = GetWindowThreadProcessId(hWnd, &pid);

	RtlZeroMemory(&hrn, sizeof(hrn));
	hrn.major_type = PROC_OP;
	hrn.minor_type = OP_PROC_KILL;
	hrn.sub_pid = (HANDLE)GetCurrentProcessId();
	hrn.obj_pid = (HANDLE)pid;
	if (!rule_match(&hrn))
	{
		return FALSE;
	}
	return real_EndTask( hWnd,fShutDown, fForce);
}
