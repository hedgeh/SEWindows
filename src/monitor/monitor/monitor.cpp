// monitor.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "monitor.h"

#pragma comment(lib,"User32.lib")

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
	return real_CreateServiceA	        
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

SC_HANDLE WINAPI fake_OpenServiceW(
	_In_            SC_HANDLE               hSCManager,
	_In_            LPCWSTR                lpServiceName,
	_In_            DWORD                   dwDesiredAccess
	)
{
	if (dwDesiredAccess & SERVICE_CHANGE_CONFIG)
	{
		dwDesiredAccess &= ~SERVICE_CHANGE_CONFIG;
	}
	if (dwDesiredAccess & SERVICE_PAUSE_CONTINUE)
	{
		dwDesiredAccess &= ~SERVICE_PAUSE_CONTINUE;
	}
	if (dwDesiredAccess & SERVICE_START)
	{
		dwDesiredAccess &= ~SERVICE_START;
	}
	if (dwDesiredAccess & SERVICE_STOP)
	{
		dwDesiredAccess &= ~SERVICE_STOP;
	}
	if (dwDesiredAccess & DELETE)
	{
		dwDesiredAccess &= ~DELETE;
	}
	return real_OpenServiceW(hSCManager, lpServiceName,dwDesiredAccess);
}


SC_HANDLE WINAPI fake_OpenServiceA(
	_In_            SC_HANDLE               hSCManager,
	_In_            LPCSTR                lpServiceName,
	_In_            DWORD                   dwDesiredAccess
	)
{
	if (dwDesiredAccess & SERVICE_CHANGE_CONFIG)
	{
		dwDesiredAccess &= ~SERVICE_CHANGE_CONFIG;
	}
	if (dwDesiredAccess & SERVICE_PAUSE_CONTINUE)
	{
		dwDesiredAccess &= ~SERVICE_PAUSE_CONTINUE;
	}
	if (dwDesiredAccess & SERVICE_START)
	{
		dwDesiredAccess &= ~SERVICE_START;
	}
	if (dwDesiredAccess & SERVICE_STOP)
	{
		dwDesiredAccess &= ~SERVICE_STOP;
	}
	if (dwDesiredAccess & DELETE)
	{
		dwDesiredAccess &= ~DELETE;
	}
	return real_OpenServiceA(hSCManager, lpServiceName, dwDesiredAccess);
}


BOOL WINAPI fake_EndTask(
	_In_ HWND hWnd,
	_In_ BOOL fShutDown,
	_In_ BOOL fForce
	)
{
	return real_EndTask( hWnd,fShutDown, fForce);
}
