#include "stdafx.h"
#include "scm_drv_ctrl.h"
#include <winioctl.h>
#pragma comment(lib,"Advapi32.lib")


ScmDrvCtrl::ScmDrvCtrl(void)
{
	RtlZeroMemory(m_link_name, sizeof( m_link_name));
}

ScmDrvCtrl::~ScmDrvCtrl(void)
{
}

BOOLEAN ScmDrvCtrl::UnInstall(const TCHAR* lpszServiceName)
{
	SC_HANDLE        schManager;
	SC_HANDLE        schService;
	SERVICE_STATUS    svcStatus;

	schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == schManager)
	{
		return FALSE;
	}
	schService = OpenService(schManager, lpszServiceName, SERVICE_ALL_ACCESS);
	if (NULL == schService)
	{
		CloseServiceHandle(schManager);
		return FALSE;
	}
	ControlService(schService, SERVICE_CONTROL_STOP, &svcStatus);
	
	if (!DeleteService(schService))
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		return FALSE;
	}
	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);
	return TRUE;
}

BOOLEAN ScmDrvCtrl::Install(const TCHAR* lpszServiceName, const TCHAR* lpszDriverPath, const TCHAR* lpszAltitude, const TCHAR* lpszLink_name)
{
	SC_HANDLE hServiceMgr = NULL;
	SC_HANDLE hService = NULL;
	int i = 0;
	_tcscpy_s(m_link_name, MAX_PATH, lpszLink_name);
	if (NULL == lpszServiceName || NULL == lpszDriverPath || NULL == lpszAltitude)
	{
		return FALSE;
	}
	UnInstall(lpszServiceName);
	WIN32_FIND_DATA FindFileData;
	if (FindFirstFileW(lpszDriverPath, &FindFileData) == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

again:
	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hServiceMgr == NULL)
	{
		return FALSE;
	}
	hService = CreateService(hServiceMgr,
		lpszServiceName,				// 驱动程序的在注册表中的名字
		lpszServiceName,				// 注册表驱动程序的DisplayName 值
		SERVICE_ALL_ACCESS,				// 加载驱动程序的访问权限
		SERVICE_FILE_SYSTEM_DRIVER,		// 表示加载的服务是文件系统驱动程序
		SERVICE_DEMAND_START,			// 注册表驱动程序的Start 值
		SERVICE_ERROR_IGNORE,			// 注册表驱动程序的ErrorControl 值
		lpszDriverPath,					// 注册表驱动程序的ImagePath 值
		_T("FSFilter Activity Monitor"),// 注册表驱动程序的Group 值
		NULL,
		_T("FltMgr"),                   // 注册表驱动程序的DependOnService 值
		NULL,
		NULL);

	if (hService == NULL)
	{
		CloseServiceHandle(hServiceMgr);
		if (i > 100000)
		{
			return FALSE;
		}
		i++;
		printf("%d\n", i);
		goto again;
	}
	
	CloseServiceHandle(hService);       // 服务句柄
	CloseServiceHandle(hServiceMgr);    // SCM句柄

	TCHAR		szTempStr[MAX_PATH];
	HKEY		hKey = NULL;
	DWORD		dwData = 0;

	_tcscpy_s(szTempStr, MAX_PATH, _T("SYSTEM\\CurrentControlSet\\Services\\"));
	_tcscat_s(szTempStr, MAX_PATH, lpszServiceName);

	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szTempStr, 0, _T(""), REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, (LPDWORD)&dwData) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	_tcscpy_s(szTempStr, MAX_PATH, lpszServiceName);
	if (RegSetValueEx(hKey, _T("service_name"), 0, REG_SZ, (CONST BYTE*)szTempStr, (DWORD)_tcslen(szTempStr)*sizeof(TCHAR)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	//GetWindowsDirectory(szTempStr,MAX_PATH);
	//if (RegSetValueEx(hKey, _T("system_dir"), 0, REG_SZ, (CONST BYTE*)szTempStr, (DWORD)_tcslen(szTempStr)*sizeof(TCHAR)) != ERROR_SUCCESS)
	//{
	//	return FALSE;
	//}

	RegFlushKey(hKey);
	RegCloseKey(hKey);

	_tcscpy_s(szTempStr, MAX_PATH, _T("SYSTEM\\CurrentControlSet\\Services\\"));
	_tcscat_s(szTempStr, MAX_PATH, lpszServiceName);
	_tcscat_s(szTempStr, MAX_PATH, _T("\\Instances"));

	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szTempStr, 0, _T(""), REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, (LPDWORD)&dwData) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	_tcscpy_s(szTempStr, MAX_PATH, lpszServiceName);
	_tcscat_s(szTempStr, MAX_PATH, _T(" Instance"));
	if (RegSetValueEx(hKey, _T("DefaultInstance"), 0, REG_SZ, (CONST BYTE*)szTempStr, (DWORD)_tcslen(szTempStr)*sizeof(TCHAR)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	RegFlushKey(hKey);
	RegCloseKey(hKey);

	_tcscpy_s(szTempStr, MAX_PATH, _T("SYSTEM\\CurrentControlSet\\Services\\"));
	_tcscat_s(szTempStr, MAX_PATH, lpszServiceName);
	_tcscat_s(szTempStr, MAX_PATH, _T("\\Instances\\"));
	_tcscat_s(szTempStr, MAX_PATH, lpszServiceName);
	_tcscat_s(szTempStr, MAX_PATH, _T(" Instance"));
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szTempStr, 0, _T(""), REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, (LPDWORD)&dwData) != ERROR_SUCCESS)
	{
		return FALSE;
	}

	_tcscpy_s(szTempStr, lpszAltitude);
	if (RegSetValueEx(hKey, _T("Altitude"), 0, REG_SZ, (CONST BYTE*)szTempStr, (DWORD)_tcslen(szTempStr)*sizeof(TCHAR)) != ERROR_SUCCESS)
	{
		return FALSE;
	}

	dwData = 0x0;
	if (RegSetValueEx(hKey, _T("Flags"), 0, REG_DWORD, (CONST BYTE*)&dwData, sizeof(DWORD)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	RegFlushKey(hKey);
	RegCloseKey(hKey);
	return TRUE;
}
BOOLEAN ScmDrvCtrl::Start(const TCHAR* lpszDriverName)
{
	SC_HANDLE        schManager;
	SC_HANDLE        schService;

	if (NULL == lpszDriverName)
	{
		return FALSE;
	}

	schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == schManager)
	{
		return FALSE;
	}
	schService = OpenService(schManager, lpszDriverName, SERVICE_ALL_ACCESS);
	if (NULL == schService)
	{
		CloseServiceHandle(schManager);
		return FALSE;
	}

	if (!StartService(schService, 0, NULL))
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
		{
			return TRUE;
		}
		return FALSE;
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);
	return TRUE;
}

BOOLEAN ScmDrvCtrl::Stop(const TCHAR* lpszDriverName)
{
	SC_HANDLE        schManager;
	SC_HANDLE        schService;
	SERVICE_STATUS    svcStatus;

	schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == schManager)
	{
		return FALSE;
	}
	schService = OpenService(schManager, lpszDriverName, SERVICE_ALL_ACCESS);
	if (NULL == schService)
	{
		CloseServiceHandle(schManager);
		return FALSE;
	}
	if (!ControlService(schService, SERVICE_CONTROL_STOP, &svcStatus) && (svcStatus.dwCurrentState != SERVICE_STOPPED))
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		return FALSE;
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);

	return TRUE;

}


BOOLEAN ScmDrvCtrl::IoControl(DWORD dwIoCode, PVOID InBuff, DWORD InBuffLen, PVOID OutBuff, DWORD OutBuffLen, DWORD *RealRetBytes)
{
	DWORD dw = 0;
	HANDLE hDevice = CreateFile(m_link_name, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	BOOLEAN b = DeviceIoControl(hDevice, dwIoCode, InBuff, InBuffLen, OutBuff, OutBuffLen, &dw, NULL)?TRUE:FALSE;
	if(RealRetBytes)
		*RealRetBytes=dw;
	CloseHandle(hDevice);
	return b;
}
