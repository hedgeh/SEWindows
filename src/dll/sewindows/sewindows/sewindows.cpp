#include "stdafx.h"
#include "sewindows.h"
#include "communite_with_driver.h"

#pragma comment(lib,"Advapi32.lib")

CCommunicateDriv	g_comm;
BOOLEAN				g_bIsDriverInited = TRUE;
CString				g_str_altitude;
CString				g_str_service_name;
CString				g_str_port_name;
CString				g_str_link_name;
CString				g_str_path;
sewin_operations	g_sewin_operation;

BOOL SetPrivilege(LPCTSTR lpszPrivilege,  BOOL bEnablePrivilege )
{
	TOKEN_PRIVILEGES	tp;
	LUID				luid;
	HANDLE				hToken;      

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		printf("OpenProcessToken failed: %u\n", GetLastError());
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL,lpszPrivilege,  &luid))        
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
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
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}
	printf("success privilege. \n");
	return TRUE;
}

BOOLEAN get_user_name_by_pid(HANDLE pid, WCHAR* sz_user_name)
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


	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
	if (hProcess == NULL)
	{
		printf("OpenProcess %d error: %u\n", (DWORD)pid, GetLastError());
		return FALSE;
	}
	
	__try
	{
		if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
		{
			bResult = FALSE;
			printf("OpenProcessToken error: %u\n", GetLastError());
			__leave;
		}

		if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize))
		{
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			{
				bResult = FALSE;
				printf("GetTokenInformation error: %u\n", GetLastError());
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

BOOL delete_unprotected_sewin(const TCHAR* lpszServiceName)
{
	SC_HANDLE        schManager;
	SC_HANDLE        schService;
	SERVICE_STATUS    svcStatus;

	TCHAR		szTempStr[MAX_PATH];
	HKEY		hKey = NULL;
	DWORD		dwData = 0;

	_tcscpy_s(szTempStr, MAX_PATH, _T("SYSTEM\\CurrentControlSet\\Services\\"));
	_tcscat_s(szTempStr, MAX_PATH, lpszServiceName);

	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szTempStr, 0, _T(""), REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, (LPDWORD)&dwData) != ERROR_SUCCESS)
	{
		printf("RegCreateKeyEx err\n");
		return FALSE;
	}

	RegCloseKey(hKey);

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

ULONG get_the_top_altitude()
{
	BYTE	buffer[200] = { 0 };
	DWORD	len = 0;
	HANDLE  handle;
	PFILTER_AGGREGATE_BASIC_INFORMATION p_info = NULL;
	TCHAR	sz_altitude[50];
	TCHAR	sz_service_name[50];
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
			StringCbCopy(sz_altitude, p_info->Type.MiniFilter.FilterAltitudeLength + sizeof(TCHAR), (TCHAR*)((ULONG_PTR)buffer + p_info->Type.MiniFilter.FilterAltitudeBufferOffset));
			StringCbCopy(sz_service_name, p_info->Type.MiniFilter.FilterNameLength + sizeof(TCHAR), (TCHAR*)((ULONG_PTR)buffer + p_info->Type.MiniFilter.FilterNameBufferOffset));
			if (_tcsnicmp(sz_service_name,_T("sewindows"),_tcslen(_T("sewindows"))) == 0)
			{
				delete_unprotected_sewin(sz_service_name);
			}
			
			altitude = max(_tcstoul(sz_altitude, NULL, 10), altitude);
		}
		ret = FilterFindNext(handle, FilterAggregateBasicInformation, buffer, sizeof(buffer), &len);
	} while (ret == S_OK);
	if (altitude == 0)
	{
		return  30000;
	}
	return  altitude+10;
}

CString GetMoudulePath()
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

BOOLEAN notify_callback_func(Param& op)
{
	WCHAR	user_name[MAX_PATH] = {0};
	PHIPS_RULE_NODE prule_node = &op.opdata.rule_node;
	switch (prule_node->major_type)
	{
	case PROC_OP:
	{
		switch (prule_node->minor_type)
		{
		case OP_PROC_KILL:
			if (g_sewin_operation.process_kill)
			{
				get_user_name_by_pid(prule_node->sub_pid, user_name);
				return g_sewin_operation.process_kill(user_name, prule_node->src_path, prule_node->des_path);
			}
			break;
		case OP_PROC_CREATE_REMOTE_THREAD:
			if (g_sewin_operation.process_create_thread)
			{
				get_user_name_by_pid(prule_node->sub_pid, user_name);
				return g_sewin_operation.process_create_thread(user_name, prule_node->src_path, prule_node->des_path);
			}
			break;
		case OP_PROC_READ_PROCESS:
			if (g_sewin_operation.process_read_mem)
			{
				get_user_name_by_pid(prule_node->sub_pid, user_name);
				return g_sewin_operation.process_read_mem(user_name, prule_node->src_path, prule_node->des_path);
			}
			break;
		case OP_PROC_WRITE_PROCESS:
			if (g_sewin_operation.process_write_mem)
			{
				get_user_name_by_pid(prule_node->sub_pid, user_name);
				return g_sewin_operation.process_write_mem(user_name, prule_node->src_path, prule_node->des_path);
			}
			break;
		case OP_PROC_CREATE_PROCESS:
			if (g_sewin_operation.process_create)
			{
				get_user_name_by_pid(prule_node->sub_pid, user_name);
				return g_sewin_operation.process_create(user_name, prule_node->src_path, prule_node->des_path);
			}
			break;
		case OP_PROC_CHANGE_VM:
			if (g_sewin_operation.process_set_mem_attr)
			{
				get_user_name_by_pid(prule_node->sub_pid, user_name);
				return g_sewin_operation.process_set_mem_attr(user_name, prule_node->src_path, prule_node->des_path);
			}
			break;
		default:
			break;
		}
		break;
	}
	case REG_OP:
	{
		switch (prule_node->minor_type)
		{
		case OP_REG_READ:
			if (g_sewin_operation.reg_read_key)
			{
				get_user_name_by_pid(prule_node->sub_pid, user_name);
				return g_sewin_operation.reg_read_key(user_name, prule_node->src_path, prule_node->des_path);
			}
			break;
		case OP_REG_DELETE_VALUE_KEY:
			if (g_sewin_operation.reg_delete_value)
			{
				get_user_name_by_pid(prule_node->sub_pid, user_name);
				return g_sewin_operation.reg_delete_value(user_name, prule_node->src_path, prule_node->des_path);
			}
			break;
		case OP_REG_CREATE_KEY:
			if (g_sewin_operation.reg_create_key)
			{
				get_user_name_by_pid(prule_node->sub_pid, user_name);
				return g_sewin_operation.reg_create_key(user_name, prule_node->src_path, prule_node->des_path);
			}
			break;
		case OP_REG_SET_VALUE_KEY:
			if (g_sewin_operation.reg_set_value)
			{
				get_user_name_by_pid(prule_node->sub_pid, user_name);
				return g_sewin_operation.reg_set_value(user_name, prule_node->src_path, prule_node->des_path, prule_node->new_name);
			}
			break;
		case OP_REG_RENAME:
			if (g_sewin_operation.reg_rename_key)
			{
				get_user_name_by_pid(prule_node->sub_pid, user_name);
				return g_sewin_operation.reg_rename_key(user_name, prule_node->src_path, prule_node->des_path, prule_node->new_name);
			}
			break;
		case OP_REG_DELETE_KEY:
			if (g_sewin_operation.reg_delete_key)
			{
				get_user_name_by_pid(prule_node->sub_pid, user_name);
				return g_sewin_operation.reg_delete_key(user_name, prule_node->src_path, prule_node->des_path);
			}
			break;
		case OP_REG_SAVE:
			if (g_sewin_operation.reg_save_key)
			{
				get_user_name_by_pid(prule_node->sub_pid, user_name);
				return g_sewin_operation.reg_save_key(user_name, prule_node->src_path, prule_node->des_path);
			}
			break;
		case OP_REG_RESTORE:
			if (g_sewin_operation.reg_restore_key)
			{
				get_user_name_by_pid(prule_node->sub_pid, user_name);
				return g_sewin_operation.reg_restore_key(user_name, prule_node->src_path, prule_node->des_path);
			}
			break;
		case OP_REG_REPLACE:
			if (g_sewin_operation.reg_replace)
			{
				get_user_name_by_pid(prule_node->sub_pid, user_name);
				return g_sewin_operation.reg_replace(user_name, prule_node->src_path, prule_node->des_path);
			}
			break;
		case OP_REG_LOAD:
			if (g_sewin_operation.reg_load_key)
			{
				get_user_name_by_pid(prule_node->sub_pid, user_name);
				return g_sewin_operation.reg_load_key(user_name, prule_node->src_path, prule_node->des_path);
			}
			break;
		case OP_REG_UNLOAD:
			if (g_sewin_operation.reg_unload_key)
			{
				get_user_name_by_pid(prule_node->sub_pid, user_name);
				return g_sewin_operation.reg_unload_key(user_name, prule_node->src_path, prule_node->des_path);
			}
			break;

		default:
			break;
		}
		break;
	}
	case FILE_OP:
	{
		if (prule_node->isDir)
		{
			switch (prule_node->minor_type)
			{
			case FILE_DEL_XX:
				if (g_sewin_operation.dir_unlink)
				{
					get_user_name_by_pid(prule_node->sub_pid, user_name);
					return g_sewin_operation.dir_unlink(user_name, prule_node->src_path, prule_node->des_path);
				}
				break;
			case FILE_RENAME_XX:
				if (g_sewin_operation.dir_rename)
				{
					get_user_name_by_pid(prule_node->sub_pid, user_name);
					return g_sewin_operation.dir_rename(user_name, prule_node->src_path, prule_node->des_path,prule_node->new_name);
				}
				break;
			case FILE_CREATE_XX:
				if (g_sewin_operation.dir_create)
				{
					get_user_name_by_pid(prule_node->sub_pid, user_name);
					return g_sewin_operation.dir_create(user_name, prule_node->src_path, prule_node->des_path);
				}
				break;
			case FILE_SETINFO_XX:
				if (g_sewin_operation.dir_set_attr)
				{
					get_user_name_by_pid(prule_node->sub_pid, user_name);
					return g_sewin_operation.dir_set_attr(user_name, prule_node->src_path, prule_node->des_path, &prule_node->fbi);
				}
				break;
			default:
				break;
			}
		}
		else
		{
			switch (prule_node->minor_type)
			{
			case FILE_READ_DATA_XX:
				if (g_sewin_operation.file_read)
				{
					get_user_name_by_pid(prule_node->sub_pid, user_name);
					return g_sewin_operation.file_read(user_name, prule_node->src_path, prule_node->des_path);
				}
				break;
			case FILE_WRITE_DATA_XX:
				if (g_sewin_operation.file_write)
				{
					get_user_name_by_pid(prule_node->sub_pid, user_name);
					return g_sewin_operation.file_write(user_name, prule_node->src_path, prule_node->des_path);
				}
				break;
			case FILE_DEL_XX:
				if (g_sewin_operation.file_unlink)
				{
					get_user_name_by_pid(prule_node->sub_pid, user_name);
					return g_sewin_operation.file_unlink(user_name, prule_node->src_path, prule_node->des_path);
				}
				break;
			case FILE_RENAME_XX:
				if (g_sewin_operation.file_rename)
				{
					get_user_name_by_pid(prule_node->sub_pid, user_name);
					return g_sewin_operation.file_rename(user_name, prule_node->src_path, prule_node->des_path, prule_node->new_name);
				}
				break;
			case FILE_CREATE_XX:
				if (g_sewin_operation.file_create)
				{
					get_user_name_by_pid(prule_node->sub_pid, user_name);
					return g_sewin_operation.file_create(user_name, prule_node->src_path, prule_node->des_path);
				}
				break;
			case FILE_SETINFO_XX:
				if (g_sewin_operation.file_set_attr)
				{
					get_user_name_by_pid(prule_node->sub_pid, user_name);
					return g_sewin_operation.file_set_attr(user_name, prule_node->src_path, prule_node->des_path, &prule_node->fbi);
				}
				break;
			case FILE_EXECUTE_XX:
				if (g_sewin_operation.file_execute)
				{
					get_user_name_by_pid(prule_node->sub_pid, user_name);
					return g_sewin_operation.file_execute(user_name, prule_node->src_path, prule_node->des_path);
				}
				break;
			default:
				break;
			}
		}
		break;
	}
	default:
		break;
	}
	return TRUE;
}


void sewin_uninit(void)
{
	SetPrivilege(SE_DEBUG_NAME, FALSE);
	g_comm.PermitUnload();
	g_comm.CloseComplete();
	g_comm.OnExitProcess(g_str_service_name.GetBuffer());
}

SEWINDOWS_API BOOLEAN sewin_init(void)
{
	ULONG		top_altitude;
	RtlZeroMemory(&g_sewin_operation, sizeof(g_sewin_operation));
	top_altitude = get_the_top_altitude();

	if (top_altitude == 0)
	{
		return FALSE;
	}
	SetPrivilege(SE_DEBUG_NAME, TRUE);
	g_str_altitude.Format(_T("%d"), top_altitude);
	g_str_service_name.Format(_T("%08d"), top_altitude);
	g_str_port_name.Format(_T("%08d"), top_altitude);
	g_str_link_name.Format(_T("%08d"), top_altitude);
	g_str_path = GetMoudulePath();
	if (g_str_path.GetAt(g_str_path.GetLength()) != _T('\\'))
	{
		g_str_path += _T("\\");
	}
	g_str_path += DRIVERNAME;
	g_str_service_name = SERVICENAME + g_str_service_name;
	g_str_port_name = HIPSPORTNAME + g_str_port_name;
	g_str_link_name = LINKNAME + g_str_link_name;
	g_comm.SetNotify(notify_callback_func);
	if (!g_comm.InitDriver(g_str_service_name.GetBuffer(), g_str_path.GetBuffer(), g_str_altitude.GetBuffer(), g_str_port_name.GetBuffer(), g_str_link_name.GetBuffer()))
	{
		MessageBox(NULL,g_comm.m_errStr,NULL,0);
		g_bIsDriverInited = FALSE;
		return FALSE;
	}
	g_bIsDriverInited = g_comm.StopUnload();
	return g_bIsDriverInited;
}


SEWINDOWS_API BOOLEAN sewin_setoption(int mode, int type)
{
	BOOLEAN bret = FALSE;
	if (mode != SEWIN_MODE_INTERCEPT && mode != SEWIN_MODE_NOTIFY)
	{
		return FALSE;
	}

	if (mode == SEWIN_MODE_INTERCEPT)
	{
		bret = g_comm.SetMode(FALSE);
	}
	else
	{
		bret = g_comm.SetMode(TRUE);
	}

	if (!bret)
	{
		return bret;
	}

	if (type & SEWIN_TYPE_FILE)
	{
		bret = g_comm.StartFileMon(TRUE);
	}
	else
	{
		bret = g_comm.StartFileMon(FALSE);
	}
	if (!bret)
	{
		return bret;
	}
	if (type & SEWIN_TYPE_FROC)
	{
		bret = g_comm.StartProcMon(TRUE);
	}
	else
	{
		bret = g_comm.StartProcMon(FALSE);
	}
	if (!bret)
	{
		return bret;
	}
	if (type & SEWIN_TYPE_REG)
	{
		bret = g_comm.StartRegMon(TRUE);
	}
	else
	{
		bret = g_comm.StartRegMon(FALSE);
	}
	if (!bret)
	{
		return bret;
	}
	return TRUE;
}
SEWINDOWS_API BOOLEAN sewin_register_opt(struct sewin_operations *ops)
{
	if (ops == NULL)
	{
		return FALSE;
	}
	g_sewin_operation = *ops;
	return TRUE;
}