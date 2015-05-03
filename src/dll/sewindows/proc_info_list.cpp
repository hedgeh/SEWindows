#include "stdafx.h"
#include "proc_info_list.h"
#include "read_write_lock.h"
#include "avl_tree.h"
#include "lib.h"
#include <tlhelp32.h> 

typedef struct _process_info
{
	st_avl_nodes	avl_entry;
	DWORD			pid;
	WCHAR			user_name[MAX_PATH];
	WCHAR			proc_path[MAX_PATH];
} process_info, *pprocess_info;

#define	WHITE_LIST_LEN	13

WCHAR						g_white_process[WHITE_LIST_LEN][MAX_PATH];

static READ_WRITE_LOCK	g_read_write_lock;
static st_avl_tree		g_avl_p2u_list;

void build_white_process_list()
{
	WCHAR temp_path[MAX_PATH];
	if (!GetWindowsDirectoryW(temp_path, MAX_PATH))
	{
		return ;
	}
	if (temp_path[wcslen(temp_path)-1] == L'\\')
	{
		temp_path[wcslen(temp_path) - 1] = L'\0';
	}
	StringCbCopyW(g_white_process[0], MAXPATHLEN*sizeof(WCHAR), temp_path);
	StringCbCatW(g_white_process[0], MAXPATHLEN*sizeof(WCHAR), L"\\explorer.exe");

	StringCbCopyW(g_white_process[1], MAXPATHLEN*sizeof(WCHAR), temp_path);
	StringCbCatW(g_white_process[1], MAXPATHLEN*sizeof(WCHAR), L"\\system32\\svchost.exe");

	StringCbCopyW(g_white_process[2], MAXPATHLEN*sizeof(WCHAR), temp_path);
	StringCbCatW(g_white_process[2], MAXPATHLEN*sizeof(WCHAR), L"\\system32\\lsass.exe");

	StringCbCopyW(g_white_process[3], MAXPATHLEN*sizeof(WCHAR), temp_path);
	StringCbCatW(g_white_process[3], MAXPATHLEN*sizeof(WCHAR), L"\\system32\\services.exe");

	StringCbCopyW(g_white_process[4], MAXPATHLEN*sizeof(WCHAR), temp_path);
	StringCbCatW(g_white_process[4], MAXPATHLEN*sizeof(WCHAR), L"\\system32\\csrss.exe");

	StringCbCopyW(g_white_process[5], MAXPATHLEN*sizeof(WCHAR), temp_path);
	StringCbCatW(g_white_process[5], MAXPATHLEN*sizeof(WCHAR), L"\\system32\\winlogon.exe");

	StringCbCopyW(g_white_process[6], MAXPATHLEN*sizeof(WCHAR), temp_path);
	StringCbCatW(g_white_process[6], MAXPATHLEN*sizeof(WCHAR), L"\\system32\\smss.exe");

	StringCbCopyW(g_white_process[7], MAXPATHLEN*sizeof(WCHAR), temp_path);
	StringCbCatW(g_white_process[7], MAXPATHLEN*sizeof(WCHAR), L"\\system32\\spoolsv.exe");

	StringCbCopyW(g_white_process[8], MAXPATHLEN*sizeof(WCHAR), temp_path);
	StringCbCatW(g_white_process[8], MAXPATHLEN*sizeof(WCHAR), L"\\system32\\alg.exe");

	StringCbCopyW(g_white_process[9], MAXPATHLEN*sizeof(WCHAR), temp_path);
	StringCbCatW(g_white_process[9], MAXPATHLEN*sizeof(WCHAR), L"\\system32\\conime.exe"); 

	StringCbCopyW(g_white_process[10], MAXPATHLEN*sizeof(WCHAR), temp_path);
	StringCbCatW(g_white_process[10], MAXPATHLEN*sizeof(WCHAR), L"\\system32\\wscntfy.exe"); 

	StringCbCopyW(g_white_process[11], MAXPATHLEN*sizeof(WCHAR), temp_path);
	StringCbCatW(g_white_process[11], MAXPATHLEN*sizeof(WCHAR), L"\\system32\\ctfmon.exe"); 

	StringCbCopyW(g_white_process[12], MAXPATHLEN*sizeof(WCHAR), temp_path);
	StringCbCatW(g_white_process[12], MAXPATHLEN*sizeof(WCHAR), L"\\system32\\wuauclt.exe"); 
}

BOOLEAN is_pid_in_whitelist(DWORD pid)
{
	WCHAR	procpath[MAX_PATH];
	DWORD ID = pid;

	if (ID == 0 || ID == 4 || ID == GetCurrentProcessId())
	{
		return  TRUE;
	}

	if (!get_proc_path_by_pid(ID, procpath))
	{
		return  TRUE;
	}
	for (int i = 0; i < WHITE_LIST_LEN; i++)
	{
		if (_wcsicmp(procpath, g_white_process[i]) == 0)
		{
			return TRUE;
		}
	}
	return FALSE;
}

BOOLEAN  InjectLibW(DWORD dwProcessId, PCWSTR pszLibFile) 
{
	BOOLEAN	bOk = FALSE;
	HANDLE	hProcess = NULL;
	HANDLE	hThread = NULL;
	PWSTR	pszLibFileRemote = NULL;

	__try {
		hProcess = OpenProcess(
			PROCESS_VM_READ|
			PROCESS_QUERY_INFORMATION |   // Required by Alpha
			PROCESS_CREATE_THREAD |   // For CreateRemoteThread
			PROCESS_VM_OPERATION |   // For VirtualAllocEx/VirtualFreeEx
			PROCESS_VM_WRITE,             // For WriteProcessMemory
			FALSE, dwProcessId);
		if (hProcess == NULL)
		{
			__leave;
		}

		int cch = 1 + lstrlenW(pszLibFile);
		int cb = cch * sizeof(wchar_t);

		pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, cb, MEM_COMMIT, PAGE_READWRITE);
		if (pszLibFileRemote == NULL)
		{
			__leave;
		}

		if (!WriteProcessMemory(hProcess, pszLibFileRemote,(PVOID)pszLibFile, cb, NULL))
		{
			__leave;
		}
		
		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
		if (pfnThreadRtn == NULL)
		{
			__leave;
		}

		hThread = CreateRemoteThread(hProcess, NULL, 0,pfnThreadRtn, pszLibFileRemote, 0, NULL);
		if (hThread == NULL)
		{
			__leave;
		}
		WaitForSingleObject(hThread, 300);

		bOk = TRUE;
	}
	__finally { 

		
		if (pszLibFileRemote != NULL)
		{
			VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);
		}
		if (hThread != NULL)
		{
			CloseHandle(hThread);
		}

		if (hProcess != NULL)
		{
			CloseHandle(hProcess);
		}
	}
	return(bOk);
}


BOOLEAN inject_dll_by_pid(DWORD pid)
{
	TCHAR szLibFile[MAX_PATH];
	if (is_pid_in_whitelist(pid))
	{
		return TRUE;
	}
	GetModuleFileName(NULL, szLibFile, _countof(szLibFile));
	PTSTR pFilename = _tcsrchr(szLibFile, TEXT('\\')) + 1;
	_tcscpy_s(pFilename, _countof(szLibFile) - (pFilename - szLibFile),TEXT("monitor.dll"));
	return InjectLibW(pid, szLibFile);
}

pprocess_info find_proc_info_by_pid(DWORD pid)
{
	process_info		info;
	pprocess_info		pinfo = NULL;
	pst_avl_nodes       pnode = NULL;

	info.pid = pid;

	lock_read(&g_read_write_lock);
	pnode = avl_tree_find_node(&g_avl_p2u_list,&info.avl_entry);
	unlock_read(&g_read_write_lock);

	if (pnode)
	{
		pinfo = CONTAINING_RECORD(pnode, process_info, avl_entry);
	}

	return pinfo;
}

BOOLEAN insert_to_procinfo_list(DWORD pid, const WCHAR* user_name,const WCHAR* proc_path)
{
	pprocess_info info;
	pst_avl_nodes pnode = NULL;
	

	if (find_proc_info_by_pid(pid))
	{
		return FALSE;
	}
	info = (pprocess_info)malloc(sizeof(process_info));
	if (NULL == info)
	{
		return FALSE;
	}
	RtlZeroMemory(info, sizeof(process_info));
	info->pid = pid;
	if (user_name)
	{
		wcscpy_s(info->user_name, MAX_PATH, user_name);
	}
	if (proc_path)
	{
		wcscpy_s(info->proc_path, MAX_PATH, proc_path);
	}
	
	lock_write(&g_read_write_lock);
	pnode = avl_tree_add_node(&g_avl_p2u_list,&info->avl_entry);
	unlock_write(&g_read_write_lock);
//	printf("insert_to_procinfo_list \nproc_path:%ws\nuser_name %ws\n",info->proc_path,info->user_name);
	return  (pnode==NULL);
}

void delete_entry_by_pid(DWORD pid)
{
	process_info		p2u;
	pst_avl_nodes       pnode = NULL;

	p2u.pid = pid;

	lock_read(&g_read_write_lock);
	pnode = avl_tree_find_node(&g_avl_p2u_list,&p2u.avl_entry);
	unlock_read(&g_read_write_lock);
	if (pnode)
	{ 
		lock_write(&g_read_write_lock);
		avl_tree_remove_node(&g_avl_p2u_list,pnode);
		unlock_write(&g_read_write_lock);
		pprocess_info p2u1 = CONTAINING_RECORD(pnode, process_info, avl_entry);
//		printf("delete_entry_by_pid \nproc_path:%ws\nuser_name %ws\n",p2u1->proc_path,p2u1->user_name);
		if (p2u1)
		{
			free(p2u1);
		}
	}
}

BOOLEAN get_proc_info_by_pid(HANDLE pid, WCHAR* sz_user_name, WCHAR* sz_proc_path)
{
	pprocess_info pinfo = NULL;
	pinfo = find_proc_info_by_pid((DWORD)pid);
	if (pinfo)
	{
		wcscpy_s(sz_user_name, MAX_PATH, pinfo->user_name); 
		wcscpy_s(sz_proc_path, MAX_PATH, pinfo->proc_path); 
		return TRUE;
	}
	if (get_proc_path_by_pid((DWORD)pid,sz_proc_path) && get_proc_user_by_pid((DWORD)pid,sz_user_name))
	{
		insert_to_procinfo_list((DWORD)pid, sz_user_name,sz_proc_path);
		return TRUE;
	}
	return FALSE;
}

LONG  avl_compare_function(
	_In_ pst_avl_nodes node1,
    _In_ pst_avl_nodes node2
    )
{
	pprocess_info p2u1 = CONTAINING_RECORD(node1, process_info, avl_entry);
    pprocess_info p2u2 = CONTAINING_RECORD(node2, process_info, avl_entry);

	return p2u1->pid - p2u2->pid;
}

void destroy_avl(pst_avl_nodes tree)
{
	if (tree == NULL)
	{
		return;
	}
	destroy_avl(tree->Left);
	destroy_avl(tree->Right);
	pprocess_info p2u2 = CONTAINING_RECORD(tree, process_info, avl_entry);
	free(p2u2);
}


PWCHAR mywcsistr(PWCHAR s1, PWCHAR s2)
{
	wchar_t * s = s1;
	wchar_t * p = s2;
	do
	{
		if (!*p)
		{
			return s1;
		}

		if ((*p == *s) || (towlower(*p) == towlower(*s)))
		{
			++p;
			++s;
		}
		else
		{
			p = s2;
			if (!*s)
			{
				return NULL;
			}
			s = ++s1;
		}

	} while (1);
	return NULL;
}


void bulid_p2u_map()
{
	WCHAR	user_name[MAX_PATH];
	WCHAR	proc_path[MAX_PATH];
	WCHAR	windir[MAX_PATH];
	GetWindowsDirectoryW(windir, MAX_PATH);
	HANDLE procSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	build_white_process_list();
	if(procSnap == INVALID_HANDLE_VALUE)
	{
	//	printf("CreateToolhelp32Snapshot failed, %d ",GetLastError());
		return;
	}
	
	PROCESSENTRY32 procEntry = { 0 };
	procEntry.dwSize = sizeof(PROCESSENTRY32);
	BOOL bRet = Process32First(procSnap,&procEntry);
	while(bRet)
	{
		if (get_proc_user_by_pid(procEntry.th32ProcessID, user_name) && get_proc_path_by_pid(procEntry.th32ProcessID,proc_path))
		{
			//taskmgr mmc
			if (_wcsnicmp(windir, proc_path, wcslen(windir)) != 0 || mywcsistr(proc_path, L"taskmgr.exe") || mywcsistr(proc_path, L"mmc.exe"))
			{
				inject_dll_by_pid(procEntry.th32ProcessID);
			}
			insert_to_procinfo_list(procEntry.th32ProcessID, user_name,proc_path);
//			printf("\ninsert_to_procinfo_list:\nproc_path:%ws\n user_name:%ws\n",proc_path,user_name);
		}
		bRet = Process32Next(procSnap, &procEntry);
	}
	CloseHandle(procSnap);
}

BOOLEAN avl_tree_enum_callback
	(
    _In_ pst_avl_tree Tree,
    _In_ pst_avl_nodes Element,
    _In_opt_ PVOID Context
    )
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Tree);
	pprocess_info p2u2 = CONTAINING_RECORD(Element, process_info, avl_entry);
	printf("pid:%d:path:%ws\n",p2u2->pid,p2u2->user_name);
	return TRUE;
}

//void	PrintBST1()
//{
//	avl_tree_enum(&g_avl_p2u_list,tree_enum_order_in_order,avl_tree_enum_callback,NULL);
//}

void init_user_list()
{
	avl_tree_init(&g_avl_p2u_list,avl_compare_function);
	init_rwlock(&g_read_write_lock); 
}

void uninit_user_list()
{
	if (ROOT_ELEMENT_OF_TREE(&g_avl_p2u_list))
	{
		destroy_avl(ROOT_ELEMENT_OF_TREE(&g_avl_p2u_list));
		ROOT_ELEMENT_OF_TREE(&g_avl_p2u_list) = NULL;
	}
	uninit_rwlock(&g_read_write_lock);
}