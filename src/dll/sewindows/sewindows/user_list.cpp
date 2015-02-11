#include "stdafx.h"
#include "user_list.h"
#include "read_write_lock.h"

static LIST_ENTRY		g_p2u_list;
static READ_WRITE_LOCK	g_read_write_lock;
 
FORCEINLINE VOID InitializeListHead(PLIST_ENTRY ListHead)
{
	ListHead->Flink = ListHead->Blink = ListHead;
	return;
}

CFORCEINLINE BOOLEAN  IsListEmpty(const LIST_ENTRY * ListHead)
{
	return (BOOLEAN)(ListHead->Flink == ListHead);
}

FORCEINLINE PLIST_ENTRY RemoveListEntry(PLIST_ENTRY ListHead)
{
	if ((((ListHead->Flink)->Blink) != ListHead) || (((ListHead->Blink)->Flink) != ListHead))
	{
		return NULL;
	}

	if (IsListEmpty(ListHead))
	{
		return NULL;
	}

	ListHead->Flink->Blink = ListHead->Blink;
	ListHead->Blink->Flink = ListHead->Flink;
	return ListHead;
}

FORCEINLINE BOOLEAN InsertHeadList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry)
{
	if ((((ListHead->Flink)->Blink) != ListHead) || (((ListHead->Blink)->Flink) != ListHead))
	{
		return FALSE;
	}

	Entry->Flink = ListHead->Flink;
	Entry->Blink = ListHead;
	ListHead->Flink->Blink = Entry;
	ListHead->Flink = Entry;

	return TRUE;
}

PPROCESS_USERNAME find_uname_by_pid(DWORD pid)
{
	PLIST_ENTRY			plist = g_p2u_list.Flink;
	PPROCESS_USERNAME   p_p2u = NULL;
	lock_read(&g_read_write_lock);
	while (plist != &g_p2u_list)
	{
		if (((PPROCESS_USERNAME)plist)->pid == pid)
		{
			p_p2u = (PPROCESS_USERNAME)plist;
			break;
		}
		plist = plist->Flink;
	}
	unlock_read(&g_read_write_lock);
	return p_p2u;
}

BOOLEAN insert_to_p2u_list(DWORD pid, const WCHAR* user_name)
{
	PPROCESS_USERNAME p_info = NULL;
	BOOLEAN ret = FALSE;
	if (user_name == NULL || wcslen(user_name) >= MAX_PATH)
	{
		return FALSE;
	}

	if (find_uname_by_pid(pid))
	{
		return FALSE;
	}

	p_info = (PPROCESS_USERNAME)malloc(sizeof(PROCESS_USERNAME));
	if (NULL == p_info)
	{
		return FALSE;
	}
	RtlZeroMemory(p_info, sizeof(PROCESS_USERNAME));
	p_info->pid = pid;
	wcscpy_s(p_info->user_name, MAX_PATH, user_name);
	lock_write(&g_read_write_lock);
	ret = InsertHeadList(&g_p2u_list, &p_info->list_entry);
	unlock_write(&g_read_write_lock);
	return  ret;
}

void delete_entry_by_pid(DWORD pid)
{
	PLIST_ENTRY			plist = g_p2u_list.Flink;
	PPROCESS_USERNAME   p_p2u = NULL;
	lock_write(&g_read_write_lock);
	while (plist != &g_p2u_list)
	{
		if (((PPROCESS_USERNAME)plist)->pid == pid)
		{
			p_p2u = (PPROCESS_USERNAME)plist;
			break;
		}
		plist = plist->Flink;
	}

	if (p_p2u)
	{
		plist = RemoveListEntry(&p_p2u->list_entry);
		if (plist)
		{
			free(plist);
		}
	}
	unlock_write(&g_read_write_lock);
}

VOID destry_p2u_list()
{
	PLIST_ENTRY plist = NULL;
	lock_write(&g_read_write_lock);
	while (!IsListEmpty(&g_p2u_list))
	{
		plist = RemoveListEntry(g_p2u_list.Flink);
		if (plist)
		{
			free(plist);
			plist = NULL;
		}
	}
	unlock_write(&g_read_write_lock);
}

BOOLEAN get_user_name_by_pid_ex(HANDLE pid, WCHAR* sz_user_name)
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
		//	printf("OpenProcess %d error: %u\n", (DWORD)pid, GetLastError());
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

BOOLEAN get_user_name_by_pid(HANDLE pid, WCHAR* sz_user_name)
{
	PPROCESS_USERNAME   p_p2u = NULL;

	p_p2u = find_uname_by_pid((DWORD)pid);
	if (p_p2u)
	{
		wcscpy_s(sz_user_name, MAX_PATH, p_p2u->user_name); 
		return TRUE;
	}

	if (get_user_name_by_pid_ex(pid, sz_user_name))
	{
		insert_to_p2u_list((DWORD)pid, sz_user_name);
		return TRUE;
	}

	return FALSE;
}

void init_user_list()
{
	init_rwlock(&g_read_write_lock);
	InitializeListHead(&g_p2u_list);
}

void uninit_user_list()
{
	uninit_rwlock(&g_read_write_lock);
	destry_p2u_list();
}