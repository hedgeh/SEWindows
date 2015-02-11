#ifndef _USER_LIST_HEADER_H
#define _USER_LIST_HEADER_H
#include <Windows.h>

typedef struct _PROCESS_USERNAME
{
	LIST_ENTRY	list_entry;
	DWORD		pid;
	WCHAR		user_name[MAX_PATH];
} PROCESS_USERNAME, *PPROCESS_USERNAME;

BOOLEAN get_user_name_by_pid(HANDLE pid, WCHAR* sz_user_name);
void	init_user_list();
void	uninit_user_list();
void	delete_entry_by_pid(DWORD pid);

#endif