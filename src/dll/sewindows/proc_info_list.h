#ifndef _USER_LIST_HEADER_H
#define _USER_LIST_HEADER_H
#include <Windows.h>

BOOLEAN get_proc_info_by_pid(HANDLE pid, WCHAR* sz_user_name, WCHAR* sz_proc_path);
void	init_user_list();
void	uninit_user_list();
void	delete_entry_by_pid(DWORD pid);
//void	add_entry_by_pid(DWORD pid);
void	bulid_p2u_map();
//BOOLEAN insert_to_procinfo_list(DWORD pid, const WCHAR* user_name,const WCHAR* proc_path);
BOOLEAN inject_dll_by_pid(DWORD pid, BOOLEAN bOnlyCui);
//void	PrintBST1();
#endif