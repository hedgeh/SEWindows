// sewindows_test.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include "../sewindows/sewindows.h"
#include <atlstr.h>


typedef void(*funinit_sewindows)();
typedef BOOLEAN(*finit_sewindows)();
typedef BOOLEAN(*fsewin_setoption)(int mode, int type);
typedef BOOLEAN(*fsewin_register_opt)(struct sewin_operations *ops);

finit_sewindows		myinit_sewindows;
funinit_sewindows	myuninit_sewindows;
fsewin_setoption	mysewin_setoption;
fsewin_register_opt mysewin_register_opt;

sewin_operations	g_sewin_operation;



BOOLEAN  my_file_creat	(WCHAR *user_name, WCHAR *process, WCHAR *file_path)
{
	//C:\Users\you\Desktop\ProcessHacker.exe
	if (_wcsicmp(process, L"C:\\Users\\you\\Desktop\\ProcessHacker.exe") == 0)
	{
		printf("user:%S\nprocess:%S\nfile_path:%S\n----------\n", user_name, process, file_path);
		return FALSE;
	}
	//	printf("%S\n", file_path);
	printf("user:%S\nprocess:%S\nfile_path:%S\n----------\n",user_name, process, file_path);
	return TRUE;
}

BOOLEAN  my_file_set(WCHAR *user_name, WCHAR *process, WCHAR *file_path, PFILE_BASIC_INFORMATION pfbi)
{
	static int i = 0;
	//if (_wcsicmp(file_path, L"C:\\create_dir_test") == 0)
	//{
	//	printf("%d\n", i++);
	//	return FALSE;
	//}
	////	printf("%S\n", file_path);
	//printf("process:%S\nfile_path:%S\n", process, file_path);
	//return TRUE;


	if (_wcsicmp(file_path, L"HKEY_USERS\\S-1-5-21-1431085315-574252236-1710062456-1000\\SOFTWARE\\yyhipstest") == 0)
	{
		printf("%d\n", i++);
		return FALSE;
	}
	printf("%S\n", file_path);
	printf("process:%S\nfile_path:%S\n", process, file_path);

	return TRUE;
}

BOOLEAN myfile_rename (WCHAR *user_name, WCHAR *process, WCHAR *src_file, WCHAR *new_name)
{
	static int i = 0;
	if (_wcsicmp(src_file, L"C:\\create_dir_test") == 0)
	{
		printf("%d\n", i++);
		return FALSE;
	}

//	static int i = 0;
	if (_wcsicmp(src_file, L"HKEY_USERS\\S-1-5-21-1431085315-574252236-1710062456-1000\\SOFTWARE\\yyhipstest\\REG_DWORD") == 0)
	{
		printf("%d\n", i++);
		return FALSE;
	}
	printf("%S\n", src_file);
	printf("process:%S\nfile_path:%S\n", process, src_file);
	return TRUE;
}


int _tmain(int argc, _TCHAR* argv[])
{
	HMODULE hMod = LoadLibrary(_T("sewindows.dll"));
	myinit_sewindows = (finit_sewindows)GetProcAddress(hMod, "sewin_init");
	mysewin_setoption = (fsewin_setoption)GetProcAddress(hMod, "sewin_setoption");
	mysewin_register_opt = (fsewin_register_opt)GetProcAddress(hMod, "sewin_register_opt");
	if (myinit_sewindows == NULL || mysewin_setoption == NULL || mysewin_register_opt == NULL)
	{
		return -1;
	}
	BOOLEAN ret = myinit_sewindows();
	if (!ret)
	{
		return -1;
	}
	RtlZeroMemory(&g_sewin_operation, sizeof(g_sewin_operation));
	mysewin_setoption(SEWIN_MODE_INTERCEPT, SEWIN_TYPE_REG | SEWIN_TYPE_FILE | SEWIN_TYPE_FROC);
	/*g_sewin_operation.reg_read_key = my_file_creat;
	g_sewin_operation.reg_create_key = my_file_creat;
	g_sewin_operation.reg_delete_value = my_file_creat;*/
	/*g_sewin_operation.process_read_mem = my_file_creat;
	g_sewin_operation.process_create_thread = my_file_creat;
	g_sewin_operation.process_create = my_file_creat;
	g_sewin_operation.process_kill = my_file_creat;
	g_sewin_operation.process_set_mem_attr = my_file_creat;*/
	/*g_sewin_operation.thread_kill = my_file_creat;
	g_sewin_operation.thread_susresume = my_file_creat;*/

	//g_sewin_operation.file_read = my_file_creat;
	//g_sewin_operation.file_write = my_file_creat;

	//g_sewin_operation.file_unlink = my_file_creat;
	g_sewin_operation.file_execute = my_file_creat;
	mysewin_register_opt(&g_sewin_operation);
	

	printf("print 'q' to quit!!\n");
	while (getchar() != 'q');
	FreeLibrary(hMod);
	return 0;
}

