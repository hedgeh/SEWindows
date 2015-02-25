/*
  intercept_example : intercept file create

  --dir-------intercept_example.exe
         |----sewindows.sys
         |----sewindows.dll
*/

#include <stdio.h>
#include <tchar.h>
#include <locale.h>
#include <windows.h>
#include "sewindows.h"

#pragma comment(lib,"Advapi32.lib") 
#pragma comment(lib,"User32.lib") 

typedef BOOLEAN(*fsewin_init)();
typedef BOOLEAN(*fsewin_setoption)(int mode, int type);
typedef BOOLEAN(*fsewin_register_opt)(struct sewin_operations *ops);

fsewin_init         monitor_sewin_init;
fsewin_setoption    monitor_sewin_setoption;
fsewin_register_opt monitor_sewin_register_opt;

BOOLEAN  monitor_file_create(WCHAR *user_name, WCHAR *process, WCHAR *file_path)
{
    WCHAR *mon_dir = _T("C:\\test");
    
    /**
     * not allow create file on "C:\\test"
     */
    if (_tcsnicmp(file_path, mon_dir, wcslen(mon_dir)) == 0)
    {
        wprintf(_T("User=%s, Process=%s, file=%s\n"), user_name, process, file_path);
        return FALSE;
    }
    
    return TRUE;
}

int _tmain(int argc, TCHAR * argv[])
{
    int   ret   = 0;
    sewin_operations ops;
    HMODULE handle;

    setlocale(LC_ALL, "chs");

    // step1. loadLibrary sewindows.dll
    handle                     = LoadLibrary(_T("sewindows.dll"));
    monitor_sewin_init         = (fsewin_init)GetProcAddress(handle, "sewin_init");
    monitor_sewin_setoption    = (fsewin_setoption)GetProcAddress(handle, "sewin_setoption");
    monitor_sewin_register_opt = (fsewin_register_opt)GetProcAddress(handle, "sewin_register_opt");

    if (monitor_sewin_init == NULL || monitor_sewin_setoption == NULL || monitor_sewin_register_opt == NULL)
    {
        return -1;
    }

    // step2. init sewindows
    BOOLEAN bret = monitor_sewin_init();
    if ( !bret )
    {
        return -2;
    }

    // step3. set options
    //monitor_sewin_setoption(SEWIN_MODE_NOTIFY, SEWIN_TYPE_FILE|SEWIN_TYPE_PROC|SEWIN_TYPE_REG);
    monitor_sewin_setoption(SEWIN_MODE_INTERCEPT, SEWIN_TYPE_FILE);
    
    // step4. register callbak functions
    memset(&ops, 0x00, sizeof(struct sewin_operations));
    ops.file_create = monitor_file_create;
    monitor_sewin_register_opt(&ops);

    printf("Start Working (Ctrl + 'C' to exists) ...\n");

    while(1){
        Sleep(3000);
    }

    return 0;
}
