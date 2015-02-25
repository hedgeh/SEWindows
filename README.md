# SEWindows
在Windows上建立一个开源的强制访问控制框架及SDK。使Windows平台的应用开发者，可以不用关心操作系统底层技术，只用进行简单的SDK调用或配置就可以保护自己的应用程序。

## 跟我学如何使用SEWindows SDK

### 第一步:包含头文件"sewindows.h"，并从sewindows.dll中导出接口函数
		// 包含头文件
		#include "sewindows.h"
		
		// 定义导出函数
		typedef BOOLEAN(*fsewin_init)();
		typedef BOOLEAN(*fsewin_setoption)(int mode, int type);
		typedef BOOLEAN(*fsewin_register_opt)(struct sewin_operations *ops);
		
		fsewin_init         monitor_sewin_init;
		fsewin_setoption    monitor_sewin_setoption;
		fsewin_register_opt monitor_sewin_register_opt;
		
		// 从动态库sewindows.dll中导出接口函数
		HMODULE handle;	
		handle                     = LoadLibrary(_T("sewindows.dll"));
		monitor_sewin_init         = (fsewin_init)GetProcAddress(handle, "sewin_init");
		monitor_sewin_setoption    = (fsewin_setoption)GetProcAddress(handle, "sewin_setoption");
		monitor_sewin_register_opt = (fsewin_register_opt)GetProcAddress(handle, "sewin_register_opt");
		
		if (monitor_sewin_init == NULL || monitor_sewin_setoption == NULL || monitor_sewin_register_opt == NULL)
		{
		    exit(0);
		}


### 第二步:初始化SDK
		BOOLEAN bret = monitor_sewin_init();
		if ( !bret )
		{
		     exit(0);
		}


### 第三步:设置SDK模式和操作对象
		// 设置模式为“通知模式”，设置类型为“文件(夹)”操作
		monitor_sewin_setoption(SEWIN_MODE_NOTIFY, SEWIN_TYPE_FILE);		


### 第四步:注册回调函数，处理感兴趣的操作
		//我们先定义一个自己的回调函数，用来打印文件创建操作的信息		
		BOOLEAN  monitor_file_create(WCHAR *user_name, WCHAR *process, WCHAR *file_path)
		{
		    wprintf(_T("User=%s, Process=%s, file=%s\n"), user_name, process, file_path);
		    return TRUE;
		}
		
		// 注册monitor_file_create到SDK中
		sewin_operations ops;
		memset(&ops, 0x00, sizeof(struct sewin_operations));
		ops.file_create = monitor_file_create;
		monitor_sewin_register_opt(&ops);


### 第五步:编译运行
		将编译的exe文件和sewindows.sys，sewindows.dll拷贝到同一个目录，运行exe，就可以看到下面效果啦:
		  User=LZF-A87A7288234\Administrator, Process=C:\WINDOWS\explorer.exe, file=C:\新建 文本文档.txt
		  User=LZF-A87A7288234\Administrator, Process=C:\WINDOWS\explorer.exe, file=C:\新建 RTF 文档.rtf
		  User=LZF-A87A7288234\Administrator, Process=C:\WINDOWS\explorer.exe, file=C:\新建 写字板文档.doc
		
		注:
		  回调函数的调用过程是多线程的，所有如果你的回调函数中有公用的内容，需要自己处理好同步。


### 完整示例:
		下面是一个完整的示例，演示了使用SDK对文件的创建操作进行通知，并在用户自定义函数中打印了收到的
		操作详细信息。
		
		/*                                  
		  notify_example : print file create
		  --dir-------notify_example.exe    
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
		    wprintf(_T("User=%s, Process=%s, file=%s\n"), user_name, process, file_path);
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
		    //monitor_sewin_setoption(SEWIN_MODE_INTERCEPT, SEWIN_TYPE_FILE|SEWIN_TYPE_PROC|SEWIN_TYPE_REG);
		    monitor_sewin_setoption(SEWIN_MODE_NOTIFY, SEWIN_TYPE_FILE);
		    
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
	


  
  