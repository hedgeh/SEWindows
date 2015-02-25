# SEWindows SDK接口文档

## SDK说明
		在Windows上建立一个开源的强制访问控制框架及SDK。使Windows平台的应用开发者，
		可以不用关心操作系统底层技术，只用进行简单的SDK调用或配置就可以保护自己的应用程序。

## 接口说明

### SDK依赖文件
		1、sewindows.sys  驱动
		2、sewindows.dll  动态库
		3、sewindows.h    头文件

### SDK初始化:sewin_init
		初始化函数，在使用SDK之前调用。
#### 函数定义
		SEWINDOWS_API BOOLEAN sewin_init(void);
#### 参数
		无参数
#### 返回值
		TRUE  : 成功
		FALSE : 失败
#### 备注
		版本   : win7、win8、win2008
		头文件 : sewindows.h
		库     : sewindows.dll、sewindows.sys
#### 示例
		BOOLEAN bret = sewin_init();
		if ( !bret )
		{
		    exit(0);
		}


### SDK设置工作模式:sewin_setoption
		设置SDK的工作模式为“通知模式”或者“拦截模式”。
#### 函数定义
		SEWINDOWS_API BOOLEAN sewin_setoption(int mode, int type);
#### 参数
		mode [IN] : 工作模式
		    --SEWIN_MODE_INTERCEPT
		      拦截模式，SDK会根据sewin_operations.function()的返回值决定对某个
		      操作“放行”或者“拦截”。
		    --SEWIN_MODE_NOTIFY
		      通知模式，SDK只会将sewin_operations.function()的操作信息进行通知，
		      不会根据返回值进行拦截。
		type [IN]
		    --SEWIN_TYPE_FILE
		      设置此标识，SDK会对文件（夹）操作进行“拦截”或“通知”。
		    --SEWIN_TYPE_PROC
		      设置此标识，SDK会对进程操作进行“拦截”或“通知”。
		    --SEWIN_TYPE_REG
		      设置此标识，SDK会对进注册表操作进行“拦截”或“通知”。
		
		注： 
		    type支持“或”操作，即下面情形是合法的：
		    type = SEWIN_TYPE_FILE | SEWIN_TYPE_PROC | SEWIN_TYPE_REG
		      
#### 返回值
		TRUE  : 成功
		FALSE : 失败
#### 备注
		版本   : win7
		头文件 : sewindows.h
		库     : sewindows.dll、sewindows.sys
#### 示例
		BOOLEAN bret = sewin_setoption(SEWIN_MODE_NOTIFY, SEWIN_TYPE_FILE | SEWIN_TYPE_PROC);
		if ( !bret )
		{
		    exit(0);
		}


### SDK注册自定义处理函数:sewin_register_opt
		将用户自定义的函数注册到SDK中(每个SDK中，只能有一份注册函数)，当SDK捕获到系统操作后，
		会调用用户自定义的函数，交由用户进行处理，并在“拦截模式”下，根据用户的返回值决定对该
		操作进行“拦截”或者“放行”。
		
		“拦截模式下”，用户自定义函数返回“TRUE”，SDK会对该操作“放行”；
		“拦截模式下”，用户自定义函数返回“FALSE”，SDK会对该操作“拦截”。
#### 函数定义
		SEWINDOWS_API BOOLEAN sewin_register_opt(struct sewin_operations *ops);
#### 参数
		ops [IN] : 自定义的处理函数集合
		    struct sewin_operations {
		        // 文件 - 创建
		        BOOLEAN(*file_create)           (WCHAR *user_name, WCHAR *process, WCHAR *file_path);
		        // 文件 - 删除
		        BOOLEAN(*file_unlink)           (WCHAR *user_name, WCHAR *process, WCHAR *file_path);
		        // 文件 - 设置属性
		        BOOLEAN(*file_set_attr)         (WCHAR *user_name, WCHAR *process, WCHAR *file_path, PFILE_BASIC_INFORMATION pfbi);
		        // 文件 - 读
		        BOOLEAN(*file_read)             (WCHAR *user_name, WCHAR *process, WCHAR *file_path);
		        // 文件 - 写
		        BOOLEAN(*file_write)            (WCHAR *user_name, WCHAR *process, WCHAR *file_path);
		        // 文件 - 重命名
		        BOOLEAN(*file_rename)           (WCHAR *user_name, WCHAR *process, WCHAR *src_file, WCHAR *new_name);
		        // 文件 - 执行
		        BOOLEAN(*file_execute)          (WCHAR *user_name, WCHAR *process, WCHAR *file_path);
		
		        // 文件夹 - 创建
		        BOOLEAN(*dir_create)            (WCHAR *user_name, WCHAR *process, WCHAR *dir_path);
		        // 文件夹 - 删除
		        BOOLEAN(*dir_unlink)            (WCHAR *user_name, WCHAR *process, WCHAR *dir_path);
		        // 文件夹 - 设置属性
		        BOOLEAN(*dir_set_attr)          (WCHAR *user_name, WCHAR *process, WCHAR *dir_path, PFILE_BASIC_INFORMATION pfbi);
		        // 文件夹 - 重命名
		        BOOLEAN(*dir_rename)            (WCHAR *user_name, WCHAR *process, WCHAR *src_dir, WCHAR *new_name);
		
		        // 进程 - 创建
		        BOOLEAN(*process_create)        (WCHAR *user_name, WCHAR *process, WCHAR *dst_proc);
		        // 进程 - 线程创建
		        BOOLEAN(*process_create_thread) (WCHAR *user_name, WCHAR *process, WCHAR *dst_proc);
		        // 进程 - 进程结束
		        BOOLEAN(*process_kill)          (WCHAR *user_name, WCHAR *process, WCHAR *dst_proc);
		        // 进程 - 读取内存
		        BOOLEAN(*process_read_mem)      (WCHAR *user_name, WCHAR *process, WCHAR *dst_proc);
		        // 进程 - 修改内存
		        BOOLEAN(*process_write_mem)     (WCHAR *user_name, WCHAR *process, WCHAR *dst_proc);
		        // 进程 - 设置属性
		        BOOLEAN(*process_set_mem_attr)  (WCHAR *user_name, WCHAR *process, WCHAR *dst_proc);
		        
		        // 注册表 - 创建项
		        BOOLEAN(*reg_create_key)        (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		        // 注册表 - 删除项
		        BOOLEAN(*reg_delete_key)        (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		        // 注册表 - 枚举项
		        BOOLEAN(*reg_enum_key)          (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		        // 注册表 - 重命名项
		        BOOLEAN(*reg_rename_key)        (WCHAR *user_name, WCHAR *process, WCHAR *src_path, WCHAR *new_name);
		        // 注册表 - 设置值
		        BOOLEAN(*reg_set_value)         (WCHAR *user_name, WCHAR *process, WCHAR *reg_path, WCHAR *reg_value);
		        // 注册表 - 删除值
		        BOOLEAN(*reg_delete_value)      (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		        // 注册表 - 读取项
		        BOOLEAN(*reg_read_key)          (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		        // 注册表 - 枚举值
		        BOOLEAN(*reg_enum_value)        (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		        // 注册表 - 导出文件
		        BOOLEAN(*reg_save_key)          (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		        // 注册表 - 从文件导入
		        BOOLEAN(*reg_restore_key)       (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		        // 注册表 - 替换
		        BOOLEAN(*reg_replace)           (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		        // 注册表 - 从磁盘加载注册表文件
		        BOOLEAN(*reg_load_key)          (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		        // 注册表 - 导出注册表项到磁盘
		        BOOLEAN(*reg_unload_key)        (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		    };
		    
		    typedef struct _FILE_BASIC_INFORMATION {
		        LARGE_INTEGER CreationTime;
		        LARGE_INTEGER LastAccessTime;
		        LARGE_INTEGER LastWriteTime;
		        LARGE_INTEGER ChangeTime;
		        ULONG         FileAttributes;
		    } FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;
#### 返回值
		TRUE  : 成功
		FALSE : 失败
#### 备注
		版本   : win7
		头文件 : sewindows.h
		库     : sewindows.dll、sewindows.sys
#### 示例
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

