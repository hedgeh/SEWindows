# SEWindows
在Windows上建立一个开源的强制访问控制框架及SDK。使Windows平台的应用开发者，可以不用关心操作系统底层技术，只用进行简单的SDK调用或配置就可以保护自己的应用程序。

## 跟我学如何使用SEWindows SDK
完整示例可以参照：
		
https://github.com/hedgeh/SEWindows/blob/develop/examples/simple_example/simple_example.cpp

### 第一步:
		
包含头文件"inc/sewindows.h"，并从sewindows.dll中导出接口函数，
这个过程就不用细说了，实在不会的可以参照例子。（一共只有三个函数）  
从dll中导出了：
初始化函数monitor_sewin_init，
设置函数monitor_sewin_setoption
注册回调的函数monitor_sewin_register_opt。

### 第二步：		
初始化SDK
		
BOOLEAN bret = monitor_sewin_init();

### 第三步：
		
设置SDK，设置函数有两个参数：
第一个参数表示SDK的工作模式，在SEWIN_MODE_INTERCEPT模式下，
    SDK会拦截操作。在SEWIN_MODE_NOTIFY模式下，SDK只是通知，
    不会对操作进行拦截。
第二个参数表示要拦截的对象，SEWIN_TYPE_FILE，SEWIN_TYPE_FROC，
    SEWIN_TYPE_REG分别对应文件、进程、注册表。这个参数支持或操作，
    即可以设置成下面这样：SEWIN_TYPE_FILE|SEWIN_TYPE_FROC|SEWIN_TYPE_REG
我们的示例中只是设置了“对文件的操作进行通知”
		
monitor_sewin_setoption(SEWIN_MODE_NOTIFY, SEWIN_TYPE_FILE);

### 第四步：
		
注册回调函数：
我们先定义一个自己的回调函数，用来打印文件创建操作的信息
		
BOOLEAN  monitor_file_create(WCHAR *user_name, WCHAR *process, WCHAR *file_path)
{
    wprintf(_T("User=%s, Process=%s, file=%s\n"), user_name, process, file_path);
    return TRUE;
}  
sewin_operations ops;
memset(&ops, 0x00, sizeof(struct sewin_operations));
ops.file_create = monitor_file_create;
monitor_sewin_register_opt(&ops);
		
PS:
如果你对其他的操作感兴趣，也可以在注册函数中加入其他的回调函数。
在拦截模式SEWIN_MODE_INTERCEPT下，如果回调函数返回TRUE，该操作会被SDK允许，如果回调函数返回FALSE，该操作会被SDK阻值。
例如我们设置了拦截模式，同时让ops.file_create回调函数总返回FALSE，那么系统的文件创建就不能成功了。

### 第五步：
		
将编译的exe文件和sewindows.sys，sewindows.dll拷贝到同一个目录，运行exe，就可以看到效果啦。
PS：
  1、回调函数的调用过程是多线程的，所有如果你的回调函数中有公用的内存，需要自己处理好同步。

### 现在你已经学会如何使用SEWindows SDK了。
  
  