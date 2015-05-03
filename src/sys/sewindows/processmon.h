#pragma once
                 
#define  OP_PROC_KILL						1  // 杀死进程                          
#define  OP_PROC_CREATE_REMOTE_THREAD		2  // 远程线程程创建                     
#define  OP_PROC_READ_PROCESS				3  // 进程读操作             
#define  OP_PROC_WRITE_PROCESS				4  // 进程写操作  
#define  OP_PROC_CREATE_PROCESS				5  // 进程创建操作  
#define  OP_PROC_CHANGE_VM					6  // 修改内存属性 
#define  OP_PROC_SUSPEND_RESUME				7  // 挂起进程
#define  OP_THREAD_KILL						8  // 杀死线程
#define  OP_THREAD_SUSPEND_RESUME			9  // 恢复线程
#define  OP_THREAD_GET_CONTEXT				10  // 获取CONTEXT
#define  OP_THREAD_SET_CONTEXT				11  // 设置CONTEXT
#define  OP_PROC_DUPHANDLE				    12  // 复制句柄



#define PROCESS_TERMINATE                  (0x0001)  
#define PROCESS_CREATE_THREAD              (0x0002)  
#define PROCESS_SET_SESSIONID              (0x0004)  
#define PROCESS_VM_OPERATION               (0x0008)  
#define PROCESS_VM_READ                    (0x0010)  
#define PROCESS_VM_WRITE                   (0x0020)  
#define PROCESS_DUP_HANDLE                 (0x0040)  
#define PROCESS_CREATE_PROCESS             (0x0080)  
#define PROCESS_SET_QUOTA                  (0x0100)  
#define PROCESS_SET_INFORMATION            (0x0200)  
#define PROCESS_QUERY_INFORMATION          (0x0400)  
#define PROCESS_SUSPEND_RESUME             (0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)  
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)  

#define THREAD_TERMINATE                 (0x0001)  
#define THREAD_SUSPEND_RESUME            (0x0002)  
#define THREAD_GET_CONTEXT               (0x0008)  
#define THREAD_SET_CONTEXT               (0x0010)  
#define THREAD_QUERY_INFORMATION         (0x0040)  
#define THREAD_SET_INFORMATION           (0x0020)  
#define THREAD_SET_THREAD_TOKEN          (0x0080)
#define THREAD_IMPERSONATE               (0x0100)
#define THREAD_DIRECT_IMPERSONATION      (0x0200)
// begin_wdm
#define THREAD_SET_LIMITED_INFORMATION   (0x0400)  // winnt
#define THREAD_QUERY_LIMITED_INFORMATION (0x0800)  // winnt
#define THREAD_RESUME                    (0x1000)  // winnt

NTSTATUS sw_init_procss(PDRIVER_OBJECT pDriverObj);
NTSTATUS sw_uninit_procss(PDRIVER_OBJECT pDriverObj);


#if (NTDDI_VERSION >= NTDDI_VISTA)
OB_PREOP_CALLBACK_STATUS pre_procopration_callback( PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation);
VOID create_process_notity_routine( PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);

#else

#ifndef _WIN64
NTSTATUS del_pid_from_list(__in HANDLE pid);
void un_init_process_list();
#endif 
#endif

