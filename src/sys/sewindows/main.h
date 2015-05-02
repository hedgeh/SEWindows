#pragma once
#include <fltKernel.h>


#pragma warning( disable:4127 4305 4100 4201)
#define  MAXPATHLEN         260        // 文件|进程|注册表最大长度
#define  MAXNAMELEN         64         // 用户名最大长度

#define _DEVICE_NAME L"\\Device\\"
#define _DEVICE_DOSNAME L"\\DosDevices\\"

#define IOCTL_STOP_ALL				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_START_ALL				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1002, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_INTERCEPT_MODE	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1003, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_START_PROCMONITOR		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1004, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PAUSE_PROCMONITOR		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1005, METHOD_BUFFERED, FILE_ANY_ACCESS)  
#define IOCTL_START_REGMONITOR		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1006, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PAUSE_REGMONITOR		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1007, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_START_FILEMONITOR		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1008, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PAUSE_FILEMONITOR		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1009, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STOP_UNLOAD			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1010, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PERMIT_UNLOAD			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1011, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_NOTIFY_MODE		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1012, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TRANSFER_SYSROOT		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1013, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_HOOK			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1014, METHOD_BUFFERED, FILE_ANY_ACCESS) 
#define	IOCTL_FROM_R3MSG			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1100, METHOD_BUFFERED, FILE_ANY_ACCESS) 

typedef NTSTATUS(*QUERY_INFO_PROCESS) (HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

typedef NTSTATUS
(*fn_NtQueryInformationThread)(
    __in HANDLE ThreadHandle,
    __in THREADINFOCLASS ThreadInformationClass,
    __out_bcount(ThreadInformationLength) PVOID ThreadInformation,
    __in ULONG ThreadInformationLength,
    __out_opt PULONG ReturnLength
    );

typedef	struct _PATH_TABLE
{
	WCHAR dos_name[3];
	WCHAR nt_name[40];
}PATH_TABLE,*PPATH_TABLE;


typedef struct _HIPS_RULE_NODE
{
	UCHAR		major_type;
	UCHAR		minor_type;
	UCHAR		is_dir;
	HANDLE		sub_pid;
	union
	{
		HANDLE		obj_pid;
	};
	WCHAR		des_path[MAXPATHLEN];
	union
	{
		FILE_BASIC_INFORMATION	fbi;
		WCHAR		new_name[MAXPATHLEN];
		WCHAR		key_value[MAXPATHLEN];
		WCHAR		service_name[MAXPATHLEN];
	};

} HIPS_RULE_NODE, *PHIPS_RULE_NODE;
typedef struct _USER_DATA
{
	UCHAR		option;
	union
	{
		HIPS_RULE_NODE rule_node;
	};
} USER_DATA, *PUSER_DATA;

#define	NONE_OP		0
#define	PROC_OP		1
#define	REG_OP		2
#define	FILE_OP		3



#define	OPTION_TO_JUGE		1
#define	OPTION_TO_NOTIFY	2
#define	OPTION_PROC_EXIT	3
#define	OPTION_TIME_TO_HOOK	4


extern PATH_TABLE			g_path_table[26];
extern HANDLE				g_current_pid;
extern BOOLEAN				g_is_reg_run;
extern BOOLEAN				g_is_proc_run;
extern BOOLEAN				g_is_file_run;
extern PDRIVER_OBJECT		g_driver_obj;
extern PDEVICE_OBJECT		g_device_obj;
extern WCHAR				g_port_name[MAXNAMELEN];
extern WCHAR				g_symbol_name[MAXNAMELEN];
extern BOOLEAN				g_is_unload_allowed;
extern WCHAR				g_service_name[MAXNAMELEN];
extern WCHAR				g_white_process[6][MAXPATHLEN];
extern BOOLEAN				g_is_notify_mode;

PWCHAR get_proc_name_by_pid(IN  HANDLE   dwProcessId, PWCHAR pPath);
BOOLEAN is_process_in_white_list(HANDLE pid);

extern QUERY_INFO_PROCESS			g_ZwQueryInformationProcess ;
extern fn_NtQueryInformationThread  g_zwQueryInformationThread;