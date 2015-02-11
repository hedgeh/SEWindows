#pragma once
#include "sewindows.h"
#define  MAXPATHLEN         MAX_PATH    // 文件|进程|注册表最大长度
#define  MAXNAMELEN         64         // 用户名最大长度

#define	NONE_OP		0
#define	PROC_OP		1
#define	REG_OP		2
#define	FILE_OP		3

#define	OPTION_TO_JUGE		1
#define	OPTION_TO_NOTIFY	2
#define	OPTION_PROC_EXIT	3

#define	FILE_READ_DATA_XX		1
#define	FILE_WRITE_DATA_XX		2
#define	FILE_DEL_XX				3
#define	FILE_RENAME_XX			4
#define	FILE_CREATE_XX			5
#define	FILE_SETINFO_XX			6
#define	FILE_EXECUTE_XX			7

#define  OP_PROC_KILL                      1  // 杀死进程                          
#define  OP_PROC_CREATE_REMOTE_THREAD      2  // 远程线程程创建                     
#define  OP_PROC_READ_PROCESS              3  // 进程读操作             
#define  OP_PROC_WRITE_PROCESS             4  // 进程写操作  
#define  OP_PROC_CREATE_PROCESS            5  // 进程创建操作  
#define  OP_PROC_CHANGE_VM				   6  // 修改内存属性 

#define  OP_REG_READ						1  // 注册表读
#define  OP_REG_DELETE_VALUE_KEY			3  // 删除键值
#define  OP_REG_CREATE_KEY                  4  // 创建键
#define  OP_REG_SET_VALUE_KEY				5  // 设置键值
#define  OP_REG_RENAME						6  // 重命名
#define  OP_REG_DELETE_KEY                  7  // 删除键
#define  OP_REG_SAVE						8  // 保存
#define  OP_REG_RESTORE						9 // 恢复
#define  OP_REG_REPLACE						10 // 替换
#define  OP_REG_LOAD						11 // 加载
#define  OP_REG_UNLOAD						12 // 卸载


typedef struct _HIPS_RULE_NODE
{
	UCHAR		major_type;
	UCHAR		minor_type;
	UCHAR		isDir;
	HANDLE		sub_pid;
	union 
	{
		HANDLE		obj_pid;
	};
	WCHAR		src_path[MAXPATHLEN];
	WCHAR		des_path[MAXPATHLEN];
	union 
	{
		FILE_BASIC_INFORMATION	fbi;
		WCHAR		new_name[MAXPATHLEN];
		WCHAR		key_value[MAXPATHLEN];
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


typedef struct _SCANNER_REPLY 
{

	BOOLEAN IsPermitted;

} SCANNER_REPLY, *PSCANNER_REPLY;


typedef struct _SCANNER_MESSAGE 
{
	FILTER_MESSAGE_HEADER MessageHeader;
	USER_DATA Notification;
	OVERLAPPED Ovlp;

} SCANNER_MESSAGE, *PSCANNER_MESSAGE;

typedef struct _SCANNER_REPLY_MESSAGE 
{
	FILTER_REPLY_HEADER ReplyHeader;
	SCANNER_REPLY Reply;
} SCANNER_REPLY_MESSAGE, *PSCANNER_REPLY_MESSAGE;

typedef struct _Param
{
	USER_DATA opdata;
}Param,*PParam;
