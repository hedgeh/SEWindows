#pragma once

#define  OP_REG_READ						1  // ×¢²á±í¶Á
#define  OP_REG_DELETE_VALUE_KEY			3  // É¾³ý¼üÖµ
#define  OP_REG_CREATE_KEY                  4  // ´´½¨¼ü
#define  OP_REG_SET_VALUE_KEY				5  // ÉèÖÃ¼üÖµ
#define  OP_REG_RENAME						6  // ÖØÃüÃû
#define  OP_REG_DELETE_KEY                  7  // É¾³ý¼ü
#define  OP_REG_SAVE						8  // ±£´æ
#define  OP_REG_RESTORE						9 // »Ö¸´
#define  OP_REG_REPLACE						10 // Ìæ»»
#define  OP_REG_LOAD						11 // ¼ÓÔØ
#define  OP_REG_UNLOAD						12 // Ð¶ÔØ

NTSTATUS sw_register_init(PDRIVER_OBJECT pDriverObject);
NTSTATUS sw_register_uninit(PDRIVER_OBJECT pDriverObject);
NTSTATUS reg_create_key(const WCHAR* szRegPath,const WCHAR* szSubPath);
BOOLEAN IsRegKeyExist(const WCHAR *szKey);
NTSTATUS reg_set_value_key(const WCHAR *szKey, const WCHAR *szValueName, ULONG type,PVOID data,ULONG dataSize);
NTSTATUS reg_delete_value_key(const WCHAR *szKey,const WCHAR* szSubKey);
PKEY_VALUE_PARTIAL_INFORMATION reg_query_value_key(const WCHAR *szKey, const WCHAR *szValueName);
BOOLEAN AddInjectPathToReg( WCHAR* szDllPath);
BOOLEAN DelInjectPathToReg( WCHAR* szDllPath);
//VOID ActivityWatchDog(PVOID Context);