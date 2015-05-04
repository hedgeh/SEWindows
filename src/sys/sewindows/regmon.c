#include "main.h"
#include "regmon.h"
#include <strsafe.h>
#include <ntstrsafe.h>
#include "lpc.h"
//#include "processmon.h"

typedef struct _LOOK_ASIDE_BUFFER_MNG
{
	PAGED_LOOKASIDE_LIST Lookaside;
	USHORT buflen;
}LOOK_ASIDE_BUFFER_MNG;

typedef struct _CAPTURE_REGISTRY_MANAGER
{
	LARGE_INTEGER  registry_callback_cookie;
	LOOK_ASIDE_BUFFER_MNG  lookaside_req_reg;	
	LOOK_ASIDE_BUFFER_MNG  lookaside_obj_name;	
	LOOK_ASIDE_BUFFER_MNG  lookaside_unicode;	
} CAPTURE_REGISTRY_MANAGER, *PCAPTURE_REGISTRY_MANAGER;

EX_CALLBACK_FUNCTION registry_callback;

static CAPTURE_REGISTRY_MANAGER g_registery_mem_manager;
static BOOLEAN g_bRegistryManager = FALSE;
static BOOLEAN g_RegisterCallback = FALSE;


static BOOLEAN get_registry_name_by_obj(PUNICODE_STRING pRegistryPath, PVOID pRegistryObject)
{
	BOOLEAN foundCompleteName = FALSE;
	NTSTATUS status;
	ULONG returnedLength;
	PUNICODE_STRING pObjectName = NULL;

	if ((!MmIsAddressValid(pRegistryObject)) || (pRegistryObject == NULL))
	{
		return FALSE;
	}

	status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, 0, &returnedLength);
	if (status == STATUS_INFO_LENGTH_MISMATCH && returnedLength < g_registery_mem_manager.lookaside_obj_name.buflen)
	{
		pObjectName = ExAllocateFromPagedLookasideList(&(g_registery_mem_manager.lookaside_obj_name.Lookaside));
		if (pObjectName)
		{
			RtlZeroMemory(pObjectName, g_registery_mem_manager.lookaside_obj_name.buflen);
			status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, returnedLength, &returnedLength);
			if (NT_SUCCESS(status))
			{
				RtlUnicodeStringCopy(pRegistryPath, pObjectName);
				foundCompleteName = TRUE;
			}
			ExFreeToPagedLookasideList(&(g_registery_mem_manager.lookaside_obj_name.Lookaside), pObjectName);
		}
	}
	return foundCompleteName;
}

PWCHAR mywcsistr( PWCHAR s1,const PWCHAR s2)
{
	wchar_t * s = s1;
	wchar_t * p = s2;
    do
	{
		if (!*p)
		{
			return s1;
		}

		if ((*p == *s) || (towlower(*p) == towlower(*s)))
        {
            ++p;
            ++s;
        }
        else
        {
			p = s2;
			if (!*s)
			{
				return NULL;
			}
			s = ++s1;
        }

	} while (1);
    return NULL;
}


 NTSTATUS registry_callback(IN PVOID CallbackContext,IN PVOID  Argument1,IN PVOID  Argument2)
{
	ULONG registryDataLength = 0;
	ULONG registryDataType = 0;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	BOOLEAN registryEventIsValid = FALSE;
	int type;
	UNICODE_STRING registryPath;
	PHIPS_RULE_NODE preq_reg = NULL;

	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return STATUS_SUCCESS;
	}

	if (ExGetPreviousMode() == KernelMode)
	{
		return STATUS_SUCCESS;
	}

	if ((PsGetCurrentProcessId() == (HANDLE)0) || g_current_pid == PsGetCurrentProcessId())
	{
		return STATUS_SUCCESS;
	}

	if (g_is_unload_allowed && PsGetCurrentProcessId() == (HANDLE)4)
	{
		return STATUS_SUCCESS;
	}

	type = (REG_NOTIFY_CLASS)Argument1;
	if (
		type != RegNtPreDeleteKey
		&& type != RegNtPreDeleteValueKey
		&& type != RegNtPreSetValueKey
		&& type != RegNtPreRenameKey
		&& type != RegNtPreEnumerateKey
		&& type != RegNtPreEnumerateValueKey
		&& type != RegNtPreQueryKey
		&& type != RegNtPreCreateKey
		&& type != RegNtQueryValueKey
		&& type != RegNtPreQueryMultipleValueKey 
		&& type != RegNtPreCreateKeyEx 
		&& type != RegNtPreOpenKey
#if (NTDDI_VERSION >= NTDDI_VISTA)
		&& type != RegNtPreSaveKey
		&& type != RegNtPreRestoreKey
		&& type != RegNtPreReplaceKey
		&& type != RegNtPreLoadKey
		&& type != RegNtPreUnLoadKey
#endif
		)
	{
		return STATUS_SUCCESS;
	}
	
	registryPath.Buffer = NULL;
	registryPath.Length = 0;
	registryPath.MaximumLength = 0;
	preq_reg = ExAllocateFromPagedLookasideList(&(g_registery_mem_manager.lookaside_req_reg.Lookaside));
	if (preq_reg == NULL)
	{
		return STATUS_SUCCESS;
	}
	RtlZeroMemory(preq_reg, g_registery_mem_manager.lookaside_req_reg.buflen);
	preq_reg->major_type = REG_OP;
	registryPath.Length = 0;
	registryPath.MaximumLength = g_registery_mem_manager.lookaside_unicode.buflen;
	registryPath.Buffer = ExAllocateFromPagedLookasideList(&(g_registery_mem_manager.lookaside_unicode.Lookaside));
	if (registryPath.Buffer == NULL)
	{
		ExFreeToPagedLookasideList(&(g_registery_mem_manager.lookaside_req_reg.Lookaside), preq_reg);
		return STATUS_SUCCESS;
	}
	RtlZeroMemory(registryPath.Buffer, g_registery_mem_manager.lookaside_unicode.buflen);
	preq_reg->minor_type = 0;
	__try
	{
		switch (type)
		{
		case RegNtPreDeleteKey:
		{	
			PREG_DELETE_KEY_INFORMATION deleteKey = (PREG_DELETE_KEY_INFORMATION)Argument2;
			registryEventIsValid = get_registry_name_by_obj(&registryPath, deleteKey->Object);
			
			preq_reg->minor_type = OP_REG_DELETE_KEY;
			break;
		}
		case RegNtPreCreateKey:
		{	
			PREG_PRE_CREATE_KEY_INFORMATION createKey = (PREG_PRE_CREATE_KEY_INFORMATION)Argument2;
			RtlCopyUnicodeString(&registryPath, createKey->CompleteName);
			preq_reg->minor_type = OP_REG_CREATE_KEY;
			registryEventIsValid = TRUE;
			break;
		}
		case RegNtPreCreateKeyEx:
		{	
			PREG_CREATE_KEY_INFORMATION createKey = (PREG_CREATE_KEY_INFORMATION)Argument2;
			registryEventIsValid = get_registry_name_by_obj(&registryPath, createKey->RootObject);
			RtlUnicodeStringCatString(&registryPath, L"\\");
			RtlAppendUnicodeStringToString(&registryPath, createKey->CompleteName);
			preq_reg->minor_type = OP_REG_CREATE_KEY;
			break;
		}
		case RegNtPreDeleteValueKey:	
		{	
			PREG_DELETE_VALUE_KEY_INFORMATION deleteValueKey = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
			registryEventIsValid = get_registry_name_by_obj(&registryPath, deleteValueKey->Object);
			if ((registryEventIsValid) && (deleteValueKey->ValueName->Length > 0))
			{
				RtlUnicodeStringCatString(&registryPath, L"\\");
				RtlUnicodeStringCat(&registryPath, deleteValueKey->ValueName);
			}
			
			preq_reg->minor_type = OP_REG_DELETE_VALUE_KEY;
			break;
		}
		case RegNtPreSetValueKey:	
		{
			PREG_SET_VALUE_KEY_INFORMATION setValueKey = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
			registryEventIsValid = get_registry_name_by_obj(&registryPath, setValueKey->Object);
			if ((registryEventIsValid) && (setValueKey->ValueName->Length > 0))
			{
				registryDataType = setValueKey->Type;
				registryDataLength = setValueKey->DataSize;
				RtlUnicodeStringCatString(&registryPath, L"\\");
				RtlUnicodeStringCat(&registryPath, setValueKey->ValueName);
			}
			
			preq_reg->minor_type = OP_REG_SET_VALUE_KEY;
			break;
		}
		case RegNtPreRenameKey:
		{
			PREG_RENAME_KEY_INFORMATION renameKey = (PREG_RENAME_KEY_INFORMATION)Argument2;
			registryEventIsValid = get_registry_name_by_obj(&registryPath, renameKey->Object);
			StringCbCopyNW(preq_reg->new_name, sizeof(preq_reg->new_name), renameKey->NewName->Buffer, renameKey->NewName->Length);
			preq_reg->minor_type = OP_REG_RENAME;
			break;
		}
		case RegNtPreEnumerateKey:
		{	
			PREG_ENUMERATE_KEY_INFORMATION enumerateKey = (PREG_ENUMERATE_KEY_INFORMATION)Argument2;
			registryDataType = enumerateKey->KeyInformationClass;
			registryEventIsValid = get_registry_name_by_obj(&registryPath, enumerateKey->Object);
			
			preq_reg->minor_type = OP_REG_READ;
			break;
		}
		case RegNtPreEnumerateValueKey:
		{
			PREG_ENUMERATE_VALUE_KEY_INFORMATION enumerateValueKey = (PREG_ENUMERATE_VALUE_KEY_INFORMATION)Argument2;
			registryDataType = enumerateValueKey->KeyValueInformationClass;
			registryEventIsValid = get_registry_name_by_obj(&registryPath, enumerateValueKey->Object);
			
			preq_reg->minor_type = OP_REG_READ;
			break;
		}
		case RegNtPreQueryKey:	
		{	
			PREG_QUERY_KEY_INFORMATION queryKey = (PREG_QUERY_KEY_INFORMATION)Argument2;
			registryDataType = queryKey->KeyInformationClass;
			registryEventIsValid = get_registry_name_by_obj(&registryPath, queryKey->Object);
			
			preq_reg->minor_type = OP_REG_READ;
			break;
		}
		case RegNtQueryValueKey:
		{	
			PREG_QUERY_VALUE_KEY_INFORMATION queryValueKey = (PREG_QUERY_VALUE_KEY_INFORMATION)Argument2;
			registryEventIsValid = get_registry_name_by_obj(&registryPath, queryValueKey->Object);
			if (registryEventIsValid)
			{
				if (queryValueKey->ValueName->Length > 0)
				{
					registryDataType = queryValueKey->KeyValueInformationClass;
					RtlUnicodeStringCatString(&registryPath, L"\\");
					RtlUnicodeStringCat(&registryPath, queryValueKey->ValueName);
				}
				
				preq_reg->minor_type = OP_REG_READ;
			}
			else
			{
				registryEventIsValid = FALSE;
			}
			break;
		}
		case RegNtPreQueryMultipleValueKey:
		{
			PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION queryMultiple = (PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION)Argument2;
			registryEventIsValid = get_registry_name_by_obj(&registryPath, queryMultiple->Object);
			
			preq_reg->minor_type = OP_REG_READ;
			break;
		}
#if (NTDDI_VERSION >= NTDDI_VISTA)
		case RegNtPreLoadKey:
		{ 
			PREG_LOAD_KEY_INFORMATION queryMultiple = (PREG_LOAD_KEY_INFORMATION)Argument2;
			registryEventIsValid = get_registry_name_by_obj(&registryPath, queryMultiple->Object);

			preq_reg->minor_type = OP_REG_LOAD;
			break;
		}
		case RegNtPreUnLoadKey:
		{
			PREG_UNLOAD_KEY_INFORMATION queryMultiple = (PREG_UNLOAD_KEY_INFORMATION)Argument2;
			registryEventIsValid = get_registry_name_by_obj(&registryPath, queryMultiple->Object);

			preq_reg->minor_type = OP_REG_UNLOAD;
			break;
		}
		case RegNtPreSaveKey:
		{
			PREG_SAVE_KEY_INFORMATION queryMultiple = (PREG_SAVE_KEY_INFORMATION)Argument2;
			registryEventIsValid = get_registry_name_by_obj(&registryPath, queryMultiple->Object);

			preq_reg->minor_type = OP_REG_SAVE;
			break;
		}
		case RegNtPreRestoreKey:
		{
			PREG_RESTORE_KEY_INFORMATION queryMultiple = (PREG_RESTORE_KEY_INFORMATION)Argument2;
			registryEventIsValid = get_registry_name_by_obj(&registryPath, queryMultiple->Object);

			preq_reg->minor_type = OP_REG_RESTORE;
			break;
		}
		case RegNtPreReplaceKey:
		{
			PREG_REPLACE_KEY_INFORMATION pReplace = (PREG_REPLACE_KEY_INFORMATION)Argument2;
			
			registryEventIsValid = get_registry_name_by_obj(&registryPath, pReplace->Object);

			preq_reg->minor_type = OP_REG_REPLACE;
			break;
		}
#endif
		default:
			registryEventIsValid = FALSE;
			break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint(("Reg except \n"));
		registryEventIsValid = FALSE;
	}

	if (registryEventIsValid)
	{
		WCHAR		tmpPath[MAXPATHLEN] = { 0 };
		if (g_is_unload_allowed == FALSE)
		{
			StringCbCopyW(tmpPath, sizeof(WCHAR)*MAXPATHLEN, L"\\Services\\");
			StringCbCatW(tmpPath, sizeof(WCHAR)*MAXPATHLEN, g_service_name);
			
			if (mywcsistr(registryPath.Buffer, tmpPath))
			{
				ntStatus = STATUS_UNSUCCESSFUL;
				goto err_ret;
			}
		}

		if (PsGetCurrentProcessId() == (HANDLE)4 || g_is_reg_run == FALSE)
		{
			goto err_ret;
		}

		if (registryPath.Length < MAXPATHLEN*sizeof(WCHAR))
		{
			StringCbCopyNW(preq_reg->des_path, MAXPATHLEN*sizeof(WCHAR), registryPath.Buffer,registryPath.Length);
		}
		if (type == RegNtPreSetValueKey)
		{	
			PREG_SET_VALUE_KEY_INFORMATION setValueKey = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
			if (setValueKey->Data != NULL && setValueKey->Type == REG_SZ)
			{
				StringCbCopyNW(preq_reg->new_name, sizeof(preq_reg->new_name), setValueKey->Data, setValueKey->DataSize);
			}
		}
		preq_reg->sub_pid = PsGetCurrentProcessId();

		if (preq_reg->minor_type == OP_REG_READ)
		{
			if (is_process_in_white_list(preq_reg->sub_pid))
			{
				goto err_ret;
			}
		}
		
		if (rule_match(preq_reg) == FALSE)
		{
			ntStatus = STATUS_UNSUCCESSFUL;
		}
	}
err_ret:
	if (preq_reg != NULL)
	{
		ExFreeToPagedLookasideList(&(g_registery_mem_manager.lookaside_req_reg.Lookaside), preq_reg);
	}
	if (registryPath.Buffer != NULL)
	{
		ExFreeToPagedLookasideList(&(g_registery_mem_manager.lookaside_unicode.Lookaside), registryPath.Buffer);
	}

	return ntStatus;
}


NTSTATUS sw_register_init(PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	g_registery_mem_manager.lookaside_obj_name.buflen = 1024;
	ExInitializePagedLookasideList(&(g_registery_mem_manager.lookaside_obj_name.Lookaside), NULL, NULL, 0, g_registery_mem_manager.lookaside_obj_name.buflen, 'objn', 0);
	g_registery_mem_manager.lookaside_req_reg.buflen = sizeof(HIPS_RULE_NODE);
	ExInitializePagedLookasideList(&(g_registery_mem_manager.lookaside_req_reg.Lookaside), NULL, NULL, 0, g_registery_mem_manager.lookaside_req_reg.buflen, 'objn', 0);
	g_registery_mem_manager.lookaside_unicode.buflen = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
	ExInitializePagedLookasideList(&(g_registery_mem_manager.lookaside_unicode.Lookaside), NULL, NULL, 0, g_registery_mem_manager.lookaside_unicode.buflen, 'objn', 0);

	g_bRegistryManager = TRUE;
		 
	status = CmRegisterCallback(registry_callback, &g_registery_mem_manager, &(g_registery_mem_manager.registry_callback_cookie));
	if (NT_SUCCESS(status))
	{
		g_RegisterCallback = TRUE;
	}
	return status;
}

NTSTATUS sw_register_uninit(PDRIVER_OBJECT pDriverObject)
{
	DelInjectPathToReg(g_inject_dll);
	if (g_bRegistryManager)
	{
		ExDeletePagedLookasideList(&(g_registery_mem_manager.lookaside_obj_name.Lookaside));
		ExDeletePagedLookasideList(&(g_registery_mem_manager.lookaside_req_reg.Lookaside));
		ExDeletePagedLookasideList(&(g_registery_mem_manager.lookaside_unicode.Lookaside));
		g_bRegistryManager = FALSE;
	}
	
	if (g_RegisterCallback)
	{
		CmUnRegisterCallback(g_registery_mem_manager.registry_callback_cookie);
		g_RegisterCallback = FALSE;
	}
	return STATUS_SUCCESS;
}


BOOLEAN IsRegKeyExist(const WCHAR *szKey)
{
	UNICODE_STRING 		RegUnicodeString = {0};
	HANDLE 				hRegister = NULL;
	OBJECT_ATTRIBUTES 	objectAttributes = {0};
	NTSTATUS			ntStatus = STATUS_SUCCESS;

	RtlInitUnicodeString( &RegUnicodeString, szKey);
	
	InitializeObjectAttributes(&objectAttributes,
							&RegUnicodeString,
							OBJ_CASE_INSENSITIVE,
							NULL, 
							NULL );
	ntStatus = ZwOpenKey( &hRegister,
							KEY_READ,
							&objectAttributes);

	if (NT_SUCCESS(ntStatus))
	{
		ZwClose(hRegister);
		return TRUE;
	}
	ZwClose(hRegister);
	return FALSE;
}


NTSTATUS reg_create_key(const WCHAR* szRegPath,const WCHAR* szSubPath)
{
	UNICODE_STRING 		uRegKey = {0};
	HANDLE 				hRegister = NULL;
	ULONG 				ulResult = 0;
	OBJECT_ATTRIBUTES 	objectAttributes = {0};
	UNICODE_STRING 		subRegKey = {0};
	HANDLE 				hSubRegister = NULL;
	OBJECT_ATTRIBUTES 	subObjectAttributes = {0};
	NTSTATUS			ntStatus = STATUS_SUCCESS;
	WCHAR*				szLongPath = NULL;
	UNICODE_STRING		usString = {0};
	ULONG				ulLen = 0;
	
	if (!szRegPath || !szSubPath || !IsRegKeyExist(szRegPath))
	{
		return STATUS_UNSUCCESSFUL;
	}

	ulLen = (wcslen(szRegPath) + wcslen(szRegPath)+2)*sizeof(WCHAR);

	szLongPath = (WCHAR*)ExAllocatePoolWithTag(PagedPool,ulLen,'rego');
	if (szLongPath == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	StringCbCopyW(szLongPath,ulLen,szRegPath);
	if (szRegPath[wcslen(szRegPath)-1] != L'\\')
	{
		StringCbCatW(szLongPath,ulLen,L"\\");
	}

	StringCbCatW(szLongPath,ulLen,szSubPath);
	if (IsRegKeyExist(szLongPath))
	{
		ExFreePool(szLongPath);
		return STATUS_SUCCESS;
	}
	ExFreePool(szLongPath);
	RtlInitUnicodeString( &uRegKey, szRegPath);
	InitializeObjectAttributes(&objectAttributes,
							&uRegKey,
							OBJ_CASE_INSENSITIVE,
							NULL, 
							NULL );

	ntStatus = ZwCreateKey( &hRegister,
							KEY_CREATE_SUB_KEY,
							&objectAttributes,
							0,
							NULL,
							REG_OPTION_NON_VOLATILE,
							&ulResult);

	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;	
	}

	RtlInitUnicodeString( &subRegKey, szSubPath);

	InitializeObjectAttributes(&subObjectAttributes,
							&subRegKey,
							OBJ_CASE_INSENSITIVE, 
							hRegister, 
							NULL );
	ntStatus = ZwCreateKey( &hSubRegister,
							KEY_ALL_ACCESS,
							&subObjectAttributes,
							0,
							NULL,
							REG_OPTION_NON_VOLATILE,
							&ulResult);

	if (!NT_SUCCESS(ntStatus))
	{
		ZwClose(hRegister);
		return ntStatus;
	}

	ZwClose(hRegister);
	ZwClose(hSubRegister);

	return ntStatus;
}

NTSTATUS reg_set_value_key(const WCHAR *szKey, const WCHAR *szValueName, ULONG type,PVOID data,ULONG dataSize)
{

	UNICODE_STRING 		RegUnicodeString = {0};
	HANDLE 				hRegister = NULL;
	OBJECT_ATTRIBUTES 	objectAttributes = {0};
	UNICODE_STRING 		ValueName = {0};
	NTSTATUS			ntStatus = STATUS_SUCCESS;
	ULONG				ulValue = 0;

	if (!szKey || !szValueName || !data || !dataSize || !IsRegKeyExist(szKey))
	{
		return STATUS_UNSUCCESSFUL;
	}

	RtlInitUnicodeString( &RegUnicodeString,szKey);

	InitializeObjectAttributes(
		&objectAttributes,
		&RegUnicodeString,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, 
		NULL 
		);

	ntStatus = ZwOpenKey( &hRegister,KEY_ALL_ACCESS,&objectAttributes);

	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	RtlInitUnicodeString( &ValueName, szValueName);
	ntStatus = ZwSetValueKey(hRegister,
				&ValueName,
				0,
				type,
				data,
				dataSize);
	ZwClose(hRegister);
	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}
	return STATUS_SUCCESS;
}


NTSTATUS reg_delete_value_key(const WCHAR *szKey,const WCHAR* szSubKey)
{
	UNICODE_STRING 		RegUnicodeString = {0};
	HANDLE 				hRegister = NULL;
	OBJECT_ATTRIBUTES 	objectAttributes = {0};
	UNICODE_STRING 		ValueName ={0};
	ULONG 				ulSize = 0;
	NTSTATUS			ntStatus = STATUS_SUCCESS;

	RtlInitUnicodeString( &RegUnicodeString,szKey);
	
	InitializeObjectAttributes(&objectAttributes,
							&RegUnicodeString,
							OBJ_CASE_INSENSITIVE,
							NULL, 
							NULL );
	ntStatus = ZwOpenKey( &hRegister,
							KEY_ALL_ACCESS,
							&objectAttributes);
	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	RtlInitUnicodeString( &ValueName, szSubKey);
	ntStatus = ZwDeleteValueKey(hRegister, &ValueName);

	ZwClose(hRegister);
	return ntStatus;
}

PKEY_VALUE_PARTIAL_INFORMATION reg_query_value_key(const WCHAR *szKey, const WCHAR *szValueName)
{
	UNICODE_STRING 					RegUnicodeString = {0};
	HANDLE 							hRegister = 0;
	OBJECT_ATTRIBUTES 				objectAttributes = {0};
	UNICODE_STRING 					ValueName = {0};
	ULONG 							ulSize = 0;
	NTSTATUS						ntStatus = STATUS_SUCCESS;
	PKEY_VALUE_PARTIAL_INFORMATION	pvpi = NULL;
	WCHAR*							szRet = NULL;

	RtlInitUnicodeString( &RegUnicodeString,szKey);
	
	InitializeObjectAttributes(&objectAttributes,
							&RegUnicodeString,
							OBJ_CASE_INSENSITIVE,
							NULL, 
							NULL );

	ntStatus = ZwOpenKey( &hRegister,KEY_ALL_ACCESS,&objectAttributes);
	if (!NT_SUCCESS(ntStatus))
	{
		return NULL;
	}

	RtlInitUnicodeString( &ValueName,szValueName);

	ntStatus = ZwQueryValueKey(hRegister,
				&ValueName,
				KeyValuePartialInformation ,
				NULL,
				0,
				&ulSize);

	if (ntStatus==STATUS_OBJECT_NAME_NOT_FOUND || ulSize==0)
	{
		ZwClose(hRegister);
		return NULL;
	}
	pvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool,ulSize, 'SGER');
	if (pvpi == NULL)
	{
		ZwClose(hRegister);
		return NULL;
	}

	ntStatus = ZwQueryValueKey(hRegister,
				&ValueName,
				KeyValuePartialInformation ,
				pvpi,
				ulSize,
				&ulSize);
	if (!NT_SUCCESS(ntStatus))
	{
		ExFreePool(pvpi);
		ZwClose(hRegister);
		return NULL;
	}
	ZwClose(hRegister);
	return pvpi;
}

BOOLEAN DeleteSubString(WCHAR* szStr, WCHAR* szSubStr)
{
	WCHAR* szTmp = NULL;
	ULONG  offset = 0;

	if (!szStr || !szSubStr || wcslen(szStr) <= wcslen(szSubStr))
	{
		return FALSE;
	}

	szTmp = mywcsistr(szStr,szSubStr);
	if (!szTmp)
	{
		return FALSE;
	}

	if (szTmp[wcslen(szSubStr)] == L'\0')
	{
		szStr[wcslen(szStr)-wcslen(szSubStr)-1] = L'\0';
		return TRUE;
	}
	else if (szTmp[wcslen(szSubStr) == L','])
	{
		offset = (wcslen(szStr)-wcslen(szSubStr)-1)*sizeof(WCHAR) - ((ULONG_PTR)szTmp-(ULONG_PTR)szStr);
		RtlMoveMemory((PVOID)szTmp,(PVOID)(szTmp+wcslen(szSubStr)+1),offset);
		szStr[wcslen(szStr)-wcslen(szSubStr)-1] = 0;
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

#define DLL_INJECT_KEY			L"\\Registry\\Machine\\SoftWare\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
#define DLL_INJECT_VALUVE_PATH	L"AppInit_DLLs"
#define DLL_INJECT_VALUVE_INIT	L"LoadAppInit_DLLs"

BOOLEAN DelInjectPathToReg( WCHAR* szDllPath)
{
	DWORD value = 1;
	NTSTATUS status;
	PKEY_VALUE_PARTIAL_INFORMATION pvpi = NULL;
	WCHAR*	szOrigin = NULL;
	ULONG	szOriginLen = 0;
	WCHAR*  szNew = NULL;
	ULONG	szNewLen = 0;

	if (!IsRegKeyExist(DLL_INJECT_KEY))
	{
		return FALSE;
	}

	pvpi = reg_query_value_key(DLL_INJECT_KEY,DLL_INJECT_VALUVE_PATH);
	if (!pvpi)
	{
		return TRUE;
	}
	else
	{
		if (pvpi->Type != REG_SZ)
		{
			ExFreePool(pvpi);
			return FALSE;
		}
		else
		{
			WCHAR* szTmp = NULL;
			szOrigin = (WCHAR*)pvpi->Data;
			szOriginLen = pvpi->DataLength;
			szTmp = (WCHAR*)ExAllocatePoolWithTag(PagedPool,szOriginLen+2,'rego');
			if (!szTmp)
			{
				ExFreePool(pvpi);
				return FALSE;
			}
			StringCbCopyNW(szTmp,szOriginLen+2,szOrigin,szOriginLen);
			if (mywcsistr(szTmp,szDllPath))
			{
				if (wcslen(szTmp) == wcslen(szDllPath))
				{
					status = reg_delete_value_key(DLL_INJECT_KEY,DLL_INJECT_VALUVE_PATH);
					ExFreePool(pvpi);
					ExFreePool(szTmp);
					if (NT_SUCCESS(status))
					{
						return TRUE;
					}
					else
					{
						return FALSE;
					}
				}
				else
				{
					if (DeleteSubString(szTmp,szDllPath))
					{
						status = reg_set_value_key(DLL_INJECT_KEY,DLL_INJECT_VALUVE_PATH,REG_SZ,szTmp,wcslen(szTmp)*sizeof(WCHAR));
						ExFreePool(pvpi);
						ExFreePool(szTmp);
						if (NT_SUCCESS(status))
						{
							return TRUE;
						}
						else
						{
							return FALSE;
						}
					}
					else
					{
						ExFreePool(szTmp);
						ExFreePool(pvpi);
						return FALSE;
					}
				}
			}
			else
			{
				ExFreePool(pvpi);
				return TRUE;
			}
		}
	}
}

//VOID ActivityWatchDog(PVOID Context)
//{
//	WCHAR* path = (WCHAR*)Context;
//
//	while(g_is_watch_dll_inject)
//	{
//		AddInjectPathToReg(path);
//			
//		SleepImp( 1 );
//	}
//	DelInjectPathToReg(path);
//	PsTerminateSystemThread(STATUS_SUCCESS);
//}


BOOLEAN AddInjectPathToReg( WCHAR* szDllPath)
{
	DWORD value = 1;
	NTSTATUS status;
	PKEY_VALUE_PARTIAL_INFORMATION pvpi = NULL;
	WCHAR*	szOrigin = NULL;
	ULONG	szOriginLen = 0;
	WCHAR*  szNew = NULL;
	WCHAR*  szTmp = NULL;
	ULONG	szNewLen = 0;

	if (!IsRegKeyExist(DLL_INJECT_KEY))
	{
		return FALSE;
	}
	status = reg_set_value_key(DLL_INJECT_KEY,DLL_INJECT_VALUVE_INIT,REG_DWORD,&value,sizeof(DWORD));
	if (!NT_SUCCESS(status))
	{
		return FALSE;
	}
	pvpi = reg_query_value_key(DLL_INJECT_KEY,DLL_INJECT_VALUVE_PATH);
	if (!pvpi)
	{
		status = reg_set_value_key(DLL_INJECT_KEY,DLL_INJECT_VALUVE_PATH,REG_SZ,(PVOID)szDllPath,wcslen(szDllPath)*sizeof(WCHAR));
		if (!NT_SUCCESS(status))
		{
			return FALSE;
		}
		else
		{
			return TRUE;
		}
	}
	else if (pvpi->DataLength <=2)
	{
		ExFreePool(pvpi);
		status = reg_set_value_key(DLL_INJECT_KEY,DLL_INJECT_VALUVE_PATH,REG_SZ,(PVOID)szDllPath,wcslen(szDllPath)*sizeof(WCHAR));
		if (!NT_SUCCESS(status))
		{
			return FALSE;
		}
		else
		{
			return TRUE;
		}
	}
	else
	{
		if (pvpi->Type != REG_SZ)
		{
			ExFreePool(pvpi);
			status = reg_set_value_key(DLL_INJECT_KEY,DLL_INJECT_VALUVE_PATH,REG_SZ,(PVOID)szDllPath,wcslen(szDllPath)*sizeof(WCHAR));
			if (!NT_SUCCESS(status))
			{
				return FALSE;
			}
			else
			{
				return TRUE;
			}
		}
		else
		{
			szOrigin = (WCHAR*)pvpi->Data;
			szOriginLen = pvpi->DataLength;

			szTmp = (WCHAR*)ExAllocatePoolWithTag(PagedPool,szOriginLen+2,'rego');
			if (!szTmp)
			{
				ExFreePool(pvpi);
				return FALSE;
			}
			StringCbCopyNW(szTmp,szOriginLen+2,szOrigin,szOriginLen);//StringCbCopyW
			if (mywcsistr(szTmp,szDllPath))
			{
				ExFreePool(szTmp);
				ExFreePool(pvpi);
				return TRUE;
			}
			else
			{
				szNewLen = szOriginLen + (wcslen(szDllPath)+2)*sizeof(WCHAR);
				szNew = (WCHAR*)ExAllocatePoolWithTag(PagedPool,szNewLen,'rego');
				if (szNew)
				{
					StringCbCopyNW(szNew,szNewLen,szOrigin,szOriginLen);
					StringCbCatW(szNew,szNewLen,L",");
					StringCbCatW(szNew,szNewLen,szDllPath);
					status = reg_set_value_key(DLL_INJECT_KEY,DLL_INJECT_VALUVE_PATH,REG_SZ,(PVOID)szNew,szNewLen);
					ExFreePool(szTmp);
					ExFreePool(pvpi);
					ExFreePool(szNew);
					if (NT_SUCCESS(status))
					{
						return TRUE;
					}
					else
					{
						return FALSE;
					}
				}
				else
				{
					ExFreePool(szTmp);
					ExFreePool(pvpi);
					return FALSE;
				}
			}

		}
	}
}