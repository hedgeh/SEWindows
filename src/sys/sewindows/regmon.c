#include "main.h"
#include "regmon.h"
#include <strsafe.h>
#include <ntstrsafe.h>
#include "lpc.h"

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


BOOLEAN is_process_in_white_list(HANDLE pid)
{
	WCHAR	temp_path[MAXPATHLEN];
	int i = 0;
	if (!get_proc_name_by_pid(pid, temp_path))
	{
		return FALSE;
	}
	for (; i < 6; i++)
	{
		if (_wcsicmp(temp_path, g_white_process[i]) == 0)
		{
			return TRUE;
		}
	}
	return FALSE;
}

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

PWCHAR mywcsistr(PWCHAR s1, PWCHAR s2)
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
			StringCbCopyW(preq_reg->des_path, MAXPATHLEN*sizeof(WCHAR), registryPath.Buffer);
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