#include "main.h"
#include "regmon.h"
#include "common.h"
#include <strsafe.h>
#include <ntstrsafe.h>
#include "lpc.h"

struct
{
	WCHAR	destPath[260];
	ULONG	dstlen;
	WCHAR	srcPath[260];
	ULONG	srclen;
} g_RegisterPath[2];

typedef struct _LOOK_ASIDE_BUFFER_MNG
{
	PAGED_LOOKASIDE_LIST Lookaside;
	USHORT buflen;
}LOOK_ASIDE_BUFFER_MNG;

typedef struct _CAPTURE_REGISTRY_MANAGER
{
	LARGE_INTEGER  registryCallbackCookie;
	LOOK_ASIDE_BUFFER_MNG  Lookaside_req_reg;	
	LOOK_ASIDE_BUFFER_MNG  Lookaside_obj_name;	
	LOOK_ASIDE_BUFFER_MNG  Lookaside_unicode;	
} CAPTURE_REGISTRY_MANAGER, *PCAPTURE_REGISTRY_MANAGER;

static CAPTURE_REGISTRY_MANAGER g_RegistryManager;
static BOOLEAN g_bRegistryManager = FALSE;
static BOOLEAN g_RegisterCallback = FALSE;
static BOOLEAN GetRegistryObjectCompleteName(PUNICODE_STRING pRegistryPath, PVOID pRegistryObject)
{
	BOOLEAN foundCompleteName = FALSE;
	int		try_count = 0;
	NTSTATUS status;
	ULONG returnedLength;
	PUNICODE_STRING pObjectName = NULL;

	if ((!MmIsAddressValid(pRegistryObject)) || (pRegistryObject == NULL))
	{
		return FALSE;
	}

	status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, 0, &returnedLength);
	if (status == STATUS_INFO_LENGTH_MISMATCH && returnedLength < g_RegistryManager.Lookaside_obj_name.buflen)
	{
try_again:
		pObjectName = ExAllocateFromPagedLookasideList(&(g_RegistryManager.Lookaside_obj_name.Lookaside));
		if (pObjectName)
		{
			RtlZeroMemory(pObjectName, g_RegistryManager.Lookaside_obj_name.buflen);
			status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, returnedLength, &returnedLength);
			if (NT_SUCCESS(status))
			{
				RtlUnicodeStringCopy(pRegistryPath, pObjectName);
				foundCompleteName = TRUE;
			}
			ExFreeToPagedLookasideList(&(g_RegistryManager.Lookaside_obj_name.Lookaside), pObjectName);
		}
		else
		{
			if (try_count < 10)
			{
				try_count++;
				goto try_again;
			}
		}
	}
	return foundCompleteName;
}

static NTSTATUS RegistryCallback(IN PVOID CallbackContext,
	IN PVOID  Argument1,
	IN PVOID  Argument2)
{
	ULONG registryDataLength = 0;
	ULONG registryDataType = 0;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	BOOLEAN registryEventIsValid = FALSE;
	int type;
	UNICODE_STRING registryPath;
	PWCHAR pPath = NULL;
	PHIPS_RULE_NODE preq_reg = NULL;
	int				try_count = 0;
	int				try_count1 = 0;

	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return STATUS_SUCCESS;
	}

	if ((PsGetCurrentProcessId() == (HANDLE)0) || g_currentPid == PsGetCurrentProcessId())
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
try_again:
	preq_reg = ExAllocateFromPagedLookasideList(&(g_RegistryManager.Lookaside_req_reg.Lookaside));
	if (preq_reg == NULL)
	{
		if (try_count < 10)
		{
			try_count++;
			goto try_again;
		}
		return STATUS_SUCCESS;
	}
	RtlZeroMemory(preq_reg, g_RegistryManager.Lookaside_req_reg.buflen);
	preq_reg->major_type = REG_OP;
	registryPath.Length = 0;
	registryPath.MaximumLength = g_RegistryManager.Lookaside_unicode.buflen;
try_again1:
	registryPath.Buffer = ExAllocateFromPagedLookasideList(&(g_RegistryManager.Lookaside_unicode.Lookaside));
	if (registryPath.Buffer == NULL)
	{
		if (try_count1 < 10)
		{
			try_count1++;
			goto try_again1;
		}
		ExFreeToPagedLookasideList(&(g_RegistryManager.Lookaside_req_reg.Lookaside), preq_reg);
		return STATUS_SUCCESS;
	}
	RtlZeroMemory(registryPath.Buffer, g_RegistryManager.Lookaside_unicode.buflen);
	preq_reg->minor_type = 0;
	__try
	{
		switch (type)
		{
		case RegNtPreDeleteKey:
		{	
			PREG_DELETE_KEY_INFORMATION deleteKey = (PREG_DELETE_KEY_INFORMATION)Argument2;
			registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, deleteKey->Object);
			
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
			registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, createKey->RootObject);
			RtlUnicodeStringCatString(&registryPath, L"\\");
			RtlAppendUnicodeStringToString(&registryPath, createKey->CompleteName);
			preq_reg->minor_type = OP_REG_CREATE_KEY;
			break;
		}
		case RegNtPreDeleteValueKey:	
		{	
			PREG_DELETE_VALUE_KEY_INFORMATION deleteValueKey = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
			registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, deleteValueKey->Object);
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
			registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, setValueKey->Object);
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
			registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, renameKey->Object);
			StringCbCopyNW(preq_reg->new_name, sizeof(preq_reg->new_name), renameKey->NewName->Buffer, renameKey->NewName->Length);
			preq_reg->minor_type = OP_REG_RENAME;
			break;
		}
		case RegNtPreEnumerateKey:
		{	
			PREG_ENUMERATE_KEY_INFORMATION enumerateKey = (PREG_ENUMERATE_KEY_INFORMATION)Argument2;
			registryDataType = enumerateKey->KeyInformationClass;
			registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, enumerateKey->Object);
			
			preq_reg->minor_type = OP_REG_READ;
			break;
		}
		case RegNtPreEnumerateValueKey:
		{
			PREG_ENUMERATE_VALUE_KEY_INFORMATION enumerateValueKey = (PREG_ENUMERATE_VALUE_KEY_INFORMATION)Argument2;
			registryDataType = enumerateValueKey->KeyValueInformationClass;
			registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, enumerateValueKey->Object);
			
			preq_reg->minor_type = OP_REG_READ;
			break;
		}
		case RegNtPreQueryKey:	
		{	
			PREG_QUERY_KEY_INFORMATION queryKey = (PREG_QUERY_KEY_INFORMATION)Argument2;
			registryDataType = queryKey->KeyInformationClass;
			registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, queryKey->Object);
			
			preq_reg->minor_type = OP_REG_READ;
			break;
		}
		case RegNtQueryValueKey:
		{	
			PREG_QUERY_VALUE_KEY_INFORMATION queryValueKey = (PREG_QUERY_VALUE_KEY_INFORMATION)Argument2;
			registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, queryValueKey->Object);
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
			registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, queryMultiple->Object);
			
			preq_reg->minor_type = OP_REG_READ;
			break;
		}
#if (NTDDI_VERSION >= NTDDI_VISTA)
		case RegNtPreLoadKey:
		{ 
			PREG_LOAD_KEY_INFORMATION queryMultiple = (PREG_LOAD_KEY_INFORMATION)Argument2;
			registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, queryMultiple->Object);

			preq_reg->minor_type = OP_REG_LOAD;
			break;
		}
		case RegNtPreUnLoadKey:
		{
			PREG_UNLOAD_KEY_INFORMATION queryMultiple = (PREG_UNLOAD_KEY_INFORMATION)Argument2;
			registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, queryMultiple->Object);

			preq_reg->minor_type = OP_REG_UNLOAD;
			break;
		}
		case RegNtPreSaveKey:
		{
			PREG_SAVE_KEY_INFORMATION queryMultiple = (PREG_SAVE_KEY_INFORMATION)Argument2;
			registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, queryMultiple->Object);

			preq_reg->minor_type = OP_REG_SAVE;
			break;
		}
		case RegNtPreRestoreKey:
		{
			PREG_RESTORE_KEY_INFORMATION queryMultiple = (PREG_RESTORE_KEY_INFORMATION)Argument2;
			registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, queryMultiple->Object);

			preq_reg->minor_type = OP_REG_RESTORE;
			break;
		}
		case RegNtPreReplaceKey:
		{
			PREG_REPLACE_KEY_INFORMATION pReplace = (PREG_REPLACE_KEY_INFORMATION)Argument2;
			
			registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, pReplace->Object);

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
		WCHAR		wszLongName[MAXPATHLEN] = { 0 };
		if (g_is_unload_allowed == FALSE)
		{
			StringCbCopyW(tmpPath, sizeof(WCHAR)*MAXPATHLEN, L"\\Services\\");
			StringCbCatW(tmpPath, sizeof(WCHAR)*MAXPATHLEN, g_service_name);
			
			if (wcsistr(registryPath.Buffer, tmpPath))
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
			if (sw_regisster_make_path(preq_reg->des_path, sizeof(preq_reg->des_path)) == -1)
			{
				goto err_ret;
			}
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

		pPath = get_proc_name_by_pid(preq_reg->sub_pid, tmpPath);

		if (pPath != NULL)
		{
			if (is_short_name_path(pPath))
			{
				convert_short_name_to_long(wszLongName, pPath, sizeof(WCHAR)*MAXPATHLEN);
				RtlCopyMemory(pPath, wszLongName, sizeof(WCHAR)*MAXPATHLEN);
			}

			if (!get_dos_name(pPath, preq_reg->src_path))
			{
				StringCbCopyW(preq_reg->src_path, sizeof(preq_reg->src_path), pPath);
			}
		}
		if (rule_match(preq_reg) == FALSE)
		{
			ntStatus = STATUS_UNSUCCESSFUL;
		}
	}
	else
	{
	}
err_ret:
	if (preq_reg != NULL)
	{
		ExFreeToPagedLookasideList(&(g_RegistryManager.Lookaside_req_reg.Lookaside), preq_reg);
	}
	if (registryPath.Buffer != NULL)
	{
		ExFreeToPagedLookasideList(&(g_RegistryManager.Lookaside_unicode.Lookaside), registryPath.Buffer);
	}

	return ntStatus;
}


int sw_regisster_make_path(WCHAR * path, ULONG lenstr)
{
	int i;
	WCHAR str[MAXPATHLEN];
	for (i = 0; i < 2; i++)
	{
		if (0 == _wcsnicmp(path, g_RegisterPath[i].srcPath, g_RegisterPath[i].srclen) && wcslen(path) != g_RegisterPath[i].srclen)
		{
			break;
		}
	}
	if (i >= 2)
	{
		return -1;
	}

	str[0] = L'\0';
	RtlStringCbCatW(str, sizeof(str), g_RegisterPath[i].destPath);
	RtlStringCbCatW(str, sizeof(str), path + g_RegisterPath[i].srclen);

	wcscpy(path, str);
	
	return 0;
}

NTSTATUS RegisterPathInit()
{
	wcscpy(g_RegisterPath[0].destPath, L"HKEY_LOCAL_MACHINE");
	wcscpy(g_RegisterPath[0].srcPath, L"\\Registry\\Machine");
	g_RegisterPath[0].dstlen = (ULONG)wcslen(g_RegisterPath[0].destPath);
	g_RegisterPath[0].srclen = (ULONG)wcslen(g_RegisterPath[0].srcPath);

	wcscpy(g_RegisterPath[1].destPath, L"HKEY_USERS");
	wcscpy(g_RegisterPath[1].srcPath, L"\\Registry\\User");
	g_RegisterPath[1].dstlen = (ULONG)wcslen(g_RegisterPath[1].destPath);
	g_RegisterPath[1].srclen = (ULONG)wcslen(g_RegisterPath[1].srcPath);

	return STATUS_SUCCESS;
}


NTSTATUS sw_register_init(PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	status = RegisterPathInit();
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	
	g_RegistryManager.Lookaside_obj_name.buflen = 1024;
	ExInitializePagedLookasideList(&(g_RegistryManager.Lookaside_obj_name.Lookaside), NULL, NULL, 0, g_RegistryManager.Lookaside_obj_name.buflen, 'objn', 0);
	g_RegistryManager.Lookaside_req_reg.buflen = sizeof(HIPS_RULE_NODE);
	ExInitializePagedLookasideList(&(g_RegistryManager.Lookaside_req_reg.Lookaside), NULL, NULL, 0, g_RegistryManager.Lookaside_req_reg.buflen, 'objn', 0);
	g_RegistryManager.Lookaside_unicode.buflen = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
	ExInitializePagedLookasideList(&(g_RegistryManager.Lookaside_unicode.Lookaside), NULL, NULL, 0, g_RegistryManager.Lookaside_unicode.buflen, 'objn', 0);

	g_bRegistryManager = TRUE;
		 
	status = CmRegisterCallback(RegistryCallback, &g_RegistryManager, &(g_RegistryManager.registryCallbackCookie));
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
		ExDeletePagedLookasideList(&(g_RegistryManager.Lookaside_obj_name.Lookaside));
		ExDeletePagedLookasideList(&(g_RegistryManager.Lookaside_req_reg.Lookaside));
		ExDeletePagedLookasideList(&(g_RegistryManager.Lookaside_unicode.Lookaside));
		g_bRegistryManager = FALSE;
	}
	
	if (g_RegisterCallback)
	{
		CmUnRegisterCallback(g_RegistryManager.registryCallbackCookie);
		g_RegisterCallback = FALSE;
	}
	return STATUS_SUCCESS;
}