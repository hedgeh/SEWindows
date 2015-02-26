#include "main.h"
#include "filemon.h"
#include <strsafe.h>
#include "lpc.h"
#include "processmon.h"
#include "regmon.h"

#define		INIT_FILE_TABLE_COUNT	200


static PFLT_FILTER g_FilterHandle = NULL;
PATH_TABLE	g_path_table[26];
static PAGED_LOOKASIDE_LIST g_file_lookaside_list;
static BOOLEAN g_is_file_lookaside_list_installed = FALSE;
static BOOLEAN g_bCreateProcessNotifyRoutine = FALSE;

CONST FLT_OPERATION_REGISTRATION g_callbacks[] = 
{
	{ IRP_MJ_CREATE,
	FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO | FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO,
	sw_pre_create_callback,
	sw_post_create_callback},

	{ IRP_MJ_SET_INFORMATION,
	FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO | FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO,
	sw_pre_setinfo_callback,
	NULL},
	{ IRP_MJ_OPERATION_END }
};


CONST FLT_REGISTRATION g_FilterRegistration = {

	sizeof(FLT_REGISTRATION),			//  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags
	NULL,                               //  Context
	g_callbacks,                        //  Operation g_callbacks
	sw_unload,                          //  MiniFilterUnload
	NULL,								//  InstanceSetup
	NULL,								//  InstanceQueryTeardown
	NULL,								//  InstanceTeardownStart
	NULL,								//  InstanceTeardownComplete
	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent

};


FORCEINLINE BOOLEAN  is_dir(PWCHAR pPath) 
{
	return pPath[wcslen(pPath) - 1] == L'\\';
}

NTSTATUS sw_unload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNICODE_STRING deviceDosName;
	UNREFERENCED_PARAMETER(Flags);

	if (!g_is_unload_allowed)
	{
		return STATUS_FLT_DO_NOT_DETACH;
	}
	g_is_file_run = FALSE;
	g_is_proc_run = FALSE;
	g_is_reg_run = FALSE;
	sw_register_uninit(g_DriverObject);
#if (NTDDI_VERSION >= NTDDI_VISTA)
	sw_uninit_procss(g_DriverObject);
#endif
	sw_uninit_minifliter(g_DriverObject);

	if (g_DevObj)
	{
		IoUnregisterShutdownNotification(g_DevObj);
		IoDeleteDevice(g_DevObj);
		g_DevObj = NULL;
	}
	RtlInitUnicodeString(&deviceDosName, g_symbol_name);
	IoDeleteSymbolicLink(&deviceDosName);

	return STATUS_SUCCESS;
}



FLT_PREOP_CALLBACK_STATUS sw_pre_create_callback( PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
	NTSTATUS		status = STATUS_SUCCESS;
	PHIPS_RULE_NODE cinf = NULL;
	BOOLEAN			IsDirectory = FALSE;
	PFLT_FILE_NAME_INFORMATION	nameInfo = NULL;
	WCHAR						tmpPath[MAXPATHLEN] = { 0 };
	ACCESS_MASK		OriginalDesiredAccess;
	ULONG           create_options = Data->Iopb->Parameters.Create.Options & 0x00ffffff;

	
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();

	if ((PsGetCurrentProcessId() == (HANDLE)4) || (PsGetCurrentProcessId() == (HANDLE)0) ||g_is_file_run == FALSE)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (FlagOn(Data->Iopb->TargetFileObject->Flags, FO_VOLUME_OPEN) || FlagOn(Data->Iopb->TargetFileObject->Flags, FO_NAMED_PIPE) || FlagOn(Data->Iopb->TargetFileObject->Flags, FO_MAILSLOT))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (FlagOn(Data->Iopb->IrpFlags, IRP_CLOSE_OPERATION) || FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	OriginalDesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->AccessState->OriginalDesiredAccess;
	if (!((OriginalDesiredAccess  & FILE_READ_DATA)
		|| (OriginalDesiredAccess & FILE_WRITE_DATA)
		|| (OriginalDesiredAccess & FILE_APPEND_DATA)
		|| (OriginalDesiredAccess & DELETE)
		|| (OriginalDesiredAccess & FILE_EXECUTE)))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	cinf = ExAllocateFromPagedLookasideList(&g_file_lookaside_list);
	if (cinf == NULL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	RtlZeroMemory(cinf, sizeof(HIPS_RULE_NODE));
	cinf->major_type = FILE_OP;

	cinf->sub_pid = PsGetCurrentProcessId();
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED |FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &nameInfo);

	if (!NT_SUCCESS(status))
	{
		goto err_ret;
	}
	FltParseFileNameInformation(nameInfo);
	if (nameInfo->Name.Length >= MAXPATHLEN*sizeof(WCHAR))
	{
		goto err_ret;
	}
	StringCbCopyNW(cinf->des_path,sizeof(WCHAR)*MAXPATHLEN,nameInfo->Name.Buffer, nameInfo->Name.Length);

	status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &IsDirectory);
	if (!NT_SUCCESS(status))
	{
		if (is_dir(tmpPath))
		{
			IsDirectory = TRUE;
		}
		else
		{
			if (create_options & FILE_DIRECTORY_FILE)
			{
				IsDirectory = TRUE;
			}
		}
	}
	cinf->isDir = IsDirectory;

	if (wcslen(cinf->des_path) <= 3)
	{
		goto err_ret;
	}

	if ((OriginalDesiredAccess & FILE_EXECUTE))
	{
		cinf->minor_type = FILE_EXECUTE_XX;
		if (rule_match(cinf) != TRUE)
		{
			Data->Iopb->Parameters.Create.SecurityContext->AccessState->OriginalDesiredAccess &= ~FILE_EXECUTE;
			Data->Iopb->Parameters.Create.SecurityContext->AccessState->RemainingDesiredAccess &= ~FILE_EXECUTE;
			Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &= ~FILE_EXECUTE;

			FltReleaseFileNameInformation(nameInfo);
			ExFreeToPagedLookasideList(&g_file_lookaside_list, cinf);
			Data->IoStatus.Status = STATUS_ACCESS_DENIED;
			Data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;
		}
	}

	if ((OriginalDesiredAccess & FILE_READ_DATA) && cinf->isDir == FALSE)
	{
		cinf->minor_type = FILE_READ_DATA_XX;
		if (rule_match(cinf) != TRUE)
		{
			Data->Iopb->Parameters.Create.SecurityContext->AccessState->OriginalDesiredAccess &= ~FILE_READ_DATA;
			Data->Iopb->Parameters.Create.SecurityContext->AccessState->RemainingDesiredAccess &= ~FILE_READ_DATA;
			Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &= ~FILE_READ_DATA;

		}
	}

	if ((OriginalDesiredAccess & FILE_WRITE_DATA) || (OriginalDesiredAccess & FILE_APPEND_DATA))
	{
		cinf->minor_type = FILE_WRITE_DATA_XX;
		if (rule_match(cinf) != TRUE)
		{
			Data->Iopb->Parameters.Create.SecurityContext->AccessState->OriginalDesiredAccess &= ~FILE_WRITE_DATA;
			Data->Iopb->Parameters.Create.SecurityContext->AccessState->RemainingDesiredAccess &= ~FILE_WRITE_DATA;
			Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &= ~FILE_WRITE_DATA;

			Data->Iopb->Parameters.Create.SecurityContext->AccessState->OriginalDesiredAccess &= ~FILE_APPEND_DATA;
			Data->Iopb->Parameters.Create.SecurityContext->AccessState->RemainingDesiredAccess &= ~FILE_APPEND_DATA;
			Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &= ~FILE_APPEND_DATA;
		}
	}

	if ((OriginalDesiredAccess & DELETE))
	{
		cinf->minor_type = FILE_DEL_XX;
		if (rule_match(cinf) != TRUE)
		{
			Data->Iopb->Parameters.Create.SecurityContext->AccessState->OriginalDesiredAccess &= ~DELETE;
			Data->Iopb->Parameters.Create.SecurityContext->AccessState->RemainingDesiredAccess &= ~DELETE;
			Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &= ~DELETE;
		}
	}
err_ret:
	if (nameInfo)
	{
		FltReleaseFileNameInformation(nameInfo);
		nameInfo = NULL;
	}
	if (cinf)
	{
		ExFreeToPagedLookasideList(&g_file_lookaside_list, cinf);
	}
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS sw_post_create_callback( PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
	NTSTATUS			status = STATUS_SUCCESS;
	PHIPS_RULE_NODE		cinf = NULL;
	BOOLEAN				IsDirectory = FALSE;
	PFLT_FILE_NAME_INFORMATION		nameInfo = NULL;
	WCHAR							tmpPath[MAXPATHLEN] = { 0 };
	FILE_DISPOSITION_INFORMATION	fdi;

	if ((PsGetCurrentProcessId() == (HANDLE)4) || (PsGetCurrentProcessId() == (HANDLE)0) || g_is_file_run == FALSE)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (!NT_SUCCESS(Data->IoStatus.Status) || (STATUS_REPARSE == Data->IoStatus.Status))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	
	if (!NT_SUCCESS(Data->IoStatus.Status) || (STATUS_REPARSE == Data->IoStatus.Status))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	if (FILE_CREATED == Data->IoStatus.Information || FILE_OVERWRITTEN == Data->IoStatus.Information)
	{
		if (FlagOn(FltObjects->FileObject->Flags, FO_HANDLE_CREATED))
		{
			return FLT_POSTOP_FINISHED_PROCESSING;
		}
	}
	else
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	

	cinf = ExAllocateFromPagedLookasideList(&g_file_lookaside_list);
	if (cinf == NULL)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	RtlZeroMemory(cinf, sizeof(HIPS_RULE_NODE));
	cinf->major_type = FILE_OP;

	cinf->sub_pid = PsGetCurrentProcessId();
	cinf->minor_type = FILE_CREATE_XX;


	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &nameInfo);

	if (!NT_SUCCESS(status))
	{
		goto err_ret;
	}
	FltParseFileNameInformation(nameInfo);
	if (nameInfo->Name.Length >= MAXPATHLEN*sizeof(WCHAR))
	{
		goto err_ret;
	}
	StringCbCopyNW(cinf->des_path,sizeof(WCHAR)*MAXPATHLEN,nameInfo->Name.Buffer, nameInfo->Name.Length);


	status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &IsDirectory);
	if (!NT_SUCCESS(status))
	{
		if (is_dir(tmpPath))
		{
			cinf->isDir = TRUE;
		}
	}
	cinf->isDir = IsDirectory;
	
	if (wcslen(cinf->des_path) <= 3)
	{
		goto err_ret;
	}
	if (rule_match(cinf) == TRUE)
	{
		ExFreeToPagedLookasideList(&g_file_lookaside_list, cinf);
		FltReleaseFileNameInformation(nameInfo);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	else
	{
		ExFreeToPagedLookasideList(&g_file_lookaside_list, cinf);
		FltReleaseFileNameInformation(nameInfo);
		fdi.DeleteFile = TRUE;
		FltSetInformationFile(FltObjects->Instance, FltObjects->FileObject, &fdi, sizeof(FILE_DISPOSITION_INFORMATION), FileDispositionInformation);
		FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	
err_ret:
	if (nameInfo)
	{
		FltReleaseFileNameInformation(nameInfo);
		nameInfo = NULL;
	}
	if (cinf)
	{
		ExFreeToPagedLookasideList(&g_file_lookaside_list, cinf);
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS sw_pre_setinfo_callback( PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,PVOID *CompletionContext)
{
	NTSTATUS		status = STATUS_SUCCESS;
	PHIPS_RULE_NODE	cinf = NULL;
	BOOLEAN			IsDirectory = FALSE;
	PFLT_FILE_NAME_INFORMATION	nameInfo = NULL;
	WCHAR						tmpPath[MAXPATHLEN] = { 0 };


	if ((PsGetCurrentProcessId() == (HANDLE)4) || (PsGetCurrentProcessId() == (HANDLE)0) || g_is_file_run == FALSE)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (FlagOn(Data->Iopb->TargetFileObject->Flags, FO_VOLUME_OPEN) || FlagOn(Data->Iopb->TargetFileObject->Flags, FO_NAMED_PIPE) || FlagOn(Data->Iopb->TargetFileObject->Flags, FO_MAILSLOT))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (FlagOn(Data->Iopb->IrpFlags, IRP_CLOSE_OPERATION) || FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if ((Data->Iopb->Parameters.SetFileInformation.FileInformationClass != FileDispositionInformation)
		&& (Data->Iopb->Parameters.SetFileInformation.FileInformationClass != FileBasicInformation)
		&& (Data->Iopb->Parameters.SetFileInformation.FileInformationClass != FileRenameInformation))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}


	cinf = ExAllocateFromPagedLookasideList(&g_file_lookaside_list);
	if (cinf == NULL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	RtlZeroMemory(cinf, sizeof(HIPS_RULE_NODE));

	cinf->major_type = FILE_OP;

	cinf->sub_pid = PsGetCurrentProcessId();
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &nameInfo);

	if (!NT_SUCCESS(status))
	{
		goto err_ret;
	}
	FltParseFileNameInformation(nameInfo);
	if (nameInfo->Name.Length >= MAXPATHLEN*sizeof(WCHAR))
	{
		goto err_ret;
	}
	StringCbCopyNW(cinf->des_path,sizeof(WCHAR)*MAXPATHLEN,nameInfo->Name.Buffer, nameInfo->Name.Length);
	status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &IsDirectory);
	if (!NT_SUCCESS(status))
	{
		if (is_dir(tmpPath))
		{
			cinf->isDir = TRUE;
		}
	}
	cinf->isDir = IsDirectory;
	if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation)
	{
		if (((PFILE_DISPOSITION_INFORMATION)(Data->Iopb->Parameters.SetFileInformation.InfoBuffer))->DeleteFile == TRUE)
		{
			cinf->minor_type = FILE_DEL_XX;
		}
	}

	if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileBasicInformation)
	{
		PFILE_BASIC_INFORMATION pfbi = (PFILE_BASIC_INFORMATION)(Data->Iopb->Parameters.SetFileInformation.InfoBuffer);
		if (pfbi)
		{
			RtlMoveMemory(&cinf->fbi, pfbi, sizeof(FILE_BASIC_INFORMATION));
			cinf->minor_type = FILE_SETINFO_XX;
		}
	}

	if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation)
	{
		PFILE_RENAME_INFORMATION pfn = (PFILE_RENAME_INFORMATION)(Data->Iopb->Parameters.SetFileInformation.InfoBuffer);
		if (pfn != NULL)
		{
			if (pfn->FileNameLength > MAXPATHLEN)
			{
				goto err_ret;
			}
			StringCbCopyNW(cinf->new_name, sizeof(cinf->new_name),  pfn->FileName, pfn->FileNameLength);
		}
		cinf->minor_type = FILE_RENAME_XX;
	}

	if (wcslen(cinf->des_path) <= 3)
	{
		goto err_ret;
	}

	if (rule_match(cinf) == TRUE)
	{
		ExFreeToPagedLookasideList(&g_file_lookaside_list, cinf);
		FltReleaseFileNameInformation(nameInfo);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	else
	{
		ExFreeToPagedLookasideList(&g_file_lookaside_list, cinf);
		FltReleaseFileNameInformation(nameInfo);
		Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}
	

err_ret:
	if (nameInfo)
	{
		FltReleaseFileNameInformation(nameInfo);
		nameInfo = NULL;
	}
	if (cinf)
	{
		ExFreeToPagedLookasideList(&g_file_lookaside_list, cinf);
		cinf = NULL;
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


VOID
CreateProcessNotifyRoutine(
IN HANDLE  ParentId,
IN HANDLE  ProcessId,
IN BOOLEAN  Create
)
{
	if (Create == FALSE)
	{
		if (g_currentPid == ProcessId)
		{
			g_is_file_run = FALSE;
			g_is_proc_run = FALSE;
			g_is_reg_run = FALSE;
			g_is_unload_allowed = TRUE;
		}
		else
		{
			notify_process_exit(ProcessId);
		}
	}
}

NTSTATUS sw_init_minifliter(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	
	status = PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, FALSE);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	g_bCreateProcessNotifyRoutine = TRUE;
    status = FltRegisterFilter( DriverObject,
                                &g_FilterRegistration,
                                &g_FilterHandle );
    if (NT_SUCCESS( status )) 
	{
		ExInitializePagedLookasideList(&g_file_lookaside_list, NULL, NULL, 0, sizeof(HIPS_RULE_NODE), 'file', 0);
		g_is_file_lookaside_list_installed = TRUE;
		status = init_lpc(g_port_name, g_FilterHandle);
		if (NT_SUCCESS(status))
		{
			status = FltStartFiltering(g_FilterHandle);
			return status;
		}
		uninit_lpc();
		ExDeletePagedLookasideList(&g_file_lookaside_list);
		g_is_file_lookaside_list_installed = FALSE;
        FltUnregisterFilter( g_FilterHandle );
		PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);
		g_bCreateProcessNotifyRoutine = FALSE;
		g_FilterHandle = NULL;
    }
	
	return status;
}

NTSTATUS  sw_uninit_minifliter(PDRIVER_OBJECT pDriverObj)
{
	uninit_lpc();
	if (g_bCreateProcessNotifyRoutine)
	{
		PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);
		g_bCreateProcessNotifyRoutine = FALSE;
	}
	if (g_FilterHandle)
	{
		FltUnregisterFilter(g_FilterHandle);
		g_FilterHandle = NULL;
	}
	if (g_is_file_lookaside_list_installed)
	{
		ExDeletePagedLookasideList(&g_file_lookaside_list);
		g_is_file_lookaside_list_installed = FALSE;
	}
	return STATUS_SUCCESS;
}