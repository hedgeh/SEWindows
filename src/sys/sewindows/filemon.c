#include "main.h"
#include "filemon.h"
#include <strsafe.h>
#include <Ntdddisk.h>
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
	(PFLT_PRE_OPERATION_CALLBACK)sw_pre_create_callback,
	(PFLT_POST_OPERATION_CALLBACK)sw_post_create_callback},

	{ IRP_MJ_SET_INFORMATION,
	FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO | FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO,
	(PFLT_PRE_OPERATION_CALLBACK)sw_pre_setinfo_callback,
	NULL},

	{ IRP_MJ_DEVICE_CONTROL,
	FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO | FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO,
	(PFLT_PRE_OPERATION_CALLBACK)sw_pre_diskctl_callback,
	NULL},

	{ IRP_MJ_OPERATION_END }
};



FLT_PREOP_CALLBACK_STATUS
sw_pre_diskctl_callback (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    NTSTATUS	status;
	ULONG		io_ctl_code = 0;

	UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
	
	if (ExGetPreviousMode() == KernelMode)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if ((PsGetCurrentProcessId() == (HANDLE)4) || (PsGetCurrentProcessId() == (HANDLE)0) || g_is_file_run == FALSE)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	io_ctl_code = Data->Iopb->Parameters.DeviceIoControl.Common.IoControlCode;

	switch (io_ctl_code)
	{
	case IOCTL_DISK_GET_DRIVE_GEOMETRY:
		KdPrint(("IOCTL_DISK_GET_DRIVE_GEOMETRY"));
		break;
	case IOCTL_DISK_GET_PARTITION_INFO:
		KdPrint(("IOCTL_DISK_GET_PARTITION_INFO"));
		break;
	case IOCTL_DISK_SET_PARTITION_INFO:
		KdPrint(("IOCTL_DISK_SET_PARTITION_INFO"));
		break;
	case IOCTL_DISK_GET_DRIVE_LAYOUT:

		KdPrint(("IOCTL_DISK_GET_DRIVE_LAYOUT"));
		break;
	case IOCTL_DISK_SET_DRIVE_LAYOUT:
		KdPrint(("IOCTL_DISK_SET_DRIVE_LAYOUT"));
		break;
	case IOCTL_DISK_VERIFY:
		KdPrint(("IOCTL_DISK_VERIFY"));
		break;
	case IOCTL_DISK_FORMAT_TRACKS:
		KdPrint(("IOCTL_DISK_FORMAT_TRACKS"));
		break;
	case IOCTL_DISK_REASSIGN_BLOCKS:
		KdPrint(("IOCTL_DISK_REASSIGN_BLOCKS"));
		break;
	case IOCTL_DISK_PERFORMANCE:
		KdPrint(("IOCTL_DISK_PERFORMANCE"));
		break;
	case IOCTL_DISK_IS_WRITABLE:
		KdPrint(("IOCTL_DISK_IS_WRITABLE"));
		break;
	case IOCTL_DISK_LOGGING:
		KdPrint(("IOCTL_DISK_LOGGING"));
		break;

	case IOCTL_DISK_FORMAT_TRACKS_EX:
		KdPrint(("IOCTL_DISK_FORMAT_TRACKS_EX"));
		break;

	case IOCTL_DISK_HISTOGRAM_STRUCTURE:
		KdPrint(("IOCTL_DISK_HISTOGRAM_STRUCTURE"));
		break;

	case IOCTL_DISK_HISTOGRAM_DATA:
		KdPrint(("IOCTL_DISK_HISTOGRAM_DATA"));
		break;

	case IOCTL_DISK_HISTOGRAM_RESET:
		KdPrint(("IOCTL_DISK_HISTOGRAM_RESET"));
		break;

	case IOCTL_DISK_REQUEST_STRUCTURE:
		KdPrint(("IOCTL_DISK_REQUEST_STRUCTURE"));
		break;

	case IOCTL_DISK_REQUEST_DATA:
		KdPrint(("IOCTL_DISK_REQUEST_DATA"));
		break;
	case IOCTL_DISK_PERFORMANCE_OFF:
		KdPrint(("IOCTL_DISK_PERFORMANCE_OFF"));
		break;
	default:
		break;
	}

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

CONST FLT_REGISTRATION g_FilterRegistration = {

	sizeof(FLT_REGISTRATION),			//  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags
	NULL,                               //  Context
	g_callbacks,                        //  Operation g_callbacks
	(PFLT_FILTER_UNLOAD_CALLBACK)sw_unload,                          //  MiniFilterUnload
	(PFLT_INSTANCE_SETUP_CALLBACK)sw_InstanceSetup,					//  InstanceSetup
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

NTSTATUS
sw_InstanceSetup (
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_SETUP_FLAGS Flags,
	__in DEVICE_TYPE VolumeDeviceType,
	__in FLT_FILESYSTEM_TYPE VolumeFilesystemType
	)
{
	PAGED_CODE();

	if (FLT_FSTYPE_RAW == VolumeFilesystemType)
	{
		return STATUS_FLT_DO_NOT_ATTACH;
	}
	return STATUS_SUCCESS;
}



NTSTATUS sw_unload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNICODE_STRING deviceDosName;
	UNREFERENCED_PARAMETER(Flags);
	PAGED_CODE();
	if (!g_is_unload_allowed)
	{
		return STATUS_FLT_DO_NOT_DETACH;
	}
	g_is_file_run = FALSE;
	g_is_proc_run = FALSE;
	g_is_reg_run = FALSE;
	g_is_svc_run = FALSE;
	sw_uninit_minifliter(g_driver_obj);
//	SleepImp(3);
//	sw_uninit_procss(g_driver_obj);
//	SleepImp(1);
	sw_register_uninit(g_driver_obj);
	

	if (g_device_obj)
	{
		IoUnregisterShutdownNotification(g_device_obj);
		IoDeleteDevice(g_device_obj);
		g_device_obj = NULL;
	}
	RtlInitUnicodeString(&deviceDosName, g_symbol_name);
	IoDeleteSymbolicLink(&deviceDosName);

	return STATUS_SUCCESS;
}


FORCEINLINE BOOLEAN  is_file_exist(PUNICODE_STRING pPath)
{
	BOOLEAN					bret = FALSE;
	NTSTATUS				status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES		attributes;
	FILE_NETWORK_OPEN_INFORMATION  FileInformation;

	InitializeObjectAttributes(&attributes, pPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwQueryFullAttributesFile(&attributes, &FileInformation);
	if (NT_SUCCESS(status))
	{
		bret = TRUE;
	}
	return bret;
}

FLT_PREOP_CALLBACK_STATUS sw_pre_create_callback( PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
	NTSTATUS		status = STATUS_SUCCESS;
	PHIPS_RULE_NODE cinf = NULL;
	BOOLEAN			IsDirectory = FALSE;
	PFLT_FILE_NAME_INFORMATION	nameInfo = NULL;
	
	ACCESS_MASK		OriginalDesiredAccess;
	ULONG           create_options = Data->Iopb->Parameters.Create.Options & 0x00ffffff;
	UCHAR			create_disposition = (UCHAR)(((Data->Iopb->Parameters.Create.Options) >> 24) & 0xFF);
	
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();

	if (Data->RequestorMode == KernelMode)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if ((PsGetCurrentProcessId() == (HANDLE)4) || (PsGetCurrentProcessId() == (HANDLE)0) ||g_is_file_run == FALSE)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (!FltObjects || !FltObjects->Instance || !FltObjects->FileObject)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}


	if (FlagOn(Data->Iopb->TargetFileObject->Flags, FO_VOLUME_OPEN) || FlagOn(Data->Iopb->TargetFileObject->Flags, FO_NAMED_PIPE) || FlagOn(Data->Iopb->TargetFileObject->Flags, FO_MAILSLOT))
	{
		{
			NTSTATUS s;
			PFLT_FILE_NAME_INFORMATION	n = NULL;

			s = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED |FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &n);

			if (NT_SUCCESS(s))
			{
				KdPrint(("%wZ\n",&n->Name));
				FltReleaseFileNameInformation(n);
			}
		}
		
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

	if (FlagOn( FltObjects->FileObject->Flags, FO_NAMED_PIPE ) || FlagOn( FltObjects->FileObject->Flags, FO_MAILSLOT ))
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

	if (is_dir(cinf->des_path))
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
	
	cinf->is_dir = IsDirectory;

	if (wcslen(cinf->des_path) <= wcslen(L"\\Device\\HarddiskVolume1\\"))
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
		}
	}

	if ((OriginalDesiredAccess & FILE_READ_DATA) && cinf->is_dir == FALSE)
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
	
	if ((create_disposition == FILE_OVERWRITE || create_disposition == FILE_OVERWRITE_IF) && 
		FALSE == IsDirectory && 
		is_file_exist(&nameInfo->Name))
	{
		cinf->minor_type = FILE_WRITE_DATA_XX;
		if (rule_match(cinf) != TRUE)
		{
			FltReleaseFileNameInformation(nameInfo);
			ExFreeToPagedLookasideList(&g_file_lookaside_list, cinf);
			Data->IoStatus.Status = STATUS_ACCESS_DENIED;
			Data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;
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
	PIRP							pTopLevelIrp = NULL;

	PAGED_CODE();

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	
	if (FLTFL_POST_OPERATION_DRAINING & Flags)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (!FltObjects->Instance)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (!FltObjects->FileObject)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (FlagOn( FltObjects->FileObject->Flags, FO_NAMED_PIPE ))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
		
	pTopLevelIrp = IoGetTopLevelIrp();
	if (pTopLevelIrp)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	
	if (!NT_SUCCESS(Data->IoStatus.Status) || (STATUS_REPARSE == Data->IoStatus.Status))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	if (FILE_CREATED == Data->IoStatus.Information /*|| FILE_OVERWRITTEN == Data->IoStatus.Information*/)
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
			cinf->is_dir = TRUE;
		}
	}
	cinf->is_dir = IsDirectory;
	
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

	PAGED_CODE();

	if (ExGetPreviousMode() == KernelMode)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

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
			cinf->is_dir = TRUE;
		}
	}
	cinf->is_dir = IsDirectory;
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
		if (g_current_pid == ProcessId)
		{
			g_is_file_run = FALSE;
			g_is_proc_run = FALSE;
			g_is_reg_run = FALSE;
			g_is_svc_run = FALSE;
			g_is_unload_allowed = TRUE;

#ifndef _WIN64
#if (NTDDI_VERSION < NTDDI_VISTA)
			sw_uninit_procss(g_driver_obj);
#endif 
#endif 
		}
		else
		{
#ifndef _WIN64
#if (NTDDI_VERSION < NTDDI_VISTA)
			del_pid_from_list(ProcessId);
#endif 
#endif
			notify_process_exit(ProcessId);
		}
	}
}

NTSTATUS sw_init_minifliter(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	PAGED_CODE();
	
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
	PAGED_CODE();
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