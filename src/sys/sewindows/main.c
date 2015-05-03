#include "main.h"
#include "filemon.h"
#include "processmon.h"
#include "regmon.h"
#include "lpc.h"
#include <Strsafe.h>

PDEVICE_OBJECT              g_device_obj = NULL;
BOOLEAN						g_is_driver_init = FALSE;
HANDLE						g_current_pid = NULL;
BOOLEAN						g_is_reg_run = FALSE;
BOOLEAN						g_is_proc_run = FALSE;
BOOLEAN						g_is_file_run = FALSE;
BOOLEAN						g_is_svc_run = FALSE;
PDRIVER_OBJECT				g_driver_obj = NULL;
WCHAR						g_device_name[MAXNAMELEN];
WCHAR						g_symbol_name[MAXNAMELEN];
WCHAR						g_port_name[MAXNAMELEN];
WCHAR						g_service_name[MAXNAMELEN];
BOOLEAN						g_is_unload_allowed = FALSE;
BOOLEAN						g_is_notify_mode = TRUE;
PBOOLEAN					p = &g_is_proc_run;
WCHAR						g_white_process[6][MAXPATHLEN];
WCHAR						g_windows_directory[MAXPATHLEN];
QUERY_INFO_PROCESS			g_ZwQueryInformationProcess = NULL;
fn_NtQueryInformationThread  g_zwQueryInformationThread = NULL;

DRIVER_INITIALIZE 	DriverEntry;
DRIVER_DISPATCH 	dispatch_pass;
DRIVER_UNLOAD 		driver_unload;
DRIVER_DISPATCH 	dispatch_create;
DRIVER_DISPATCH 	dispatch_close;
DRIVER_DISPATCH 	dispatch_ictl;
DRIVER_DISPATCH 	dispatch_shutdown;


NTSTATUS 	DriverEntry (PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath);
VOID 		driver_unload(PDRIVER_OBJECT DriverObject);
NTSTATUS 	dispatch_create(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
NTSTATUS 	dispatch_close(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
NTSTATUS 	dispatch_ictl(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, driver_unload)
#pragma alloc_text(PAGE, get_proc_name_by_pid)
#pragma alloc_text(PAGE, dispatch_create)
#pragma alloc_text(PAGE, dispatch_close)
#pragma alloc_text(PAGE, dispatch_ictl)
#endif


void build_white_process_list()
{
	StringCbCopyW(g_white_process[0], MAXPATHLEN*sizeof(WCHAR), g_windows_directory);
	StringCbCatW(g_white_process[0], MAXPATHLEN*sizeof(WCHAR), L"\\WINDOWS\\explorer.exe");

	StringCbCopyW(g_white_process[1], MAXPATHLEN*sizeof(WCHAR), g_windows_directory);
	StringCbCatW(g_white_process[1], MAXPATHLEN*sizeof(WCHAR), L"\\WINDOWS\\system32\\svchost.exe");

	StringCbCopyW(g_white_process[2], MAXPATHLEN*sizeof(WCHAR), g_windows_directory);
	StringCbCatW(g_white_process[2], MAXPATHLEN*sizeof(WCHAR), L"\\WINDOWS\\system32\\lsass.exe");

	StringCbCopyW(g_white_process[3], MAXPATHLEN*sizeof(WCHAR), g_windows_directory);
	StringCbCatW(g_white_process[3], MAXPATHLEN*sizeof(WCHAR), L"\\WINDOWS\\system32\\services.exe");

	StringCbCopyW(g_white_process[4], MAXPATHLEN*sizeof(WCHAR), g_windows_directory);
	StringCbCatW(g_white_process[4], MAXPATHLEN*sizeof(WCHAR), L"\\WINDOWS\\system32\\csrss.exe");

	StringCbCopyW(g_white_process[5], MAXPATHLEN*sizeof(WCHAR), g_windows_directory);
	StringCbCatW(g_white_process[5], MAXPATHLEN*sizeof(WCHAR), L"\\WINDOWS\\system32\\winlogon.exe");
}



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

PWCHAR get_proc_name_by_pid(IN  HANDLE   dwProcessId, PWCHAR pPath)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	HANDLE hProcess;
	PEPROCESS pEprocess;
	ULONG returnedLength;
	PUNICODE_STRING imageName;

	PAGED_CODE();

	Status = PsLookupProcessByProcessId(dwProcessId, &pEprocess);
	if (!NT_SUCCESS(Status))
	{
		return NULL;
	}
	Status = ObOpenObjectByPointer(pEprocess, OBJ_KERNEL_HANDLE, NULL, 0, *PsProcessType, KernelMode, &hProcess);
	if (!NT_SUCCESS(Status))
	{
		ObDereferenceObject(pEprocess);
		return NULL;
	}
	Status = g_ZwQueryInformationProcess(hProcess, ProcessImageFileName, pPath, MAXPATHLEN*sizeof(WCHAR), &returnedLength);
	if (!NT_SUCCESS(Status))
	{
		ZwClose(hProcess);
		ObDereferenceObject(pEprocess);
		return NULL;
	}
	else
	{
		ULONG len = 0;
		imageName = (PUNICODE_STRING)pPath;
		len = imageName->Length;
		RtlMoveMemory(pPath, imageName->Buffer, imageName->Length);
		pPath[len / sizeof(WCHAR)] = L'\0';
	}
	ZwClose(hProcess);
	ObDereferenceObject(pEprocess);
	return pPath;
}


NTSTATUS dispatch_create(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	static BOOLEAN bFirst = TRUE;
	PAGED_CODE();
	if (!g_is_driver_init)
	{
		status = STATUS_UNSUCCESSFUL;
	}

	if (bFirst)
	{
		g_current_pid = PsGetCurrentProcessId();
		bFirst = FALSE;
	}
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS dispatch_close(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PAGED_CODE();

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

BOOLEAN get_from_r3msg(PVOID buf,ULONG ilen,ULONG olen)
{
	PHIPS_RULE_NODE phrn = NULL;
	phrn = (PHIPS_RULE_NODE)buf;
	if (!phrn || sizeof(HIPS_RULE_NODE) != ilen ||  sizeof(HIPS_RULE_NODE) != olen)
	{
		return FALSE;
	}

	if (phrn->major_type == PROC_OP && g_is_proc_run == FALSE)
	{
		return FALSE;
	}

	if (phrn->major_type == SERVICE_OP && g_is_svc_run == FALSE)
	{
		return FALSE;
	}

	if (rule_match(phrn))
	{
		phrn->is_dir = 1;
	}
	else
	{
		phrn->is_dir = 0;
	}
	return TRUE;
}

NTSTATUS dispatch_ictl(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{

	NTSTATUS			status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	irpStack;
	PVOID				ioBuf;
	ULONG				inBufLength, outBufLength;
	ULONG				ioControlCode;

	PAGED_CODE();

	/*if (g_current_pid != PsGetCurrentProcessId())
	{
		goto retLable;
	}*/
	irpStack = IoGetCurrentIrpStackLocation(pIrp);
	pIrp->IoStatus.Information = 0;
	ioBuf = pIrp->AssociatedIrp.SystemBuffer;
	inBufLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
	
	switch (ioControlCode)
	{
	case IOCTL_START_PROCMONITOR:
		g_is_proc_run = TRUE;
		break;
	case IOCTL_PAUSE_PROCMONITOR:
		g_is_proc_run = FALSE;
		break;
	case IOCTL_START_FILEMONITOR:
		g_is_file_run = TRUE;
		break;
	case IOCTL_PAUSE_FILEMONITOR: 
		g_is_file_run = FALSE;
		break;
	case IOCTL_REMOVE_HOOK: 
		sw_uninit_procss(g_driver_obj);
		break;
	case IOCTL_STOP_ALL:
		g_is_reg_run = FALSE;
		g_is_proc_run = FALSE;
		g_is_file_run = FALSE;
		break;
	case IOCTL_START_ALL:
		g_is_reg_run = TRUE;
		g_is_proc_run = TRUE;
		g_is_file_run = TRUE;
		break;
	case IOCTL_PAUSE_REGMONITOR:
		g_is_reg_run = FALSE;
		break;
	case IOCTL_FROM_R3MSG:
		{
			
			if (get_from_r3msg(ioBuf,inBufLength,outBufLength))
			{
				status = STATUS_SUCCESS;
				pIrp->IoStatus.Information = inBufLength;
			}
			else
			{
				status = STATUS_UNSUCCESSFUL;
				pIrp->IoStatus.Information = 0;
			}
			
		}
		break;
	case IOCTL_START_SVCMONITOR:
		g_is_svc_run = TRUE;
		break;
	case IOCTL_STOP_SVCMONITOR:
		g_is_svc_run = FALSE;
		break;
	case IOCTL_START_REGMONITOR:
		g_is_reg_run = TRUE;
		break;
	case IOCTL_STOP_UNLOAD:
		g_is_unload_allowed = FALSE;
		break;
	case IOCTL_PERMIT_UNLOAD:
		g_is_unload_allowed = TRUE;
		break;
	case IOCTL_SET_INTERCEPT_MODE:
		g_is_notify_mode = FALSE;
		break;
	case IOCTL_SET_NOTIFY_MODE:
		g_is_notify_mode = TRUE;
		break;
	case IOCTL_TRANSFER_SYSROOT:
		if (ioBuf == NULL || inBufLength ==0)
		{
			status = STATUS_UNSUCCESSFUL;
		}
		else
		{
			StringCbCopyNW(g_windows_directory, MAXPATHLEN*sizeof(WCHAR), ioBuf, inBufLength);
			build_white_process_list();
		}
		break;
	default:
		break;
	}

	pIrp->IoStatus.Status = status;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS dispatch_shutdown(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNICODE_STRING deviceDosName;

	g_is_file_run = FALSE;
	g_is_proc_run = FALSE;
	g_is_reg_run = FALSE;

	sw_register_uninit(g_driver_obj);
	sw_uninit_minifliter(g_driver_obj);
	sw_uninit_procss(g_driver_obj);
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


VOID driver_unload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING deviceDosName;
	PAGED_CODE();
	g_is_file_run = FALSE;
	g_is_proc_run = FALSE;
	g_is_reg_run = FALSE;

	sw_uninit_minifliter(g_driver_obj);
//	SleepImp(3);
	sw_uninit_procss(g_driver_obj);
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
}

NTSTATUS dispatch_pass(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
	return STATUS_SUCCESS;
}

BOOLEAN load_global_config(PUNICODE_STRING registryPath)
{
	NTSTATUS			status;
	OBJECT_ATTRIBUTES	objectAttributes;
	UNICODE_STRING		valueName;
	ULONG				resultLength;
	HANDLE				hKey = NULL;
	KEY_VALUE_PARTIAL_INFORMATION* regValue = NULL;
	UCHAR				buffer[512];
	regValue = (KEY_VALUE_PARTIAL_INFORMATION*)buffer;

	InitializeObjectAttributes(&objectAttributes,registryPath,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);

	status = ZwOpenKey(&hKey,KEY_READ,&objectAttributes);
	if (!NT_SUCCESS(status))
	{
		return FALSE;
	}
	RtlInitUnicodeString(&valueName,L"service_name");
	RtlZeroMemory(buffer, 512);
	status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, buffer, 512, &resultLength);
	if (!NT_SUCCESS(status) || regValue->Type != REG_SZ || resultLength >= MAXNAMELEN)
	{
		ZwClose(hKey);
		return FALSE;
	}

	StringCbCopyNW(g_service_name, MAXNAMELEN*sizeof(WCHAR), (WCHAR*)regValue->Data, regValue->DataLength);

	StringCbCopyW(g_device_name, MAXNAMELEN*sizeof(WCHAR), _DEVICE_NAME);
	StringCbCatNW(g_device_name, MAXNAMELEN*sizeof(WCHAR), (WCHAR*)regValue->Data, regValue->DataLength);
	
	StringCbCopyW(g_symbol_name, MAXNAMELEN*sizeof(WCHAR), _DEVICE_DOSNAME);
	StringCbCatNW(g_symbol_name, MAXNAMELEN*sizeof(WCHAR), (WCHAR*)regValue->Data, regValue->DataLength);

	StringCbCopyW(g_port_name, MAXNAMELEN*sizeof(WCHAR), L"\\");
	StringCbCatNW(g_port_name, MAXNAMELEN*sizeof(WCHAR), (WCHAR*)regValue->Data, regValue->DataLength);
	

	ZwClose(hKey);
	return TRUE;
}


NTSTATUS
DriverEntry (
     PDRIVER_OBJECT DriverObject,
     PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    
	BOOLEAN bNeedToDelDevice = FALSE;
	BOOLEAN bNeedToDelSym = FALSE;
	BOOLEAN bNeedToUninitMinifilter = FALSE;
	BOOLEAN bNeedToUninitProcmon = FALSE;
	BOOLEAN bNeedToUninitRegmon = FALSE;
	BOOLEAN bNeedToUnregShutdown = FALSE;
	UNICODE_STRING  deviceName = {0};
	UNICODE_STRING  deviceDosName = {0};
	int nIndex = 0;

	UNREFERENCED_PARAMETER( RegistryPath );
	
#ifdef DBG
	__debugbreak();
#endif

	if (NULL == g_ZwQueryInformationProcess)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
		g_ZwQueryInformationProcess =(QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
		if (NULL == g_ZwQueryInformationProcess)
		{
			return STATUS_UNSUCCESSFUL;
		}
	}
	
	if (NULL == g_zwQueryInformationThread)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"ZwQueryInformationThread");
		g_zwQueryInformationThread =(fn_NtQueryInformationThread)MmGetSystemRoutineAddress(&routineName);
		if (NULL == g_zwQueryInformationThread)
		{
			return STATUS_UNSUCCESSFUL;
		}
	}

	g_driver_obj = DriverObject;
	if (!load_global_config(RegistryPath))
	{
		return status;
	}

	for (; nIndex < IRP_MJ_MAXIMUM_FUNCTION; ++nIndex)
	{
		DriverObject->MajorFunction[nIndex] = dispatch_pass;
	}
	DriverObject->DriverUnload = driver_unload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = dispatch_create;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = dispatch_close;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatch_ictl;
	DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = dispatch_shutdown;


	RtlInitUnicodeString(&deviceName, g_device_name);
	status = IoCreateDevice(DriverObject,
		0,
		&deviceName,
		FILE_DEVICE_NETWORK,
		0,
		FALSE,
		&g_device_obj);
	if (!NT_SUCCESS(status))
	{
		goto err_ret;
	}
	bNeedToDelDevice = TRUE;

	status = IoRegisterShutdownNotification(g_device_obj);
	if (!NT_SUCCESS(status))
	{
		goto err_ret;
	}
	bNeedToUnregShutdown = TRUE;


	RtlInitUnicodeString(&deviceDosName, g_symbol_name);
	status = IoCreateSymbolicLink(&deviceDosName, &deviceName);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Create Symbolink name failed!\n"));
		goto err_ret;
	}

	bNeedToDelSym = TRUE;
	status = sw_init_minifliter(DriverObject);
	if (!NT_SUCCESS(status))
	{
		goto err_ret;
	}
	bNeedToUninitMinifilter = TRUE;
//#if (NTDDI_VERSION >= NTDDI_VISTA)
	status = sw_init_procss(DriverObject);
	if (!NT_SUCCESS(status))
	{
		goto err_ret;
	}
	bNeedToUninitProcmon = TRUE;
//#endif
	status = sw_register_init(DriverObject);
	if (!NT_SUCCESS(status))
	{
		goto err_ret;
	}
	bNeedToUninitRegmon = TRUE;
	g_is_driver_init = TRUE;
    return status;
err_ret:
	g_is_reg_run = FALSE;
	g_is_file_run = FALSE;
	g_is_proc_run = FALSE;

	if (bNeedToUnregShutdown)
	{
		IoUnregisterShutdownNotification(g_device_obj);
	}

	if (bNeedToDelSym)
	{
		RtlInitUnicodeString(&deviceDosName, g_symbol_name);
		IoDeleteSymbolicLink(&deviceDosName);
	}

	if (bNeedToDelDevice)
	{
		IoDeleteDevice(g_device_obj);
		g_device_obj = NULL;
	}

	if (bNeedToUninitRegmon)
	{
		sw_register_uninit(DriverObject);
	}
//#if (NTDDI_VERSION >= NTDDI_VISTA)
	if (bNeedToUninitProcmon)
	{
		sw_uninit_procss(DriverObject);
	}
//#endif
	if (bNeedToUninitMinifilter)
	{
		sw_uninit_minifliter(DriverObject);
	}
	return status;
}
