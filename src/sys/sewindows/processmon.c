#include "main.h"
#include "processmon.h"
#include "lpc.h"
#include "regmon.h"
#include "filemon.h"
#include <strsafe.h>


#if (NTDDI_VERSION >= NTDDI_VISTA)

PVOID						g_proc_callback_handle = NULL;
OB_CALLBACK_REGISTRATION	g_proc_callback = { 0 };
OB_OPERATION_REGISTRATION	g_operation_registration[2] = { { 0 }, { 0 } };
static BOOLEAN				g_bSetCreateProcessNotify = FALSE;

OB_PREOP_CALLBACK_STATUS pre_procopration_callback( PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	HIPS_RULE_NODE	Pi;
	HANDLE			target_pid = NULL;
	ACCESS_MASK		OriginalDesiredAccess = 0;
	PACCESS_MASK	DesiredAccess = NULL;

	if (pOperationInformation->KernelHandle == TRUE || g_is_proc_run == FALSE)
	{
		return OB_PREOP_SUCCESS;
	}

	if (pOperationInformation->ObjectType == *PsThreadType)
	{
		target_pid = PsGetThreadProcessId ((PETHREAD)pOperationInformation->Object);
	}
	else if (pOperationInformation->ObjectType == *PsProcessType)
	{
		target_pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
	}
	else
	{
		return OB_PREOP_SUCCESS;
	}

	if ((PsGetCurrentProcessId() == target_pid))
	{
		return OB_PREOP_SUCCESS;
	}

	switch (pOperationInformation->Operation) 
	{
	case OB_OPERATION_HANDLE_CREATE:
		DesiredAccess = &pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
		OriginalDesiredAccess = pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
		break;
	case OB_OPERATION_HANDLE_DUPLICATE:
		DesiredAccess = &pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
		OriginalDesiredAccess = pOperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
		break;
	default:
		return OB_PREOP_SUCCESS;
	}

	RtlZeroMemory(&Pi, sizeof(HIPS_RULE_NODE));
	Pi.major_type = PROC_OP;
	Pi.sub_pid = PsGetCurrentProcessId();		

	Pi.obj_pid = target_pid;		

	if (pOperationInformation->ObjectType == *PsProcessType)
	{
		if ((OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
		{
			//	杀死进程
			Pi.minor_type = OP_PROC_KILL;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~PROCESS_TERMINATE;
			}
		}
		if ((OriginalDesiredAccess & PROCESS_CREATE_THREAD) == PROCESS_CREATE_THREAD)
		{	//	远程线程创建
			Pi.minor_type = OP_PROC_CREATE_REMOTE_THREAD;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~PROCESS_CREATE_THREAD;
			}
		}
		if ((OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
		{	//	修改内存属性
			Pi.minor_type = OP_PROC_CHANGE_VM;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~PROCESS_VM_OPERATION;
			}
		}
		if ((OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
		{	//	读内存
			Pi.minor_type = OP_PROC_READ_PROCESS;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~PROCESS_VM_READ;
			}
		}
		if ((OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
		{	//	写内存
			Pi.minor_type = OP_PROC_WRITE_PROCESS;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~PROCESS_VM_WRITE;
			}
		}
		if ((OriginalDesiredAccess & PROCESS_SUSPEND_RESUME) == PROCESS_SUSPEND_RESUME)
		{	
			Pi.minor_type = OP_PROC_SUSPEND_RESUME;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
			}
		}

		if ((OriginalDesiredAccess & PROCESS_DUP_HANDLE) == PROCESS_DUP_HANDLE)
		{	
			Pi.minor_type = OP_PROC_DUPHANDLE;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~PROCESS_DUP_HANDLE;
			}
		}
	}
	else
	{
		if ((OriginalDesiredAccess & THREAD_SUSPEND_RESUME) == THREAD_SUSPEND_RESUME)
		{	
			Pi.minor_type = OP_THREAD_SUSPEND_RESUME;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~THREAD_SUSPEND_RESUME;
			}
		}

		if ((OriginalDesiredAccess & THREAD_GET_CONTEXT) == THREAD_GET_CONTEXT)
		{	
			Pi.minor_type = OP_THREAD_GET_CONTEXT;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~THREAD_GET_CONTEXT;
			}
		}

		if ((OriginalDesiredAccess & THREAD_SET_CONTEXT) == THREAD_SET_CONTEXT)
		{	
			Pi.minor_type = OP_THREAD_SET_CONTEXT;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~THREAD_SET_CONTEXT;
			}
		}

		if ((OriginalDesiredAccess & THREAD_TERMINATE) == THREAD_TERMINATE)
		{	
			Pi.minor_type = OP_THREAD_KILL;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~THREAD_TERMINATE;
			}
		}
	}
	return OB_PREOP_SUCCESS;
}

VOID create_process_notity_routine( PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	HIPS_RULE_NODE Pi;
	RtlZeroMemory(&Pi, sizeof(HIPS_RULE_NODE));
	Pi.major_type = PROC_OP;

	if (g_is_proc_run == FALSE)
	{
		return;
	}

	if (CreateInfo != NULL)
	{
		Pi.sub_pid = CreateInfo->ParentProcessId;
		Pi.obj_pid = ProcessId;
		Pi.minor_type = OP_PROC_CREATE_PROCESS;
		StringCbCopyNW(Pi.des_path, sizeof(Pi.des_path), CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length);
		if (rule_match(&Pi) == FALSE)
		{
			CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL;
		}
	}
	else
	{
		if (g_current_pid == ProcessId)
		{
			g_is_file_run = FALSE;
			g_is_proc_run = FALSE;
			g_is_reg_run = FALSE;

		}
	}
}

NTSTATUS sw_init_procss(PDRIVER_OBJECT pDriverObj)
{
	NTSTATUS					Status = STATUS_SUCCESS;
	UNICODE_STRING				altitude = { 0 };
	WCHAR						szBuffer[20];
	ULONGLONG					ul_altitude = 1000;
	Status = PsSetCreateProcessNotifyRoutineEx(create_process_notity_routine,FALSE);
	if (NT_SUCCESS(Status))
	{
		g_bSetCreateProcessNotify = TRUE;

		g_operation_registration[0].ObjectType = PsProcessType;
		g_operation_registration[0].Operations |= OB_OPERATION_HANDLE_CREATE;
		g_operation_registration[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
		g_operation_registration[0].PreOperation = pre_procopration_callback;

		g_operation_registration[1].ObjectType = PsThreadType;
		g_operation_registration[1].Operations |= OB_OPERATION_HANDLE_CREATE;
		g_operation_registration[1].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
		g_operation_registration[1].PreOperation = pre_procopration_callback;
		g_proc_callback.Version = OB_FLT_REGISTRATION_VERSION;
		g_proc_callback.OperationRegistrationCount = 2;
		g_proc_callback.RegistrationContext = NULL;
		g_proc_callback.OperationRegistration = g_operation_registration;

try_again:
		RtlZeroMemory(szBuffer, sizeof(szBuffer));
		RtlInitEmptyUnicodeString(&altitude, szBuffer, 20 * sizeof(WCHAR));
		RtlInt64ToUnicodeString(ul_altitude, 10, &altitude);
		g_proc_callback.Altitude = altitude;
		Status = ObRegisterCallbacks(
			&g_proc_callback,
			&g_proc_callback_handle       
			);
		if (NT_SUCCESS(Status))
		{
			return Status;
		}

		if (STATUS_FLT_INSTANCE_ALTITUDE_COLLISION == Status)
		{
			ul_altitude++;
			if (ul_altitude<100000)
			{
				goto try_again;
			}
		}
		PsSetCreateProcessNotifyRoutineEx(create_process_notity_routine, TRUE);
		g_bSetCreateProcessNotify = FALSE;
	}
	return Status;
}

NTSTATUS sw_uninit_procss(PDRIVER_OBJECT pDriverObj)
{
	NTSTATUS Status = STATUS_SUCCESS;
	if (g_bSetCreateProcessNotify)
	{
		Status = PsSetCreateProcessNotifyRoutineEx(create_process_notity_routine, TRUE);
		g_bSetCreateProcessNotify = FALSE;
	}

	if (g_proc_callback_handle)
	{
		ObUnRegisterCallbacks(g_proc_callback_handle);
		g_proc_callback_handle = NULL;
	}
	return Status;
}

#else

#ifndef _WIN64

#include <ntimage.h>

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //Used only in checked build
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG		Reserved[2];
	PVOID		Base;
	ULONG		Size;
	ULONG		Flags;
	USHORT		Index;
	USHORT		Unknown;
	USHORT		LoadCount;
	USHORT		ModNameOffset;
	CHAR		ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYS_MOD_INFO {
	ULONG	NumberOfModules;
	SYSTEM_MODULE_INFORMATION Module[1];
} SYS_MOD_INFO, *PSYS_MOD_INFO;


typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,             // obsolete...delete
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemVerifierAddDriverInformation,
    SystemVerifierRemoveDriverInformation,
    SystemProcessorIdleInformation,
    SystemLegacyDriverInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemVerifierThunkExtend,
    SystemSessionProcessInformation,
    SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformation,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;



typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    KPRIORITY Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION;
typedef THREAD_BASIC_INFORMATION *PTHREAD_BASIC_INFORMATION;


typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _PROCESS_NODE
{
	LIST_ENTRY	list;
	HANDLE		pid;
}PROCESS_NODE,*PPROCESS_NODE; 

typedef struct _PROCESS_LIST
{
	LIST_ENTRY	list_head;
	ERESOURCE	lock;
}PROCESS_LIST,*PPROCESS_LIST; 

PROCESS_LIST g_process_list;

void init_process_list()
{
	InitializeListHead(&g_process_list.list_head);
	ExInitializeResourceLite( &g_process_list.lock );
}

BOOLEAN  AcquireResourceExclusive ( __inout PERESOURCE Resource )
{
	BOOLEAN ret;
	KeEnterCriticalRegion();
	ret = ExAcquireResourceExclusiveLite( Resource, TRUE );
	KeLeaveCriticalRegion();
	return ret;
}

BOOLEAN  AcquireResourceShare ( __inout PERESOURCE Resource )
{
	BOOLEAN ret;
	KeEnterCriticalRegion();
	ret = ExAcquireResourceSharedLite( Resource, TRUE );
	KeLeaveCriticalRegion();
	return ret;
}


VOID ReleaseResource( __inout PERESOURCE Resource )
{
	KeEnterCriticalRegion();
	ExReleaseResourceLite( Resource );
	KeLeaveCriticalRegion();
}


void un_init_process_list()
{
	PLIST_ENTRY		Flink;
	PPROCESS_NODE	pdev_list_entry;
	static	BOOLEAN bUnInit = FALSE;

	if (bUnInit)
	{
		return;
	}
	bUnInit = TRUE;
	AcquireResourceExclusive( &g_process_list.lock );
	
	if ( IsListEmpty( &g_process_list.list_head ) )
	{
		ReleaseResource( &g_process_list.lock );
		ExDeleteResourceLite(&g_process_list.lock);
		return;
	}

	Flink=g_process_list.list_head.Flink;
	while ( Flink!=&g_process_list.list_head )
	{
		pdev_list_entry=CONTAINING_RECORD( Flink, PROCESS_NODE, list );

		Flink=Flink->Flink;
		RemoveEntryList( Flink->Blink );

		if ( pdev_list_entry )
		{
			ExFreePool( pdev_list_entry );
		}
	}
	ReleaseResource( &g_process_list.lock );
	ExDeleteResourceLite(&g_process_list.lock);
}

NTSTATUS del_pid_from_list_ex(__in PLIST_ENTRY pDevRulHead, __in HANDLE pid)
{
	PLIST_ENTRY		Flink = NULL;
	PPROCESS_NODE	pdev_rul_entry = NULL;

	if (!pDevRulHead) 
	{
		return STATUS_INVALID_PARAMETER;
	}

	if ( IsListEmpty( pDevRulHead ) )
	{
		return	STATUS_SUCCESS;
	}

	Flink=pDevRulHead->Flink;
	while ( Flink != pDevRulHead )
	{
		pdev_rul_entry=CONTAINING_RECORD( Flink, PROCESS_NODE, list );
		if (pdev_rul_entry->pid == pid)
		{
			Flink = Flink->Flink;
			RemoveEntryList(Flink->Blink);

			if ( pdev_rul_entry )
			{
				ExFreePool (pdev_rul_entry);
			}	
		}
		else
		{
			Flink=Flink->Flink;
		}	
	}
	return STATUS_SUCCESS;
}


BOOLEAN is_pid_in_list(__in HANDLE pid)
{
	PLIST_ENTRY		Flink = NULL;
	PPROCESS_NODE	pdev_rul_entry = NULL;

	AcquireResourceShare ( &g_process_list.lock );

	if ( IsListEmpty( &g_process_list.list_head ) )
	{
		ReleaseResource( &g_process_list.lock );
		return	FALSE;
	}

	Flink=g_process_list.list_head.Flink;
	while ( Flink != &g_process_list.list_head )
	{
		pdev_rul_entry=CONTAINING_RECORD( Flink, PROCESS_NODE, list );
		if (pdev_rul_entry->pid == pid)
		{
			ReleaseResource( &g_process_list.lock );
			return TRUE;
		}
		else
		{
			Flink=Flink->Flink;
		}	
	}
	ReleaseResource( &g_process_list.lock );
	return	FALSE;
}


NTSTATUS del_pid_from_list(__in HANDLE pid)
{
	NTSTATUS status;
	AcquireResourceExclusive(&g_process_list.lock );
	status = del_pid_from_list_ex( &g_process_list.list_head, pid );
	ReleaseResource( &g_process_list.lock );
	return status;
}


NTSTATUS insert_pid_to_list( __in HANDLE pid)
{
	NTSTATUS status = STATUS_SUCCESS;
	PPROCESS_NODE	pdev_rul_entry = NULL;
	AcquireResourceExclusive( &g_process_list.lock );

	pdev_rul_entry = ExAllocatePoolWithTag( PagedPool, sizeof (PROCESS_NODE), 'proc' );

	if (pdev_rul_entry)
	{
		RtlZeroMemory(pdev_rul_entry, sizeof (PROCESS_NODE));
		pdev_rul_entry->pid = pid;
		InsertHeadList( &g_process_list.list_head, &(pdev_rul_entry->list) );
	}
	else
	{
		status = STATUS_UNSUCCESSFUL;
	}
	ReleaseResource( &g_process_list.lock );
	return status;
}



__declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

#define SYSTEMSERVICE_BY_FUNC_ID(_func_id)				KeServiceDescriptorTable.ServiceTableBase[_func_id]
#define VALID_RVA(__rva1__, __hdr1__)					(GetEnclosingSectionHeader(__rva1__, __hdr1__)?TRUE:FALSE)
#define PTR_FROM_RVA(__img_base__, __hdr__, __rva__)	(VALID_RVA(__rva__, __hdr__)?(PCHAR)__img_base__+(ULONG_PTR)__rva__:NULL)
#define RVA_FROM_PTR(__img_base__, __ptr__)				((ULONG)((ULONG_PTR)__ptr__-(ULONG_PTR)__img_base__))
#define IMG_DIR_ENTRY_RVA(__hdr__, __i__)				(__hdr__->OptionalHeader.DataDirectory[__i__].VirtualAddress)
#define IMG_DIR_ENTRY_SIZE(__hdr__, __i__)				(__hdr__->OptionalHeader.DataDirectory[__i__].Size)
#define PAGE_BASE(__ptr__)								((ULONG_PTR)__ptr__ & ~((ULONG_PTR)PAGE_SIZE-1LL))
#define PAGE_OFFSET(__ptr__)							((ULONG_PTR)__ptr__ & ((ULONG_PTR)PAGE_SIZE-1LL))

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

NTSTATUS (__stdcall *real_NtTerminateProcess)( 
	__in HANDLE ProcessHandle,
	__in ULONG ProcessExitCode
	);

NTSTATUS (__stdcall *real_NtCreateThread) (
	__out PHANDLE ThreadHandle,
	__in ACCESS_MASK DesiredAccess, 
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in HANDLE ProcessHandle,
	__out PCLIENT_ID ClientID, 
	__in PCONTEXT Context,
	__in /*PUSER_STACK*/PVOID StackInfo,
	__in BOOLEAN CreateSuspended
	);


NTSTATUS (NTAPI *real_NtResumeThread)(IN HANDLE ThreadHandle,OUT PULONG SuspendCount OPTIONAL);


static PVOID	g_BaseOfNtDllDll = 0;
static ULONG	g_NtTerminateProcess_index = MAXULONG;
static ULONG	g_NtCreateThread_index = MAXULONG;
static ULONG	g_NtResumeThread_index = MAXULONG;


ULONG CheckException ()
{
	return EXCEPTION_EXECUTE_HANDLER;
}


NTSTATUS Sys_GetProcessIdByHandle (HANDLE ProcessHandle, PHANDLE pProcessId)
{
	NTSTATUS status;
	PROCESS_BASIC_INFORMATION ProcInfo;

	if (!ProcessHandle || UlongToHandle( -1 ) == ProcessHandle)
	{
		return STATUS_UNSUCCESSFUL;
	}

	status = g_ZwQueryInformationProcess (ProcessHandle,ProcessBasicInformation,&ProcInfo,sizeof(ProcInfo),NULL);

	if (NT_SUCCESS( status ))
	{
#ifdef _WIN64
		*pProcessId = (HANDLE) ProcInfo.UniqueProcessId;
#else
		*pProcessId = ULongToHandle( ProcInfo.UniqueProcessId );
#endif
	}
	return status;
}

PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(ULONG RVA, PIMAGE_NT_HEADERS pNtHeader)
{
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);
    ULONG i;
    
    for (i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++, pSection++)
    {
		ULONG SectionSize = pSection->Misc.VirtualSize;
		if (0 == SectionSize)
		{
			SectionSize = pSection->SizeOfRawData;
		}
			
        if ( RVA >= pSection->VirtualAddress && RVA <  pSection->VirtualAddress+SectionSize)
		{
			return pSection;
		}
    }
    return NULL;
}


PVOID GetExport(IN PVOID ImageBase, IN PCHAR NativeName, OUT PVOID *p_ExportAddr OPTIONAL, OUT PULONG pNativeSize OPTIONAL) 
{
	PIMAGE_EXPORT_DIRECTORY pExportDir;
	ULONG					i;
	PULONG					pFunctionRVAs;
	PUSHORT					pOrdinals;
	PULONG					pFuncNameRVAs;
	ULONG					exportsStartRVA;
	PIMAGE_DOS_HEADER		pDosHeader;
	PIMAGE_NT_HEADERS		pNTHeader;

	__try
	{
		pDosHeader= (PIMAGE_DOS_HEADER)ImageBase;
		if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return NULL;
		}

		pNTHeader = (PIMAGE_NT_HEADERS)((PCHAR)ImageBase+pDosHeader->e_lfanew);
		if(pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			return NULL;
		}
			
		exportsStartRVA = IMG_DIR_ENTRY_RVA(pNTHeader, IMAGE_DIRECTORY_ENTRY_EXPORT);
		pExportDir = (PIMAGE_EXPORT_DIRECTORY)PTR_FROM_RVA(ImageBase, pNTHeader, exportsStartRVA);
		if (!pExportDir)
		{
			return NULL;
		}
	
		pFunctionRVAs = (PULONG)PTR_FROM_RVA(ImageBase, pNTHeader, pExportDir->AddressOfFunctions);
		if (!pFunctionRVAs)
		{
			return NULL;
		}
			
		pOrdinals = (PUSHORT)PTR_FROM_RVA(ImageBase, pNTHeader, pExportDir->AddressOfNameOrdinals);
		if (!pOrdinals)
		{
			return NULL;
		}
			
		pFuncNameRVAs = (PULONG)PTR_FROM_RVA(ImageBase, pNTHeader, pExportDir->AddressOfNames);
		if (!pFuncNameRVAs)
		{
			return NULL;
		}
			

		for (i = 0; i < pExportDir->NumberOfNames; i++)
		{
			PCHAR FuncName;
			ULONG FuncNameRVA = pFuncNameRVAs[i];

			FuncName = PTR_FROM_RVA(ImageBase, pNTHeader, FuncNameRVA);
			if (!FuncName)
			{
				continue;
			}
				
			if(0 == strcmp(FuncName, NativeName))
			{
				USHORT Ordinal = pOrdinals[i];
				ULONG FuncRVA  = pFunctionRVAs[Ordinal];
				
				if(p_ExportAddr)
				{
					*p_ExportAddr = &pFunctionRVAs[Ordinal];
				}
					
				if (pNativeSize)
				{
					ULONG j;
					ULONG MinRVA = MAXULONG;

					for (j = 0; j < pExportDir->NumberOfFunctions; j++)
					{
						ULONG CurrRVA = pFunctionRVAs[j];

						if (CurrRVA > FuncRVA && CurrRVA < MinRVA)
						{
							MinRVA = CurrRVA;
						}
					}

					*pNativeSize = MinRVA-FuncRVA;
				}

				return PTR_FROM_RVA(ImageBase, pNTHeader, FuncRVA);
			}
		}
	}
	__except(CheckException())
	{
		return NULL;
	}
	return NULL;
}


PVOID GetNativeBase (PCHAR DllName)
{
	ULONG		BufLen;
	ULONG		i;
	PVOID		ret = NULL;
	PULONG		qBuff;
	PSYSTEM_MODULE_INFORMATION Mod;

	NTSTATUS status = ZwQuerySystemInformation( 11, &BufLen, 0, &BufLen );
	if (STATUS_INFO_LENGTH_MISMATCH != status || !BufLen)
	{
		return NULL;
	}
		
	qBuff = ExAllocatePoolWithTag( PagedPool, BufLen, 'HOOK' );
	if(!qBuff)
	{
		return NULL;
	}
		
	status = ZwQuerySystemInformation( 11, qBuff, BufLen, NULL );
	if(NT_SUCCESS( status ))
	{
		Mod = (PSYSTEM_MODULE_INFORMATION)( qBuff + 1 );
		for(i = 0; i < *qBuff; i++)
		{
			if(!_stricmp( Mod[i].ImageName + Mod[i].ModNameOffset, DllName ))
			{
				ret = Mod[i].Base;
				break;
			}
		}
	}
	ExFreePool( qBuff );
	return ret;
}

ULONG GetNativeID (__in PVOID NativeBase,__in PSTR NativeName)
{
	PVOID NativeEP;
	PVOID paddr = 0;
	
	if (!NativeBase)
	{
		return 0;
	}

	NativeEP = GetExport(NativeBase, NativeName, &paddr, NULL);
	if(NativeEP)
	{
		if(((UCHAR*)NativeEP)[0] == 0xB8) // MOV EAX,XXXXXXXX?
		{
			return ((ULONG*)((PCHAR)NativeEP+1))[0];
		}
	}
	return 0;
}

NTSTATUS
__stdcall
fake_NtTerminateProcess ( __in HANDLE ProcessHandle, __in ULONG ProcessExitCode )
{
	NTSTATUS		status;
	HIPS_RULE_NODE	Pi;
	HANDLE			hDestProcessId;

	if (ExGetPreviousMode() == KernelMode || 
		KeGetCurrentIrql() >= DISPATCH_LEVEL || 
		g_is_proc_run == FALSE ||
		PsGetCurrentProcessId() == (HANDLE)4 || 
		PsGetCurrentProcessId() == (HANDLE)0 ||
		g_current_pid == PsGetCurrentProcessId()|| 
		ProcessHandle == UlongToHandle(-1)
		)
	{
		return real_NtTerminateProcess( ProcessHandle, ProcessExitCode );
	}

	if (is_process_in_white_list(PsGetCurrentProcessId()))
	{
		return real_NtTerminateProcess( ProcessHandle, ProcessExitCode );
	}

	if (!NT_SUCCESS( Sys_GetProcessIdByHandle( ProcessHandle, &hDestProcessId ) ))
	{
		return real_NtTerminateProcess( ProcessHandle, ProcessExitCode );
	}

	RtlZeroMemory(&Pi, sizeof(HIPS_RULE_NODE));
	Pi.major_type = PROC_OP;
	Pi.sub_pid = PsGetCurrentProcessId();		
	Pi.obj_pid = hDestProcessId;		
	Pi.minor_type = OP_PROC_KILL;

	if (rule_match(&Pi) == FALSE)
	{
		return STATUS_ACCESS_DENIED;
	}
	else
	{
		return real_NtTerminateProcess( ProcessHandle, ProcessExitCode );
	}
}

NTSTATUS
__stdcall
fake_NtCreateThread (
				 __out PHANDLE ThreadHandle,
				 __in ACCESS_MASK DesiredAccess, 
				 __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
				 __in HANDLE ProcessHandle,
				 __out PCLIENT_ID ClientID, 
				 __in PCONTEXT Context,
				 __in /*PUSER_STACK*/PVOID StackInfo,
				 __in BOOLEAN CreateSuspended
				 )
{

	NTSTATUS		status;
	HIPS_RULE_NODE	Pi;
	HANDLE			hDestProcessId;

	if (ExGetPreviousMode() == KernelMode || 
		KeGetCurrentIrql() >= DISPATCH_LEVEL || 
		g_is_proc_run == FALSE ||
		PsGetCurrentProcessId() == (HANDLE)4 || 
		PsGetCurrentProcessId() == (HANDLE)0 ||
		ProcessHandle == UlongToHandle(-1) ||
		g_current_pid == PsGetCurrentProcessId()|| 
		ProcessHandle == 0
		)
	{
		return real_NtCreateThread( ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientID, Context, StackInfo, CreateSuspended );
	}

	if (is_process_in_white_list(PsGetCurrentProcessId()))
	{
		return real_NtCreateThread( ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientID, Context, StackInfo, CreateSuspended );
	}

	if (!NT_SUCCESS( Sys_GetProcessIdByHandle( ProcessHandle, &hDestProcessId ) ))
	{
		hDestProcessId = PsGetCurrentProcessId(); // skip
	}

	if (PsGetCurrentProcessId() == hDestProcessId)
	{
		return real_NtCreateThread( ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientID, Context, StackInfo, CreateSuspended );
	}

	RtlZeroMemory(&Pi, sizeof(HIPS_RULE_NODE));
	Pi.major_type = PROC_OP;
	Pi.sub_pid = PsGetCurrentProcessId();		
	Pi.obj_pid = hDestProcessId;		
	Pi.minor_type = OP_PROC_CREATE_REMOTE_THREAD;

	if (rule_match(&Pi) == FALSE)
	{
		return STATUS_ACCESS_DENIED;
	}
	else
	{
		return real_NtCreateThread( ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientID, Context, StackInfo, CreateSuspended );
	}
}

BOOLEAN enum_system_process()
{
	ULONG		BufLen=0;
	PVOID		ret = NULL;
	PULONG		qBuff;
	PSYSTEM_PROCESS_INFORMATION process;
	PSYSTEM_PROCESS_INFORMATION p  = NULL;

	NTSTATUS status = ZwQuerySystemInformation( SystemProcessInformation, &BufLen, 0, &BufLen );
	if (STATUS_INFO_LENGTH_MISMATCH != status || !BufLen)
	{
		return FALSE;
	}
		
	qBuff = ExAllocatePoolWithTag( PagedPool, BufLen, 'HOOK' );
	if(!qBuff)
	{
		return FALSE;
	}
		
	status = ZwQuerySystemInformation( SystemProcessInformation, qBuff, BufLen, NULL );
	if(NT_SUCCESS( status ))
	{
		process = (PSYSTEM_PROCESS_INFORMATION)qBuff; 
		do 
		{   
			insert_pid_to_list(process->UniqueProcessId);
			DbgPrint("%wZ\n",&process->ImageName);
			process = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)process +process->NextEntryOffset );  
		}while ( process->NextEntryOffset != 0 );
	}
	ExFreePool( qBuff );
	return TRUE;
}

NTSTATUS NTAPI fake_NtResumeThread(IN HANDLE ThreadHandle,OUT PULONG SuspendCount OPTIONAL)
{
	WCHAR			parent_proc[260];
	NTSTATUS		status;
	HANDLE			target_pid = NULL;
	THREAD_BASIC_INFORMATION tbi;
	
	if (ExGetPreviousMode() == KernelMode || 
		KeGetCurrentIrql() >= DISPATCH_LEVEL || 
		PsGetCurrentProcessId() == (HANDLE)4 || 
		PsGetCurrentProcessId() == (HANDLE)0 ||
		g_current_pid == PsGetCurrentProcessId()|| 
		ThreadHandle == NULL)
	{
		return real_NtResumeThread(ThreadHandle,SuspendCount);
	}

	status = g_zwQueryInformationThread(ThreadHandle,ThreadBasicInformation,&tbi,sizeof(tbi),NULL);
	if ( ! NT_SUCCESS(status) )
	{
		return real_NtResumeThread(ThreadHandle,SuspendCount);
	}

	if (tbi.ClientId.UniqueProcess == PsGetCurrentProcessId())
	{
		return real_NtResumeThread(ThreadHandle,SuspendCount);
	}


	if(is_pid_in_list(tbi.ClientId.UniqueProcess))
	{
		return real_NtResumeThread(ThreadHandle,SuspendCount);
	}


	notify_process_create(tbi.ClientId.UniqueProcess);

	insert_pid_to_list(tbi.ClientId.UniqueProcess);

	//if (!get_proc_name_by_pid(PsGetCurrentProcessId(),parent_proc))
	//{
	//	return real_NtResumeThread(ThreadHandle,SuspendCount);
	//}
	//DbgPrint("parent: %S\n",parent_proc);
	//
	//target_pid = tbi.ClientId.UniqueProcess;

	//get_proc_name_by_pid(target_pid,parent_proc);
	//DbgPrint("sub: %S\n",parent_proc);
	return real_NtResumeThread(ThreadHandle,SuspendCount);
}

BOOLEAN
HookNtFunc (
	__out PULONG pInterceptedFuncAddress,
	__out PULONG pFuncIndex,
	__in ULONG   NewFuncAddress,
	__in PCHAR   FuncName
	)
{
	BOOLEAN bPatched = FALSE;
	ULONG NativeID = 0;
	if (!pInterceptedFuncAddress || !pFuncIndex)
	{
		return FALSE;
	}

	NativeID = GetNativeID( g_BaseOfNtDllDll, FuncName );

	if (NativeID)
	{
		*pInterceptedFuncAddress = SYSTEMSERVICE_BY_FUNC_ID( NativeID );
		*pFuncIndex = NativeID;
		__asm
	{
		cli
		push eax
		mov eax,cr0
		and eax,not 0x10000
		mov cr0,eax
		pop eax
	}

		SYSTEMSERVICE_BY_FUNC_ID( NativeID ) = NewFuncAddress;

		__asm
	{
		push eax
		mov eax,cr0
		or eax,0x10000
		mov cr0,eax
		pop eax
		sti
	}

		bPatched = TRUE;
	}
	return bPatched;
}


VOID
UnHookNtFunc (
	__in ULONG	 FuncIndex,
	__in ULONG   RealFuncAddress
	)
{
	if (MAXULONG == FuncIndex || !RealFuncAddress)
	{
		return ;
	}

	__asm
	{
		cli
		push eax
		mov eax,cr0
		and eax,not 0x10000
		mov cr0,eax
		pop eax
	}

	InterlockedExchange( (PLONG) &SYSTEMSERVICE_BY_FUNC_ID( FuncIndex )    ,  (LONG) RealFuncAddress    );

	__asm
	{
		push eax
		mov eax,cr0
		or eax,0x10000
		mov cr0,eax
		pop eax
		sti
	}
}

NTSTATUS sw_init_procss(PDRIVER_OBJECT pDriverObj)
{
	NTSTATUS					Status = STATUS_SUCCESS;
	
	g_BaseOfNtDllDll = GetNativeBase( "NTDLL.DLL" );

	if (!g_BaseOfNtDllDll)
	{
		return STATUS_UNSUCCESSFUL;
	}
	init_process_list();

	HookNtFunc( (ULONG*) &real_NtTerminateProcess,&g_NtTerminateProcess_index, (ULONG) fake_NtTerminateProcess, "NtTerminateProcess");
	HookNtFunc( (ULONG*) &real_NtCreateThread,&g_NtCreateThread_index, (ULONG) fake_NtCreateThread, "NtCreateThread");
	HookNtFunc( (ULONG*) &real_NtResumeThread,&g_NtResumeThread_index, (ULONG) fake_NtResumeThread, "NtResumeThread");
	
	if (!enum_system_process())
	{
		UnHookNtFunc(g_NtTerminateProcess_index,(ULONG)real_NtTerminateProcess);
		g_NtTerminateProcess_index = MAXULONG;
	
		UnHookNtFunc(g_NtCreateThread_index,(ULONG)real_NtCreateThread);
		g_NtCreateThread_index = MAXULONG;

		UnHookNtFunc(g_NtResumeThread_index,(ULONG)real_NtResumeThread);
		g_NtResumeThread_index = MAXULONG;
		un_init_process_list();
		Status = STATUS_UNSUCCESSFUL;
	}
	return Status;
}


NTSTATUS sw_uninit_procss(PDRIVER_OBJECT pDriverObj)
{
	NTSTATUS Status = STATUS_SUCCESS;

	UnHookNtFunc(g_NtTerminateProcess_index,(ULONG)real_NtTerminateProcess);
	g_NtTerminateProcess_index = MAXULONG;
	
	UnHookNtFunc(g_NtCreateThread_index,(ULONG)real_NtCreateThread);
	g_NtCreateThread_index = MAXULONG;

	UnHookNtFunc(g_NtResumeThread_index,(ULONG)real_NtResumeThread);
	g_NtResumeThread_index = MAXULONG;
	un_init_process_list();
	return Status;
}

#endif 

#endif