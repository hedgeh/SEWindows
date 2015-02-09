#pragma once


#define	FILE_READ_DATA_XX		1
#define	FILE_WRITE_DATA_XX		2
#define	FILE_DEL_XX				3
#define	FILE_RENAME_XX			4
#define	FILE_CREATE_XX			5
#define	FILE_SETINFO_XX			6
#define	FILE_EXECUTE_XX			7



NTSTATUS sw_unload( FLT_FILTER_UNLOAD_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS	sw_pre_create_callback(PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS FltObjects,PVOID *CompletionContext);
FLT_POSTOP_CALLBACK_STATUS	sw_post_create_callback( PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS	sw_pre_setinfo_callback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);


NTSTATUS	sw_init_minifliter(PDRIVER_OBJECT pDriverObj);
NTSTATUS	sw_uninit_minifliter(PDRIVER_OBJECT pDriverObj);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, sw_pre_create_callback)
#pragma alloc_text(PAGE, sw_post_create_callback)
#pragma alloc_text(PAGE, sw_pre_setinfo_callback)
#pragma alloc_text(PAGE, sw_unload)
#pragma alloc_text(PAGE, sw_init_minifliter)
#pragma alloc_text(PAGE, sw_uninit_minifliter)
#endif
