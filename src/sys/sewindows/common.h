#pragma once

#define SystemHandleInformation 16
typedef struct _FILE_LIST_ENTRY {

	LIST_ENTRY	Entry;
	PWSTR		NameBuffer;
} FILE_LIST_ENTRY, *PFILE_LIST_ENTRY;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT	UniqueProcessId;
	USHORT	CreatorBackTraceIndex;
	UCHAR	ObjectTypeIndex;
	UCHAR	HandleAttributes;
	USHORT	HandleValue;
	PVOID	Object;
	ULONG	GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	PSYSTEM_HANDLE_TABLE_ENTRY_INFO Handles;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;


BOOLEAN		is_directory_sep(WCHAR ch);
BOOLEAN		get_directory_long_name(WCHAR * wszRootDir,WCHAR * wszShortName,WCHAR *wszLongName,ULONG ulSize);
NTSTATUS	device_name_to_dos_name(IN PUNICODE_STRING DeviceName,OUT PUNICODE_STRING DosName);
BOOLEAN		get_dos_name(WCHAR *wszNTName, WCHAR *wszFileName);
PWCHAR		get_proc_name_by_pid(IN  HANDLE   dwProcessId, PWCHAR pPath);
BOOLEAN		query_long_name(WCHAR * wszFullPath, WCHAR * wszLongName, ULONG size);
BOOLEAN		convert_short_name_to_long(WCHAR *wszLongName, WCHAR *wszShortName, ULONG size);
BOOLEAN		is_short_name_path(WCHAR * wszFileName);
PWCHAR		wcsistr(PWCHAR wcs1, PWCHAR wcs2);
BOOLEAN		is_root_directory(WCHAR * wszDir);
BOOLEAN		is_file_path_pattern_match(const PWCHAR pExpression, const PWCHAR pName, BOOLEAN IgnoreCase);
BOOLEAN		is_common_pattern_match(WCHAR * pat, WCHAR * str);
VOID		to_upper_string(WCHAR* str);
VOID		kernel_sleep(IN LONG lminiSeccond);