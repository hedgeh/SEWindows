#include "main.h"
#include <strsafe.h>
#include "common.h"

NTKERNELAPI PCHAR PsGetProcessImageFileName(PEPROCESS Process);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG    SystemInformationClass,PVOID    SystemInformation,ULONG    SystemInformationLength,PULONG    ReturnLength);
#define DELAY_ONE_MICROSECOND ( -10 )
#define DELAY_ONE_MILLISECOND	( DELAY_ONE_MICROSECOND * 1000 )

QUERY_INFO_PROCESS g_ZwQueryInformationProcess = NULL;


VOID to_upper_string(WCHAR* str)
{
	int i = 0;
	for (; str[i]; i++)
	{
		str[i] = towupper(str[i]);
	}
}

BOOLEAN is_root_directory(WCHAR * wszDir)
{
	SIZE_T length = wcslen(wszDir);

	if ((length == 2) && (wszDir[1] == L':'))
		return TRUE;

	if ((length == 6) &&
		(_wcsnicmp(wszDir, L"\\??\\", 4) == 0) &&
		(wszDir[5] == L':'))
		return TRUE;

	if ((length == 14) &&
		(_wcsnicmp(wszDir, L"\\DosDevices\\", 12) == 0) &&
		(wszDir[13] == L':'))
		return TRUE;

	if ((length == 23) &&
		(_wcsnicmp(wszDir, L"\\Device\\HarddiskVolume", 22) == 0))
		return TRUE;

	return FALSE;
}


PWCHAR wcsistr(PWCHAR s1, PWCHAR s2)
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

BOOLEAN get_directory_long_name(WCHAR * wszRootDir,WCHAR * wszShortName,WCHAR *wszLongName,ULONG ulSize)
{
	UNICODE_STRING				ustrRootDir = { 0 };
	UNICODE_STRING				ustrShortName = { 0 };
	UNICODE_STRING				ustrLongName = { 0 };
	OBJECT_ATTRIBUTES			oa = { 0 };
	IO_STATUS_BLOCK				Iosb = { 0 };
	NTSTATUS					ntStatus = 0;
	HANDLE						hDirHandle = 0;
	unsigned char				*Buffer = NULL;
	WCHAR						*wszRoot = NULL;
	PFILE_BOTH_DIR_INFORMATION	pInfo = NULL;

	RtlZeroMemory(&Iosb, sizeof(IO_STATUS_BLOCK));
	Iosb.Status = STATUS_NO_SUCH_FILE;

	wszRoot = ExAllocatePoolWithTag(PagedPool,MAXPATHLEN * sizeof(WCHAR),'L2S');
	if (wszRoot == NULL)
	{
		return FALSE;
	}

	RtlZeroMemory(wszRoot, MAXPATHLEN * sizeof(WCHAR));

	wcsncpy(wszRoot, wszRootDir, MAXPATHLEN);

	RtlInitUnicodeString(&ustrRootDir, wszRoot);
	RtlInitUnicodeString(&ustrShortName, wszShortName);

	if (is_root_directory(wszRoot))
		RtlAppendUnicodeToString(&ustrRootDir, L"\\");

	InitializeObjectAttributes(&oa,
		&ustrRootDir,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		0,
		0);

	ntStatus = ZwCreateFile(&hDirHandle,
		GENERIC_READ | SYNCHRONIZE,
		&oa,
		&Iosb,
		0,
		FILE_ATTRIBUTE_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0);

	if (!NT_SUCCESS(ntStatus))
	{
		ExFreePool(wszRoot);
		return FALSE;
	}

	ExFreePool(wszRoot);

	Buffer = ExAllocatePoolWithTag(PagedPool,1024,'L2S');
	if (Buffer == NULL)
	{
		ZwClose(hDirHandle);
		return FALSE;
	}

	RtlZeroMemory(Buffer, 1024);

	ntStatus = ZwQueryDirectoryFile(hDirHandle,
		NULL,
		0,
		0,
		&Iosb,
		Buffer,
		1024,
		FileBothDirectoryInformation,
		TRUE,
		&ustrShortName,
		TRUE);

	if (!NT_SUCCESS(ntStatus))
	{
		ExFreePool(Buffer);
		ZwClose(hDirHandle);
		return FALSE;
	}

	ZwClose(hDirHandle);

	pInfo = (PFILE_BOTH_DIR_INFORMATION)Buffer;

	if (pInfo->FileNameLength == 0)
	{
		ExFreePool(Buffer);
		return FALSE;
	}

	ustrShortName.Length = (USHORT)pInfo->FileNameLength;
	ustrShortName.MaximumLength = (USHORT)pInfo->FileNameLength;
	ustrShortName.Buffer = pInfo->FileName;	

	if (ulSize < ustrShortName.Length)
	{
		ExFreePool(Buffer);
		return FALSE;
	}

	ustrLongName.Length = 0;
	ustrLongName.MaximumLength = (USHORT)ulSize;
	ustrLongName.Buffer = wszLongName;

	RtlCopyUnicodeString(&ustrLongName, &ustrShortName);
	ExFreePool(Buffer);
	return TRUE;
}


BOOLEAN is_directory_sep(WCHAR ch)
{
	return (ch == L'\\' || ch == L'/');
}

NTSTATUS
device_name_to_dos_name(
IN PUNICODE_STRING DeviceName,
OUT PUNICODE_STRING DosName
)
{
	NTSTATUS				status = STATUS_UNSUCCESSFUL;
	WCHAR					c = L'\0';
	__try
	{
		for (c = L'A'; c <= L'Z'; c++)
		{
			if (wcslen(g_path_table[c-'A'].nt_name) >0 &&_wcsicmp(DeviceName->Buffer,g_path_table[c-'A'].nt_name)==0)
			{
				wcscpy(DosName->Buffer,g_path_table[c-'A'].dos_name);
				break;
			}
			else
			{
				continue;
			}
		}

		if (c <= L'Z')
		{
			DosName->MaximumLength = 6;
			DosName->Length = 4;
			return STATUS_SUCCESS;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		status = STATUS_UNSUCCESSFUL;
	}
	return status;
}




BOOLEAN  get_dos_name(WCHAR *wszNTName, WCHAR *wszFileName)
{
	UNICODE_STRING		ustrFileName = { 0 };
	UNICODE_STRING		ustrDosName = { 0 };
	UNICODE_STRING		ustrDeviceName = { 0 };

	WCHAR				*pPath = NULL;
	ULONG				i = 0;
	ULONG				ulSepNum = 0;
	WCHAR				wclinkTarget[10] = { 0 };
	RtlInitEmptyUnicodeString(&ustrDosName, wclinkTarget, sizeof(wclinkTarget));
	if (wszFileName == NULL || wszNTName == NULL )
	{
		return FALSE;
	}
	
	if (_wcsnicmp(wszNTName, L"\\??\\", wcslen(L"\\??\\")) == 0)
	{
		StringCbCopyW(wszFileName,MAXPATHLEN*sizeof(WCHAR),&wszNTName[wcslen(L"\\??\\")]);
		return TRUE;
	}
	if (_wcsnicmp(wszNTName, L"\\device\\harddiskvolume", wcslen(L"\\device\\harddiskvolume")) != 0)
	{
		return FALSE;
	}

	ustrFileName.Buffer = wszFileName;
	ustrFileName.Length = 0;
	ustrFileName.MaximumLength = sizeof(WCHAR)*MAXPATHLEN;

	while (wszNTName[i] != L'\0')
	{

		if (wszNTName[i] == L'\0')
		{
			break;
		}
		if (wszNTName[i] == L'\\')
		{
			ulSepNum++;
		}
		if (ulSepNum == 3)
		{
			wszNTName[i] = UNICODE_NULL;
			pPath = &wszNTName[i + 1];
			break;
		}
		i++;
	}

	if (pPath == NULL)
	{
		return FALSE;
	}

	RtlInitUnicodeString(&ustrDeviceName, wszNTName);

	if (!NT_SUCCESS(device_name_to_dos_name(&ustrDeviceName, &ustrDosName)))
	{
		return FALSE;
	}

	RtlCopyUnicodeString(&ustrFileName, &ustrDosName);
	RtlAppendUnicodeToString(&ustrFileName, L"\\");
	RtlAppendUnicodeToString(&ustrFileName, pPath);

	return TRUE;
}

BOOLEAN query_long_name(WCHAR * wszFullPath, WCHAR * wszLongName, ULONG size)
{
	BOOLEAN		rtn = FALSE;
	WCHAR *		pchStart = wszFullPath;
	WCHAR *		pchEnd = NULL;
	WCHAR *		wszShortName = NULL;


	while (*pchStart)
	{
		if (is_directory_sep(*pchStart))
			pchEnd = pchStart;

		pchStart++;
	}


	if (pchEnd)
	{
		*pchEnd++ = L'\0';
		wszShortName = pchEnd;
		rtn = get_directory_long_name(wszFullPath, wszShortName, wszLongName, size);
		*(--pchEnd) = L'\\';
	}
	return rtn;
}



BOOLEAN convert_short_name_to_long(WCHAR *wszLongName, WCHAR *wszShortName, ULONG size)
{
	WCHAR			*szResult = NULL;
	WCHAR			*pchResult = NULL;
	WCHAR			*pchStart = wszShortName;
	INT				Offset = 0;

	szResult = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)* (MAXPATHLEN * 2 + 1),'L2S');
	if (szResult == NULL)
	{
		return FALSE;
	}

	RtlZeroMemory(szResult, sizeof(WCHAR)* (MAXPATHLEN * 2 + 1));
	pchResult = szResult;


	if (pchStart[0] && pchStart[1] == L':')
	{
		*pchResult++ = L'\\';
		*pchResult++ = L'?';
		*pchResult++ = L'?';
		*pchResult++ = L'\\';
		*pchResult++ = *pchStart++;
		*pchResult++ = *pchStart++;
		Offset = 4;
	}
	else if (_wcsnicmp(pchStart, L"\\DosDevices\\", 12) == 0)
	{
		StringCbCopyW(pchResult, sizeof(WCHAR)* (MAXPATHLEN * 2 + 1), L"\\??\\");
		
		pchResult += 4;
		pchStart += 12;
		while (*pchStart && !is_directory_sep(*pchStart))
			*pchResult++ = *pchStart++;
		Offset = 4;
	}
	else if (_wcsnicmp(pchStart, L"\\Device\\HardDiskVolume", 22) == 0)
	{
		StringCbCopyW(pchResult, sizeof(WCHAR)* (MAXPATHLEN * 2 + 1), L"\\Device\\HardDiskVolume");
		
		pchResult += 22;
		pchStart += 22;
		while (*pchStart && !is_directory_sep(*pchStart))
			*pchResult++ = *pchStart++;
	}
	else if (_wcsnicmp(pchStart, L"\\??\\", 4) == 0)
	{
		StringCbCopyW(pchResult, sizeof(WCHAR)* (MAXPATHLEN * 2 + 1), L"\\??\\");
		pchResult += 4;
		pchStart += 4;

		while (*pchStart && !is_directory_sep(*pchStart))
			*pchResult++ = *pchStart++;
	}
	else
	{
		ExFreePool(szResult);
		return FALSE;
	}

	while (is_directory_sep(*pchStart))
	{
		BOOLEAN			bShortName = FALSE;
		WCHAR			*pchEnd = NULL;
		WCHAR			*pchReplacePos = NULL;

		*pchResult++ = *pchStart++;

		pchEnd = pchStart;
		pchReplacePos = pchResult;

		while (*pchEnd && !is_directory_sep(*pchEnd))
		{
			if (*pchEnd == L'~')
			{
				bShortName = TRUE;
			}

			*pchResult++ = *pchEnd++;
		}

		*pchResult = L'\0';

		if (bShortName)
		{
			WCHAR  * szLong = NULL;

			szLong = ExAllocatePoolWithTag(PagedPool,
				sizeof(WCHAR)* MAXPATHLEN,
				'L2S');
			if (szLong)
			{
				RtlZeroMemory(szLong, sizeof(WCHAR)* MAXPATHLEN);

				if (query_long_name(szResult, szLong, sizeof(WCHAR)* MAXPATHLEN))
				{
					StringCbCopyW(pchReplacePos, sizeof(WCHAR)* (MAXPATHLEN * 2 + 1), szLong);
					pchResult = pchReplacePos + wcslen(pchReplacePos);
				}

				ExFreePool(szLong);
			}
		}

		pchStart = pchEnd;
	}

	wcsncpy(wszLongName, szResult + Offset, size / sizeof(WCHAR));
	ExFreePool(szResult);
	return TRUE;
}

BOOLEAN is_short_name_path(WCHAR * wszFileName)
{
	WCHAR *p = wszFileName;

	while (*p != L'\0')
	{
		if (*p == L'~')
		{
			return TRUE;
		}
		p++;
	}

	return FALSE;
}

wchar_t *my_wcsrstr(const wchar_t *str, const wchar_t *sub_str)
{
	const wchar_t	*p = NULL;
	const wchar_t	*q = NULL;
	wchar_t			*last = NULL;

	if (NULL == str || NULL == sub_str)
	{
		return NULL;
	}

	for (; *str; str++)
	{
		p = str, q = sub_str;
		while (*q && *p)
		{
			if (*q != *p)
			{
				break;
			}
			p++, q++;
		}
		if (*q == 0)
		{
			last = (wchar_t *)str;
			str = p - 1;
		}
	}
	return last;
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
	Status = ObOpenObjectByPointer(pEprocess, OBJ_KERNEL_HANDLE, NULL, 0, *PsProcessType, KernelMode,&hProcess);
	if (!NT_SUCCESS(Status))
	{
		PCHAR str = NULL;
		ANSI_STRING ansi = { 0 };
		UNICODE_STRING uni = { 0 };
		str = PsGetProcessImageFileName(pEprocess);
		if (str)
		{
			RtlInitAnsiString(&ansi, str);
			Status = RtlAnsiStringToUnicodeString(&uni, &ansi, TRUE);
			if (!NT_SUCCESS(Status))
			{
				ObDereferenceObject(pEprocess);
				return NULL;
			}
			else
			{
				StringCbCopyNW(pPath, MAXPATHLEN*sizeof(WCHAR), uni.Buffer, uni.Length);
				RtlFreeUnicodeString(&uni);
				ObDereferenceObject(pEprocess);
				return pPath;
			}
		}
		else
		{
			ObDereferenceObject(pEprocess);
			return NULL;
		}
	}
	Status = g_ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		NULL,
		0,
		&returnedLength);
	if (STATUS_INFO_LENGTH_MISMATCH != Status || returnedLength >= MAXPATHLEN*sizeof(WCHAR))
	{
		ObDereferenceObject(pEprocess);
		ZwClose(hProcess);
		return NULL;
	}
	
	Status = g_ZwQueryInformationProcess(hProcess,ProcessImageFileName,pPath,MAXPATHLEN*sizeof(WCHAR),&returnedLength);
	if (!NT_SUCCESS(Status))
	{
		ObDereferenceObject(pEprocess);
		ZwClose(hProcess);
		return NULL;
	}
	else
	{
		ULONG len = 0;
		imageName = (PUNICODE_STRING)pPath;
		len = imageName->Length;
		RtlMoveMemory(pPath, imageName->Buffer, imageName->Length);
		pPath[len/ sizeof(WCHAR)] = L'\0';
	}
	ObDereferenceObject(pEprocess);
	ZwClose(hProcess);
	return pPath;
}

VOID kernel_sleep(IN LONG lminiSeccond)
{
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= lminiSeccond;
	KeDelayExecutionThread(KernelMode, FALSE, &my_interval);
}
