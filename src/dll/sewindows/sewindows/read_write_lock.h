#ifndef _READ_WRITE_LOCK_H
#define _READ_WRITE_LOCK_H
#include <Windows.h>
#include <intrin.h>
#ifdef _M_IX86
#define FASTCALL __fastcall
#else
#define FASTCALL
#endif


typedef struct _READ_WRITE_LOCK
{
	DWORD	lock_value;
	HANDLE	write_event;
	HANDLE	read_event;
} READ_WRITE_LOCK, *PREAD_WRITE_LOCK;

VOID	init_rwlock(_Out_ PREAD_WRITE_LOCK prwlock);
VOID	uninit_rwlock(_Inout_ PREAD_WRITE_LOCK prwlock);
VOID	FASTCALL lock_write(_Inout_ PREAD_WRITE_LOCK prwlock);
VOID	FASTCALL lock_read(_Inout_ PREAD_WRITE_LOCK prwlock);
VOID	FASTCALL unlock_write(_Inout_ PREAD_WRITE_LOCK prwlock);
VOID	FASTCALL unlock_read(_Inout_ PREAD_WRITE_LOCK prwlock);
BOOLEAN FASTCALL try_lock_write(_Inout_ PREAD_WRITE_LOCK prwlock);
BOOLEAN FASTCALL try_lock_read(_Inout_ PREAD_WRITE_LOCK prwlock);

#endif
