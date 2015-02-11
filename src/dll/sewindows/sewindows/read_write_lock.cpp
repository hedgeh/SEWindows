#include "read_write_lock.h"

#define LOCK_IS_OWNED				0x1
#define LOCK_WRITE_WAKING			0x2

#define LOCK_READ_OWNERS_SHIFT		2
#define LOCK_READ_OWNERS_MASK		0x3ff
#define LOCK_READ_OWNERS_INC		0x4

#define LOCK_READ_WAITERS_SHIFT		12
#define LOCK_READ_WAITERS_MASK		0x3ff
#define LOCK_READ_WAITERS_INC		0x1000

#define LOCK_WRITE_WAITERS_SHIFT	22
#define LOCK_WRITE_WAITERS_MASK		0x3ff
#define LOCK_WRITE_WAITERS_INC		0x400000

#define LOCK_WRITE_MASK (LOCK_WRITE_WAKING | (LOCK_WRITE_WAITERS_MASK << LOCK_WRITE_WAITERS_SHIFT))

static ULONG g_lock_spin_count = 0;

VOID init_rwlock(_Out_ PREAD_WRITE_LOCK prwlock)
{
	SYSTEM_INFO si;
	RtlZeroMemory(&si, sizeof(SYSTEM_INFO));
	GetSystemInfo(&si);
	if (si.dwNumberOfProcessors > 1)
	{
		g_lock_spin_count = 5000;
	}
	prwlock->lock_value = 0;
	prwlock->write_event = NULL;
	prwlock->read_event = NULL;
}

VOID uninit_rwlock(_Inout_ PREAD_WRITE_LOCK prwlock)
{
	if (prwlock->write_event)
	{
		CloseHandle(prwlock->write_event);
		prwlock->write_event = NULL;
	}

	if (prwlock->read_event)
	{
		CloseHandle(prwlock->read_event);
		prwlock->read_event = NULL;
	}
}

VOID create_handle(_Inout_ PHANDLE Handle)
{
	HANDLE handle;

	if (*Handle != NULL)
	{
		return;
	}

	handle = CreateSemaphore(NULL,  0, MAXLONG,NULL);

	if (_InterlockedCompareExchangePointer(Handle,handle,NULL) != NULL)
	{
		CloseHandle(handle);
	}
}

VOID FASTCALL lock_write( _Inout_ PREAD_WRITE_LOCK prwlock)
{
	DWORD value;
	ULONG i = 0;

	while (TRUE)
	{
		value = prwlock->lock_value;

		if (!(value & (LOCK_IS_OWNED | LOCK_WRITE_WAKING)))
		{
			if (_InterlockedCompareExchange(&prwlock->lock_value, value + LOCK_IS_OWNED, value) == value)
			{
				break;
			}
		}
		else if (i >= g_lock_spin_count)
		{
			create_handle(&prwlock->write_event);

			if (_InterlockedCompareExchange(&prwlock->lock_value,value + LOCK_WRITE_WAITERS_INC,value) == value)
			{
				WaitForSingleObject(prwlock->write_event, INFINITE);

				do
				{
					value = prwlock->lock_value;
				} while (_InterlockedCompareExchange(&prwlock->lock_value,value + LOCK_IS_OWNED - LOCK_WRITE_WAKING,value) != value);

				break;
			}
		}

		i++;
		YieldProcessor();
	}
}

VOID FASTCALL lock_read(_Inout_ PREAD_WRITE_LOCK prwlock)
{
	ULONG value;
	ULONG i = 0;

	while (TRUE)
	{
		value = prwlock->lock_value;

		if (!(value & (LOCK_IS_OWNED | (LOCK_READ_OWNERS_MASK << LOCK_READ_OWNERS_SHIFT) | LOCK_WRITE_MASK)))
		{
			if (_InterlockedCompareExchange(&prwlock->lock_value, value + LOCK_IS_OWNED + LOCK_READ_OWNERS_INC, value) == value)
			{
				break;
			}
		}
		else if ((value & LOCK_IS_OWNED) && ((value >> LOCK_READ_OWNERS_SHIFT) & LOCK_READ_OWNERS_MASK) > 0 &&!(value & LOCK_WRITE_MASK))
		{
			if (_InterlockedCompareExchange(&prwlock->lock_value, value + LOCK_READ_OWNERS_INC, value) == value)
			{
				break;
			}
		}
		else if (i >= g_lock_spin_count)
		{
			create_handle(&prwlock->read_event);

			if (_InterlockedCompareExchange(&prwlock->lock_value,value + LOCK_READ_WAITERS_INC,value) == value)
			{
				WaitForSingleObject(prwlock->read_event, INFINITE);
				continue;
			}
		}

		i++;
		YieldProcessor();
	}
}

VOID FASTCALL unlock_write(
	_Inout_ PREAD_WRITE_LOCK prwlock
	)
{
	ULONG value;

	while (TRUE)
	{
		value = prwlock->lock_value;

		if ((value >> LOCK_WRITE_WAITERS_SHIFT) & LOCK_WRITE_WAITERS_MASK)
		{
			if (_InterlockedCompareExchange(&prwlock->lock_value,value - LOCK_IS_OWNED + LOCK_WRITE_WAKING - LOCK_WRITE_WAITERS_INC,value) == value)
			{
				ReleaseSemaphore(prwlock->write_event, 1, NULL);

				break;
			}
		}
		else
		{
			ULONG read_waiters;

			read_waiters = (value >> LOCK_READ_WAITERS_SHIFT) & LOCK_READ_WAITERS_MASK;

			if (_InterlockedCompareExchange(&prwlock->lock_value,value & ~(LOCK_IS_OWNED | (LOCK_READ_WAITERS_MASK << LOCK_READ_WAITERS_SHIFT)),value) == value)
			{
				if (read_waiters)
				{
					ReleaseSemaphore(prwlock->read_event, read_waiters, 0);
				}

				break;
			}
		}

		YieldProcessor();
	}
}

VOID FASTCALL unlock_read(
	_Inout_ PREAD_WRITE_LOCK prwlock
	)
{
	ULONG value;

	while (TRUE)
	{
		value = prwlock->lock_value;

		if (((value >> LOCK_READ_OWNERS_SHIFT) & LOCK_READ_OWNERS_MASK) > 1)
		{
			if (_InterlockedCompareExchange(&prwlock->lock_value, value - LOCK_READ_OWNERS_INC, value) == value)
			{
				break;
			}
		}
		else if ((value >> LOCK_WRITE_WAITERS_SHIFT) & LOCK_WRITE_WAITERS_MASK)
		{
			if (_InterlockedCompareExchange(&prwlock->lock_value,value - LOCK_IS_OWNED + LOCK_WRITE_WAKING -LOCK_READ_OWNERS_INC - LOCK_WRITE_WAITERS_INC,value) == value)
			{
				ReleaseSemaphore(prwlock->write_event, 1, NULL);
				break;
			}
		}
		else
		{
			if (_InterlockedCompareExchange(&prwlock->lock_value, value - LOCK_IS_OWNED - LOCK_READ_OWNERS_INC, value) == value)
			{
				break;
			}
		}

		YieldProcessor();
	}
}

BOOLEAN FASTCALL try_lock_write(
	_Inout_ PREAD_WRITE_LOCK prwlock
	)
{
	ULONG value;

	value = prwlock->lock_value;

	if (value & (LOCK_IS_OWNED | LOCK_WRITE_WAKING))
	{
		return FALSE;
	}
		
	return _InterlockedCompareExchange(&prwlock->lock_value,value + LOCK_IS_OWNED,value) == value;
}

BOOLEAN FASTCALL try_lock_read(
	_Inout_ PREAD_WRITE_LOCK prwlock
	)
{
	ULONG value;

	value = prwlock->lock_value;

	if (value & LOCK_WRITE_MASK)
	{
		return FALSE;
	}

	if (!(value & LOCK_IS_OWNED))
	{
		return _InterlockedCompareExchange(&prwlock->lock_value,value + LOCK_IS_OWNED + LOCK_READ_OWNERS_INC,value) == value;
	}
	else if ((value >> LOCK_READ_OWNERS_SHIFT) & LOCK_READ_OWNERS_MASK)
	{
		return _InterlockedCompareExchange(&prwlock->lock_value,value + LOCK_READ_OWNERS_INC,value) == value;
	}
	else
	{
		return FALSE;
	}
}
