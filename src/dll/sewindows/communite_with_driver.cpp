#include "stdafx.h"
#include "scm_drv_ctrl.h"
#include "communite_with_driver.h"
#include "rule_struct.h"
#pragma comment(lib,"fltLib.lib")

CCommunicateDriv::CCommunicateDriv(void)
{
	m_pScmDrvCtrl = NULL;
	ZeroMemory(m_errStr,sizeof(m_errStr));
	m_funcNotify = NULL;
	ZeroMemory(&m_threads,sizeof(m_threads));
	ZeroMemory(&m_msg,sizeof(m_msg));
	m_port = NULL;
	m_completion = NULL;
	ZeroMemory(&m_pMagPoint,sizeof(m_pMagPoint));
	m_iMsgCount = 0;
}


CCommunicateDriv::~CCommunicateDriv(void)
{
	for (int i = 0; i < REQUEST_COUNT*THREAD_COUNT; i++)
	{
		if (m_pMagPoint[i])
		{
			free(m_pMagPoint[i]);
			m_pMagPoint[i] = NULL;
		}
	}
	CloseComplete();
}

VOID CCommunicateDriv::CloseComplete()
{
	if (m_port)
	{
		CloseHandle(m_port);
		m_port = NULL;
	}
	if (m_completion)
	{
		CloseHandle(m_completion);
		m_completion = NULL;
	}
}

VOID CCommunicateDriv::SetNotify(NotifyProc notify)
{
	m_funcNotify = notify;
}

BOOLEAN CCommunicateDriv::OnExitProcess(TCHAR* lpsz_service_name)
{
	if (!m_pScmDrvCtrl->IoControl(IOCTL_STOP_ALL, NULL, 0, NULL, 0, NULL))
	{
		for (int i = 0; i < THREAD_COUNT; i++)
		{
			TerminateThread(m_threads[i],0);
		}
	}
	if (WaitForMultipleObjectsEx(THREAD_COUNT, m_threads, TRUE, 5000, FALSE) == WAIT_TIMEOUT)
	{
		for (int i = 0; i < THREAD_COUNT; i++)
		{
			TerminateThread(m_threads[i], 0);
		}
	}
	for (int i = 0; i < THREAD_COUNT; i++)
	{
		if (m_threads[i])
		{
			CloseHandle(m_threads[i]);
			m_threads[i] = NULL;
		}
	}
	return UninsDriver(lpsz_service_name);
}
BOOLEAN CCommunicateDriv::UninsDriver(TCHAR* lpsz_service_name)
{
	if (m_pScmDrvCtrl == NULL)
	{
		return TRUE;
	}
	m_pScmDrvCtrl->UnInstall(lpsz_service_name);
	if (m_pScmDrvCtrl)
	{
		delete m_pScmDrvCtrl;
		m_pScmDrvCtrl = NULL;
	}
	
	return TRUE;
}
BOOLEAN CCommunicateDriv::InitDriver(TCHAR* lpsz_service_name, TCHAR* lpsz_path, TCHAR* lpsz_altitude, TCHAR* lpsz_portname, TCHAR* lpszLink_name)
{
	m_pScmDrvCtrl = new ScmDrvCtrl();

	if (!m_pScmDrvCtrl)
	{
		_tcscpy_s(m_errStr,_tcslen( _T("初始化ScmDrvCtrl类失败"))+1, _T("初始化ScmDrvCtrl类失败"));
		return FALSE;
	}


	if (!m_pScmDrvCtrl->Install(lpsz_service_name, lpsz_path, lpsz_altitude, lpszLink_name))
	{
	
		_tcscpy_s(m_errStr, _tcslen(_T("驱动安装失败")) + 1, _T("驱动安装失败"));
		return FALSE;
		
	}
	if (!m_pScmDrvCtrl->Start(lpsz_service_name))
	{
		_tcscpy_s(m_errStr,_tcslen( _T("驱动启动失败"))+1, _T("驱动启动失败"));
		return FALSE;
	}

	 HRESULT hr;
	 hr = FilterConnectCommunicationPort(lpsz_portname,
                                         0,
                                         NULL,
                                         0,
                                         NULL,
										 &m_port );
	if (IS_ERROR( hr )) 
	{       
		_tcscpy_s(m_errStr,_tcslen( _T("连接完成端口失败"))+1, _T("连接完成端口失败"));
		return FALSE;
	}

	 m_completion = CreateIoCompletionPort( m_port,
											NULL,
											0,
											THREAD_COUNT);
	 if (m_completion == NULL) {

        _tcscpy_s(m_errStr,_tcslen( _T("创建完成端口失败"))+1, _T("创建完成端口失败"));
        CloseHandle( m_port );
		m_port = NULL;
		return FALSE;
    }
	if (!StartToWork())
	{
		_tcscpy_s(m_errStr,_tcslen( _T("工作线程启动失败"))+1, _T("工作线程启动失败"));
        CloseHandle( m_port );
		CloseHandle(m_completion);
		m_port = NULL;
		m_completion = NULL;
		return FALSE;
	}
	return TRUE; 
}

BOOLEAN  CCommunicateDriv::StartToWork()
{
	DWORD threadId;
    HRESULT hr;
	PSCANNER_MESSAGE msg;
	int i;
	for (i = 0; i < THREAD_COUNT; i++) 
	{

        m_threads[i] = CreateThread( NULL,
                                   0,
                                   (LPTHREAD_START_ROUTINE) MonitorProc,
								   this,
                                   0,
                                   &threadId );

        if (m_threads[i] == NULL) 
		{
            hr = GetLastError();
            goto main_cleanup;
        }

        for (int j = 0; j < REQUEST_COUNT; j++)
		{
			msg = (SCANNER_MESSAGE*)malloc( sizeof( SCANNER_MESSAGE ) );

            if (msg == NULL) 
			{
                goto main_cleanup;
            }
			m_pMagPoint[m_iMsgCount++] = msg;
            memset( &msg->Ovlp, 0, sizeof( OVERLAPPED ) );
            hr = FilterGetMessage( m_port,
                                   &msg->MessageHeader,
                                   FIELD_OFFSET( SCANNER_MESSAGE, Ovlp ),
                                   &msg->Ovlp );

            if (hr != HRESULT_FROM_WIN32( ERROR_IO_PENDING )) 
			{
              
                goto main_cleanup;
            }
		}
           
    }
main_cleanup:
	for (int i = 0; i < THREAD_COUNT; i++)
	{
		if (m_threads[i])
		{
			return TRUE;
		}
	}
	return FALSE;
}


DWORD  CCommunicateDriv::MonitorProc(LPVOID param)
{
	PUSER_DATA				notification;
    SCANNER_REPLY_MESSAGE	replyMessage;
	PSCANNER_MESSAGE		message = NULL;
    LPOVERLAPPED			pOvlp;
    BOOL					result;
    DWORD					outSize;
    HRESULT					hr;
    ULONG_PTR				key;
	BOOLEAN					bIsPermitted = FALSE;
	Param					pdata;
	CCommunicateDriv* pThis = (CCommunicateDriv*)param;
    while (TRUE)
	{
		ZeroMemory(&pdata,sizeof(Param));
		result = GetQueuedCompletionStatus( pThis->m_completion, &outSize, &key, &pOvlp, INFINITE );
        message = CONTAINING_RECORD( pOvlp, SCANNER_MESSAGE, Ovlp );
        if (!result)
		{
            hr = HRESULT_FROM_WIN32( GetLastError() );
            break;
        }
        notification = &message->Notification;
		memcpy_s(&pdata.opdata, sizeof(USER_DATA), notification, sizeof(USER_DATA));
		bIsPermitted = pThis->m_funcNotify(pdata);

		if (pdata.opdata.option == OPTION_TO_JUGE/* ||pdata.opdata.option == OPTION_PROC_CREATE */)
		{
			replyMessage.ReplyHeader.Status = 0;
			replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;
			replyMessage.Reply.IsPermitted = bIsPermitted;

			ULONG replyLength = sizeof(FILTER_REPLY_HEADER)+sizeof(SCANNER_REPLY);
			hr = FilterReplyMessage(pThis->m_port,
				(PFILTER_REPLY_HEADER)&replyMessage,
				replyLength);

			if (!SUCCEEDED(hr))
			{
				break;
			}
		}

        memset( &message->Ovlp, 0, sizeof( OVERLAPPED ) );

		hr = FilterGetMessage( pThis->m_port,
                               &message->MessageHeader,
                               FIELD_OFFSET( SCANNER_MESSAGE, Ovlp ),
                               &message->Ovlp );

        if (hr != HRESULT_FROM_WIN32( ERROR_IO_PENDING )) 
		{
            break;
        }
    }
	return 0;
}

BOOLEAN CCommunicateDriv::StartProcMon(BOOLEAN Start)
{
	if (Start)
	{
		return m_pScmDrvCtrl->IoControl(IOCTL_START_PROCMONITOR, NULL, 0, NULL, 0, NULL);
	}
	else
	{
		return m_pScmDrvCtrl->IoControl( IOCTL_PAUSE_PROCMONITOR, NULL, 0, NULL, 0, NULL);
	}
}
BOOLEAN CCommunicateDriv::StartRegMon(BOOLEAN Start)
{
	if (Start)
	{
		return m_pScmDrvCtrl->IoControl(IOCTL_START_REGMONITOR, NULL, 0, NULL, 0, NULL);
	}
	else
	{
		return m_pScmDrvCtrl->IoControl( IOCTL_PAUSE_REGMONITOR, NULL, 0, NULL, 0, NULL);
	}
}

BOOLEAN CCommunicateDriv::StopUnload()
{
	return m_pScmDrvCtrl->IoControl(IOCTL_STOP_UNLOAD, NULL, 0, NULL, 0, NULL);
}

BOOLEAN CCommunicateDriv::PermitUnload()
{
	return m_pScmDrvCtrl->IoControl(IOCTL_PERMIT_UNLOAD, NULL, 0, NULL, 0, NULL);
}


BOOLEAN CCommunicateDriv::StartFileMon(BOOLEAN Start)
{
	if (Start)
	{
		return m_pScmDrvCtrl->IoControl( IOCTL_START_FILEMONITOR, NULL, 0, NULL, 0, NULL);
	}
	else
	{
		return m_pScmDrvCtrl->IoControl( IOCTL_PAUSE_FILEMONITOR, NULL, 0, NULL, 0, NULL);
	}
}

BOOLEAN CCommunicateDriv::SetMode(BOOLEAN bIsNotityMode)
{
	if (bIsNotityMode)
	{
		return m_pScmDrvCtrl->IoControl(IOCTL_SET_NOTIFY_MODE, NULL, 0, NULL, 0, NULL);
	}
	else
	{
		return m_pScmDrvCtrl->IoControl(IOCTL_SET_INTERCEPT_MODE, NULL, 0, NULL, 0, NULL);
	}
}