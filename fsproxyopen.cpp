#ifndef _NONSERVICE_DEBUG_MODE
#define _NONSERVICE_DEBUG_MODE 0
#endif

#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#include <aclapi.h>
#include <strsafe.h>

#if _NONSERVICE_DEBUG_MODE
#include <stdio.h>
#endif

#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include "ntifsapi.h"
#include "common.h"

#define WSTR_SERVICENAME          L"FSProxyOpen"

#define CMDLINE_PIPENAME_SWITCH   L"-pipename:"
#define PIPENAMEPREFIX            L"\\\\.\\pipe\\"

PVOID _AllocMemory(SIZE_T cb) { return HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,cb); }
VOID  _FreeMemory(PVOID p) { HeapFree(GetProcessHeap(),0,p); }

VOID StartupService();
VOID ServiceStart (DWORD argc, LPTSTR *argv);
HANDLE CreateWorkerThread(PCWSTR);
#if _NONSERVICE_DEBUG_MODE
VOID MainProc(LPWSTR);
#endif

VOID StartupService()
{
    SERVICE_TABLE_ENTRY DispatchTable[] =
    {
        { TEXT("FsProxyOpen"), (LPSERVICE_MAIN_FUNCTION) ServiceStart },
        { NULL, NULL }
    };

    StartServiceCtrlDispatcher( DispatchTable );
}

SERVICE_STATUS          ServiceStatus;
SERVICE_STATUS_HANDLE   ServiceStatusHandle;
HANDLE                  hStopEvent;

#ifdef _DEBUG
void _cdecl DebugTrace(LPCWSTR lpszFormat, ...)
{
    va_list args;
    va_start(args, lpszFormat);

    SIZE_T cchBuffer = 32768;
    int nBuf;
    WCHAR *szBuffer = (WCHAR *)_AllocMemory( cchBuffer * sizeof(WCHAR) );
    if( szBuffer != NULL )
    {
        nBuf = _vsnwprintf_s(szBuffer, cchBuffer, cchBuffer-1, lpszFormat, args);
        if( nBuf != -1 )
        {
            OutputDebugStringW(szBuffer);
        }
        _FreeMemory( szBuffer );
    }

    va_end(args);
}
#define DBGTRACE  DebugTrace
#define DBGPRINT  DbgPrint
#else
#define DBGTRACE  __noop
#define DBGPRINT  __noop
#endif

//////////////////////////////////////////////////////////////////////////////

int APIENTRY wWinMain(HINSTANCE hInstance,
                      HINSTANCE hPrevInstance,
                      LPWSTR lpCmdLine,
                      int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);

    DBGTRACE(L"Start process\n");

    DBGTRACE(L"CmdLine=%s\n",lpCmdLine);

#if _NONSERVICE_DEBUG_MODE
    MainProc(lpCmdLine);
#else
    StartupService();
#endif

    DBGTRACE(L"Exit process\n");

    return 0;
}

//////////////////////////////////////////////////////////////////////////////

VOID WINAPI ServiceCtrlHandler (DWORD Opcode)
{
    DWORD status;

    switch(Opcode)
    {
        case SERVICE_CONTROL_PAUSE:
            ServiceStatus.dwCurrentState = SERVICE_PAUSED;
            break;
        case SERVICE_CONTROL_CONTINUE:
            ServiceStatus.dwCurrentState = SERVICE_RUNNING;
            break;
        case SERVICE_CONTROL_STOP:
            SetEvent(hStopEvent);
            return;
        case SERVICE_CONTROL_INTERROGATE:
            break;
        default:
            break;
    }

    //
    // Set current status.
    //
    if (!SetServiceStatus(ServiceStatusHandle,&ServiceStatus))
    {
        status = GetLastError();
    }
    return;
}

PWSTR AllocPipeName(PWSTR pszName)
{
    SIZE_T cch = wcslen(pszName) + (_countof(PIPENAMEPREFIX) - 1) + 1;
    PWSTR pszPipename;
    pszPipename = (PWSTR)_AllocMemory( cch * sizeof(WCHAR) );
    wcscpy_s(pszPipename,cch,PIPENAMEPREFIX);
    wcscat_s(pszPipename,cch,pszName);
    return pszPipename;
}

VOID ServiceStart(DWORD argc, LPTSTR *argv)
{
    DWORD status;
    PWSTR pszPipename = NULL;

    DBGTRACE(L"Enter StartService Handler.\n");

    DWORD i;
    for(i = 0; i < argc; i++)
    {
        DBGTRACE(L"%u : %s",i,argv[i]);

        if( wcsnicmp(argv[i],CMDLINE_PIPENAME_SWITCH,_countof(CMDLINE_PIPENAME_SWITCH)-1) == 0 && pszPipename == NULL )
        {
            // "-pipename:xyz"
            pszPipename = AllocPipeName(&argv[i][_countof(CMDLINE_PIPENAME_SWITCH)-1]);
        }
    }

    if( pszPipename == NULL )
    {
        //
        // set default pipename
        //
        pszPipename = AllocPipeName(FS_DEFAULTPIPENAME);
    }

    // register service handler
    ServiceStatusHandle = RegisterServiceCtrlHandler(
                            WSTR_SERVICENAME,
                            &ServiceCtrlHandler
                            );

    if( ServiceStatusHandle != (SERVICE_STATUS_HANDLE)NULL )
    {
        ServiceStatus.dwServiceType        = SERVICE_WIN32_OWN_PROCESS;
        ServiceStatus.dwCurrentState       = SERVICE_START_PENDING;
        ServiceStatus.dwControlsAccepted   = 0;
        ServiceStatus.dwWin32ExitCode      = 0;
        ServiceStatus.dwServiceSpecificExitCode = 0;
        ServiceStatus.dwCheckPoint         = 0;
        ServiceStatus.dwWaitHint           = 10000;
        SetServiceStatus(ServiceStatusHandle, &ServiceStatus);

        // prepare non-named manual reset event.
        hStopEvent = CreateEvent(NULL,TRUE,FALSE,NULL);

        //
        // Initialization complete - report running status.
        //
        ServiceStatus.dwCurrentState       = SERVICE_RUNNING;
        ServiceStatus.dwCheckPoint         = 0;
        ServiceStatus.dwWaitHint           = 0;
        ServiceStatus.dwWin32ExitCode      = 0;
        ServiceStatus.dwControlsAccepted   = SERVICE_ACCEPT_STOP|
                                             SERVICE_ACCEPT_PAUSE_CONTINUE|
                                             SERVICE_ACCEPT_PARAMCHANGE|
                                             SERVICE_ACCEPT_HARDWAREPROFILECHANGE|
                                             SERVICE_ACCEPT_POWEREVENT|
                                             SERVICE_ACCEPT_SESSIONCHANGE|
                                             SERVICE_ACCEPT_SHUTDOWN;
        SetServiceStatus(ServiceStatusHandle,&ServiceStatus);

        if( pszPipename != NULL )
        {
            DBGTRACE(L"Using pipename %s\n",pszPipename);

            HANDLE hThread;
            hThread = CreateWorkerThread(pszPipename);
            if( hThread != NULL )
            {
                WaitForSingleObject(hThread,INFINITE);
                GetExitCodeThread(hThread,&status);
                CloseHandle(hThread);
            }
            else
            {
                status = GetLastError();
            }

            _FreeMemory(pszPipename);
        }
        else
        {
            status = ERROR_INVALID_PARAMETER;
        }
    }

    ServiceStatus.dwCurrentState            = SERVICE_STOPPED;
    ServiceStatus.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwControlsAccepted        = 0;
    ServiceStatus.dwWin32ExitCode           = status;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint              = 0;
    ServiceStatus.dwWaitHint                = 0;
    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);

    DBGTRACE(L"Exit StartService Handler.\n");
}

//////////////////////////////////////////////////////////////////////////////

BOOL
CheckPrefix(
    PCWSTR pszPrefix,
    PCWSTR pszPath,
    BOOLEAN  CaseInSensitive
    )
{
    UNICODE_STRING usPrefix;
    UNICODE_STRING usPath;
    RtlInitUnicodeString(&usPrefix,pszPrefix);
    RtlInitUnicodeString(&usPath,pszPath);
    return (BOOL)RtlPrefixUnicodeString(&usPrefix, &usPath,CaseInSensitive);
}

#define WSTR_DEVICE   L"\\Device\\"
#define WSTR_GLOBAL   L"\\??\\"

BOOL
SplitRootPathWithPrefix(
    PCWSTR Path,
    PCWSTR Prefix,
    UNICODE_STRING *VolumeName,
    UNICODE_STRING *RootRelativePath
    )
{
    SIZE_T PathLength;
    SIZE_T PrefixLength;

    PathLength = wcslen(Path);
    PrefixLength = wcslen(Prefix);

    if( PathLength < PrefixLength )
        return FALSE;

    PCWSTR p = &Path[PrefixLength];
    while(*p != L'\\' && *p != L'\0')
        p++;

    if( *p == L'\\' )
        p++;

    RtlInitUnicodeString(RootRelativePath,p);

    VolumeName->Buffer = (PWSTR)Path;
    VolumeName->Length = (USHORT)((p - Path) * sizeof(WCHAR));
    VolumeName->MaximumLength = VolumeName->Length;

    return TRUE;
}

BOOL
SplitPath_U(
    PCWSTR FullPath,
    UNICODE_STRING *pusVolumeName,
    UNICODE_STRING *pusRelativePath
    )
{
    if( CheckPrefix(WSTR_DEVICE,FullPath,TRUE) )
    {
        // Valid path format:
        // "\Device\VolumeName\[directoryName]"
        //
        // e.g.
        // "\Device\HarddiskVolumeX\"
        //   pusVolumeName->Buffer   -> "\Device\HarddiskVolumeX\"
        //   pusRelativePath->Buffer -> NULL;
        //
        // "\Device\HarddiskVolumeX\foo\bar"
        //   pusVolumeName->Buffer   -> "\Device\HarddiskVolumeX\"
        //   pusRelativePath->Buffer -> "foo\bar"
        //
        // "\Device\HarddiskVolumeX"
        //   pusVolumeName->Buffer   -> "\Device\HarddiskVolumeX"
        //   pusRelativePath->Buffer -> NULL;
        //
        return SplitRootPathWithPrefix(FullPath,WSTR_DEVICE,pusVolumeName,pusRelativePath);
    }

    if( CheckPrefix(WSTR_GLOBAL,FullPath,TRUE) )
    {
        // Valid path format:
        // "\??\VolumeName\[directoryName]"
        //
        // e.g.
        // "\??\HarddiskVolumeX\foo\bar"
        //   pusVolumeName->Buffer   -> "\??\HarddiskVolumeX\"
        //   pusRelativePath->Buffer -> "foo\bar" 
        //
        // "\??\C:\foo\bar"
        //   pusVolumeName->Buffer   -> "\??\c:\"
        //   pusRelativePath->Buffer -> "foo\bar" 
        //
        // "\??\HarddiskVolume1"
        //   pusVolumeName->Buffer   -> "\??\HarddiskVolume1"
        //   pusRelativePath->Buffer -> null
        // "\??\C:"
        //   pusVolumeName->Buffer   -> "\??\c:"
        //   pusRelativePath->Buffer -> null
        //
        // "\??" -> invalid path
        //
        // "\??\unc\computername\sharename\[directoryName]"  is incorrect split
        //   pusVolumeName->Buffer   -> "\??\unc\"
        //   pusRelativePath->Buffer -> "computername\sharename\[directoryName]" 
        //
        return SplitRootPathWithPrefix(FullPath,WSTR_GLOBAL,pusVolumeName,pusRelativePath);
    }

    return FALSE;
}

NTSTATUS
OpenFile_U(
    PHANDLE phFile,
    HANDLE hRoot,
    UNICODE_STRING *pNtPathName,
    ULONG DesiredAccess,
    ULONG ShareAccess,
    ULONG OpenOptions
    )
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatus = {0};
    NTSTATUS Status;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    InitializeObjectAttributes(&ObjectAttributes,pNtPathName,0,hRoot,NULL);

    Status = NtOpenFile(&hFile,
                    DesiredAccess,
                    &ObjectAttributes,
                    &IoStatus,
                    ShareAccess,
                    OpenOptions);

    if( Status != STATUS_SUCCESS )
    {
        hFile = INVALID_HANDLE_VALUE;
    }

    *phFile = hFile;

    RtlSetLastWin32Error( RtlNtStatusToDosError(Status) );

    return Status;
}

NTSTATUS
CreateFile_U(
    PHANDLE phFile,
    HANDLE hRoot,
    UNICODE_STRING *pNtPathName,
    ULONG DesiredAccess,
    ULONG ShareAccess,
    ULONG CreateOptions,
    ULONG FileAttributes,
    ULONG CreateDisposition
    )
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatus = {0};
    NTSTATUS Status;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    InitializeObjectAttributes(&ObjectAttributes,pNtPathName,0,hRoot,NULL);

    Status = NtCreateFile(
                &hFile,
                DesiredAccess,
                &ObjectAttributes,
                &IoStatus,
                0,
                FileAttributes,
                ShareAccess,
                CreateDisposition,
                CreateOptions,
                0x0,
                0x0);

    if( Status != STATUS_SUCCESS )
    {
        hFile = INVALID_HANDLE_VALUE;
    }

    *phFile = hFile;

    RtlSetLastWin32Error( RtlNtStatusToDosError(Status) );

    return Status;
}

BOOL
EnablePrivilege(
    LONG lLuid,
    BOOL bEnable
    )
{
    HANDLE hToken;
    TOKEN_PRIVILEGES token;
    BOOL bResult = FALSE;
    LUID Luid;

    Luid = RtlConvertLongToLuid(lLuid);

    if (NtOpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES,
                          &hToken) == 0)
    {
        token.PrivilegeCount = 1;
        token.Privileges[0].Luid  = Luid;
        token.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

        if(NtAdjustPrivilegesToken(hToken,
                    FALSE,
                    &token,
                    sizeof(TOKEN_PRIVILEGES),
                    NULL,
                    NULL) == 0)
        {
            bResult = TRUE;
        }
        NtClose(hToken);
    }

    return bResult;
}

//////////////////////////////////////////////////////////////////////////////

typedef struct _WORKERTHREAD_PARAM
{
    HANDLE hPipe;
} WORKERTHREAD_PARAM;

DWORD DupHandle(ULONG ProcessId,HANDLE hFileHandle,HANDLE *phReturnHandle,ULONG *ErrorCode)
{
    HANDLE hTargetProcess = NULL;
    HANDLE hTargetHandle = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;
    NTSTATUS Status;

    //
    // Get target process handle
    //
    hTargetProcess = OpenProcess(PROCESS_DUP_HANDLE,FALSE,ProcessId);
    if( hTargetProcess == NULL )
    {
        *ErrorCode = FSPO_ERROR_REASON_PROCESS;
        return NULL;
    }

    //
    // Duplicate file handle
    //
    if( !DuplicateHandle(
            GetCurrentProcess(),hFileHandle,
            hTargetProcess,&hTargetHandle,
            0,FALSE,DUPLICATE_SAME_ACCESS) )
    {
        *ErrorCode = FSPO_ERROR_REASON_DUPLICATE_HANDLE;
        dwError = GetLastError();
    }

    *phReturnHandle = hTargetHandle;

    CloseHandle(hTargetProcess);

    return dwError;
}

DWORD OpenFile_DupHandle(FS_PIPE_MSG_OPENFILE *pOpen,HANDLE *phReturnHandle,ULONG *ErrorCode)
{
    HANDLE hHandle = INVALID_HANDLE_VALUE;
    HANDLE hRoot = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;
    NTSTATUS Status;

    //
    // Split the full path into volume root and relative path.
    //
    UNICODE_STRING usVolumeRoot;
    UNICODE_STRING usRelativePath;

    SplitPath_U(pOpen->Name,&usVolumeRoot,&usRelativePath);

    DBGTRACE(L"OpenFile\n");
    DBGTRACE(L"Volume:%wZ\n",&usVolumeRoot);
    DBGTRACE(L"Path  :%wZ\n",&usRelativePath);

    //
    // Open volume root directory
    //
    Status = OpenFile_U(&hRoot,NULL,&usVolumeRoot,FILE_GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,0);

    if( Status == STATUS_SUCCESS )
    {
        if( pOpen->DesiredAccess & ACCESS_SYSTEM_SECURITY )
            EnablePrivilege(SE_SECURITY_PRIVILEGE,TRUE);
        
        if( usRelativePath.Length != 0 )
        {
            //
            // Open Volume Relative Path
            //
            Status = OpenFile_U(&hHandle,hRoot,&usRelativePath,
                            pOpen->DesiredAccess,
                            pOpen->ShareAccess,
                            pOpen->OpenOptions);
        }
        else
        {
            //
            // Open Volume Device or Volume Root Directory
            //
            DBGTRACE(L"Volume/Root directory open mode\n");
            Status = OpenFile_U(&hHandle,NULL,&usVolumeRoot,
                            pOpen->DesiredAccess,
                            pOpen->ShareAccess,
                            pOpen->OpenOptions);
        }

        if( pOpen->DesiredAccess & ACCESS_SYSTEM_SECURITY )
            EnablePrivilege(SE_SECURITY_PRIVILEGE,FALSE);

        if( Status == STATUS_SUCCESS )
        {
            dwError = DupHandle((DWORD)pOpen->ProcessId,hHandle,phReturnHandle,ErrorCode);

            DBGTRACE(L"File Duplicate Handle Status   : 0x%08X\n",dwError);

            //
            // Handle to close is the original handle (hHandle) only.
            // *phReturnHandle opens in the other process, so don't close it here.
            //
            CloseHandle(hHandle);
        }
        else
        {
            DBGTRACE(L"File Open Status   : 0x%08X\n",Status);

            *ErrorCode = FSPO_ERROR_REASON_OPEN_ROOT_RELATIVE_PATH;
            dwError = RtlNtStatusToDosError( Status );
        }

        CloseHandle(hRoot);
    }
    else
    {
        DBGTRACE(L"*Volume Open Status : 0x%08X\n",Status);

        *ErrorCode = FSPO_ERROR_REASON_OPEN_VOLUME_ROOT;
        dwError = RtlNtStatusToDosError( Status );
    }

    DBGTRACE(L"\n");

    SetLastError(dwError);

    return dwError;
}

DWORD CreateFile_DupHandle(FS_PIPE_MSG_CREATEFILE *pCreate,HANDLE *phReturnHandle,ULONG *ErrorCode)
{
    HANDLE hHandle = INVALID_HANDLE_VALUE;
    HANDLE hRoot = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;
    NTSTATUS Status;

    //
    // Split the full path into volume root and relative path.
    //
    UNICODE_STRING usVolumeRoot;
    UNICODE_STRING usRelativePath;

    SplitPath_U(pCreate->Name,&usVolumeRoot,&usRelativePath);

    DBGTRACE(L"CreateFile\n");
    DBGTRACE(L"Volume:%wZ\n",&usVolumeRoot);
    DBGTRACE(L"Path  :%wZ\n",&usRelativePath);

    //
    // Open volume root directory
    //
    Status = OpenFile_U(&hRoot,NULL,&usVolumeRoot,FILE_GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,0);

    if( Status == STATUS_SUCCESS )
    {
        if( pCreate->DesiredAccess & ACCESS_SYSTEM_SECURITY )
            EnablePrivilege(SE_SECURITY_PRIVILEGE,TRUE);
        
        if( usRelativePath.Length != 0 )
        {
            //
            // Create Volume Relative Path
            //
            Status = CreateFile_U(&hHandle,hRoot,&usRelativePath,
                            pCreate->DesiredAccess,
                            pCreate->ShareAccess,
                            pCreate->CreateOptions,
                            pCreate->FileAttributes,
                            pCreate->CreateDisposition);
        }
        else
        {
            //
            // Create Volume Device of Volume Root Directory
            //
            DBGTRACE(L"Volume/Root directory create mode\n");
            Status = CreateFile_U(&hHandle,NULL,&usVolumeRoot,
                            pCreate->DesiredAccess,
                            pCreate->ShareAccess,
                            pCreate->CreateOptions,
                            pCreate->FileAttributes,
                            pCreate->CreateDisposition);
        }

        if( pCreate->DesiredAccess & ACCESS_SYSTEM_SECURITY )
            EnablePrivilege(SE_SECURITY_PRIVILEGE,FALSE);

        if( Status == STATUS_SUCCESS )
        {
            dwError = DupHandle((DWORD)pCreate->ProcessId,hHandle,phReturnHandle,ErrorCode);

            DBGTRACE(L"File Duplicate Handle Status   : 0x%08X\n",dwError);

            //
            // Handle to close is the original handle (hHandle) only.
            // *phReturnHandle opens in the other process, so don't close it here.
            //
            CloseHandle(hHandle);
        }
        else
        {
            DBGTRACE(L"File Create Status   : 0x%08X\n",Status);

            *ErrorCode = FSPO_ERROR_REASON_OPEN_ROOT_RELATIVE_PATH;
            dwError = RtlNtStatusToDosError( Status );
        }

        CloseHandle(hRoot);
    }
    else
    {
        DBGTRACE(L"*Volume Open Status : 0x%08X\n",Status);

        *ErrorCode = FSPO_ERROR_REASON_OPEN_VOLUME_ROOT;
        dwError = RtlNtStatusToDosError( Status );
    }

    DBGTRACE(L"\n");

    SetLastError(dwError);

    return dwError;
}

DWORD CALLBACK WorkerThread(PVOID pParam)
{
    WORKERTHREAD_PARAM *pThreadParam = (WORKERTHREAD_PARAM *)pParam;
    DWORD cbBytesRead;
    BOOL fSuccess;
    BOOL fConnected;
    OVERLAPPED o = {0};
    DWORD cb;
    DWORD cbMessage;
    FS_PIPE_MESSAGE *Message;
    DWORD dw;
    DWORD dwReturn = 0;
    HANDLE WaitHandles[2];
    HANDLE hPipe;

    DBGTRACE(L"Run worker thread.\n");

    __try
    {
        hPipe = pThreadParam->hPipe;

        for(;;)
        {
            fConnected = ConnectNamedPipe(hPipe,&o) ?
                         TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

            if( fConnected )
            {
                break;
            }

            WaitHandles[0] = hPipe;
            WaitHandles[1] = hStopEvent;

            dw = WaitForMultipleObjects(ARRAYSIZE(WaitHandles),WaitHandles,FALSE,INFINITE);

            if( dw == WAIT_OBJECT_0 )
            {
                cbMessage = FS_PIPE_MSGBUFSIZE;
                Message = (FS_PIPE_MESSAGE *)_AllocMemory( cbMessage );

                if( Message == NULL )
                {
                    break;
                }

                //
                // Read a request message
                //
                BOOL bLoop;
                do
                {
                    bLoop = FALSE;

                    fSuccess = ReadFile(hPipe,Message,cbMessage,&cbBytesRead,NULL);

                    if( !fSuccess )
                    {
                        DWORD dwError = GetLastError();

                        if( dwError == ERROR_MORE_DATA )
                        {
                            // Truncate trailing data.
                            SetLastError(ERROR_SUCCESS);
                            UCHAR *pDummy = (UCHAR*)_AllocMemory(4096);
                            if( pDummy == NULL )
                                __leave;
                            DWORD dw = 0;
                            while( ReadFile(hPipe,pDummy,4096,&cbBytesRead,NULL) )
                            {
                                if( GetLastError() == ERROR_SUCCESS || GetLastError() != ERROR_MORE_DATA )
                                    break;
                                if( (dw++) == 100 )
                                    __leave;
                            }
                            _FreeMemory(pDummy);
                            break;
                        }
                    }
                }
                while( bLoop );

                if( GetLastError() == ERROR_SUCCESS )
                {
                    ULONG ErrorStatus;
                    ULONG ErrorCode;

                    //
                    // Open and Duplicate Handle
                    //
                    if( Message->Type == FST_CREATEFILE )
                    {
                        ErrorStatus = CreateFile_DupHandle(
                                        &Message->CreateFile,
                                        &Message->CreateFile.Handle,
                                        &ErrorCode);
                    }
                    else // Message->Type == FST_OPENFILE
                    {
                        ErrorStatus = OpenFile_DupHandle(
                                        &Message->OpenFile,
                                        &Message->OpenFile.Handle,
                                        &ErrorCode);
                    }

                    Message->Result = ErrorStatus;
                    Message->ErrorCode = ErrorCode;

                    //
                    // Reply to client
                    //
                    WriteFile(hPipe,Message,cbMessage,&cb,NULL);
                }

                FlushFileBuffers(hPipe);
                DisconnectNamedPipe(hPipe);

                _FreeMemory(Message);
            }
            else
            {
                break;
            }
        }
    }
    __finally
    {
        CloseHandle(hPipe);

        delete pThreadParam;
    }

    return dwReturn;
}

DWORD SetAccessAllowUser(EXPLICIT_ACCESS **pea)
{
    PSID pSID=NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;

#define ACE_COUNT 8
    EXPLICIT_ACCESS *ea = (EXPLICIT_ACCESS *)_AllocMemory( sizeof(EXPLICIT_ACCESS) * ACE_COUNT );

    if( ea == NULL )
        return 0;

    DWORD dwCount = 0;

#if 0
    //
    // Create a well-known SID for the Everyone group.
    //
    if( AllocateAndInitializeSid(&SIDAuthWorld, 1,
                     SECURITY_WORLD_RID,
                     0, 0, 0, 0, 0, 0, 0,
                     &pSID) )
    {
        ea[dwCount].grfAccessPermissions = FILE_READ_DATA;
        ea[dwCount].grfAccessMode = SET_ACCESS;
        ea[dwCount].grfInheritance = NO_INHERITANCE;
        ea[dwCount].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[dwCount].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea[dwCount].Trustee.ptstrName  = (LPTSTR) pSID;
        dwCount++;
    }
#endif

#if 0
    //
    // Create a SID for the BUILTIN\Administrators group.
    //
    if( AllocateAndInitializeSid(&SIDAuthNT, 2,
                     SECURITY_BUILTIN_DOMAIN_RID,
                     DOMAIN_ALIAS_RID_ADMINS,
                     0, 0, 0, 0, 0, 0,
                     &pSID) )
    {
        ea[dwCount].grfAccessPermissions = FILE_ALL_ACCESS;
        ea[dwCount].grfAccessMode = SET_ACCESS;
        ea[dwCount].grfInheritance = NO_INHERITANCE;
        ea[dwCount].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[dwCount].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        ea[dwCount].Trustee.ptstrName  = (LPTSTR) pSID;
        dwCount++;
    }
#endif

#if 0
    //
    // Create a SID for the BUILTIN\Users group.
    //
    if( AllocateAndInitializeSid(&SIDAuthNT, 2,
                     SECURITY_BUILTIN_DOMAIN_RID,
                     DOMAIN_ALIAS_RID_USERS,
                     0, 0, 0, 0, 0, 0,
                     &pSID) )
    {
        ea[dwCount].grfAccessPermissions = FILE_ALL_ACCESS;
        ea[dwCount].grfAccessMode = SET_ACCESS;
        ea[dwCount].grfInheritance = NO_INHERITANCE;
        ea[dwCount].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[dwCount].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        ea[dwCount].Trustee.ptstrName  = (LPTSTR) pSID;
        dwCount++;
    }
#endif

#if 1
    //
    // Create a SID: S-1-5-2 network
    //
    if( AllocateAndInitializeSid(&SIDAuthNT, 1,
                     SECURITY_NETWORK_RID,
                     0, 0, 0, 0, 0, 0, 0,
                     &pSID) )
    {
        ea[dwCount].grfAccessPermissions = FILE_ALL_ACCESS;
        ea[dwCount].grfAccessMode = DENY_ACCESS;
        ea[dwCount].grfInheritance = NO_INHERITANCE;
        ea[dwCount].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[dwCount].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        ea[dwCount].Trustee.ptstrName  = (LPTSTR) pSID;
        dwCount++;
    }
#endif

#if 1
    //
    // Create a SID: S-1-5-11 authenticated users
    //
    if( AllocateAndInitializeSid(&SIDAuthNT, 1,
                     SECURITY_AUTHENTICATED_USER_RID,
                     0, 0, 0, 0, 0, 0, 0,
                     &pSID) )
    {
        ea[dwCount].grfAccessPermissions = FILE_ALL_ACCESS;
        ea[dwCount].grfAccessMode = SET_ACCESS;
        ea[dwCount].grfInheritance = NO_INHERITANCE;
        ea[dwCount].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[dwCount].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        ea[dwCount].Trustee.ptstrName  = (LPTSTR) pSID;
        dwCount++;
    }
#endif

    *pea = ea;

    return dwCount;
}

PSECURITY_DESCRIPTOR AllocateSD()
{
    PSECURITY_DESCRIPTOR pSD = NULL;

    pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,SECURITY_DESCRIPTOR_MIN_LENGTH);
    if( NULL != pSD )
    {
        if( InitializeSecurityDescriptor(pSD,SECURITY_DESCRIPTOR_REVISION) )
        {
            return pSD;
        }
    }
    return NULL;
}

HANDLE CreateSecurityDescriptor(PCWSTR pszPipename)
{
    HANDLE hPipe;
    DWORD dwRes;
    PACL pACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS *pea = NULL;
    DWORD dwCount = 0;

    __try
    {
        // Create ACE list.
        dwCount = SetAccessAllowUser(&pea);

        // Create a new ACL that contains the new ACEs.
        dwRes = SetEntriesInAcl(dwCount, pea, NULL, &pACL);
        if( ERROR_SUCCESS != dwRes )
        {
            __leave;
        }

        // Initialize a security descriptor.
        pSD = AllocateSD();
        if( pSD == NULL )
        {
            __leave;
        }

        // Add the ACL to the security descriptor.
        if( !SetSecurityDescriptorDacl(pSD,
                TRUE,      // bDaclPresent flag
                pACL,
                FALSE) )   // not a default DACL
        {
            __leave;
        }

        // Create named pipe
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = FALSE;
        sa.lpSecurityDescriptor = pSD;

        hPipe = CreateNamedPipe(
                    pszPipename,
                    PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED,
                    PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES,
                    FS_PIPE_MSGBUFSIZE,
                    FS_PIPE_MSGBUFSIZE,
                    NMPWAIT_USE_DEFAULT_WAIT,
                    &sa);
    }
    __finally
    {
        for(DWORD i = 0; i < dwCount; i++)
            FreeSid(pea[i].Trustee.ptstrName);

        if(pea)
            _FreeMemory(pea);

        if(pACL)
            LocalFree(pACL);

        if(pSD)
            LocalFree(pSD);
    }

    return hPipe;
}

HANDLE CreateWorkerThread(PCWSTR pszPipename)
{
    HANDLE hPipe;
    hPipe = CreateSecurityDescriptor(pszPipename);

    if ( hPipe == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }

    WORKERTHREAD_PARAM *param = new WORKERTHREAD_PARAM;

    DWORD ThreadId;
    HANDLE hThread;

    param->hPipe = hPipe;

    hThread = CreateThread(NULL,0,WorkerThread,param,0,&ThreadId);

    return hThread;
}

#if _NONSERVICE_DEBUG_MODE
VOID MainProc(LPWSTR lpCmdLine)
{
    DBGTRACE( L"Start non-service mode.\n" );

    PWSTR pszEventName = NULL;
    if( lpCmdLine && *lpCmdLine != L'\0' )
        pszEventName = lpCmdLine;

    hStopEvent = CreateEvent(NULL,TRUE,FALSE,pszEventName);

    if( pszEventName && GetLastError() == ERROR_ALREADY_EXISTS )
    {
        SetEvent(hStopEvent);
        return ;
    }

    PWSTR pszPipename = AllocPipeName(FS_DEFAULTPIPENAME);

    HANDLE hThread;
    hThread = CreateWorkerThread(pszPipename);

    WaitForSingleObject(hThread,INFINITE);

    DWORD status;
    GetExitCodeThread(hThread,&status);

    CloseHandle(hThread);

    _FreeMemory(pszPipename);

    DBGTRACE( L"Worker thread exit code = %u.\n",status);

    return ;
}
#endif
