#pragma once

#define WCHAR_LENGTH(u) ((u) / sizeof(WCHAR))
#define WCHAR_BYTES(w) ((w) * sizeof(WCHAR))
#define WCHAR_CHARS(u) WCHAR_LENGTH(u)

#ifndef UNICODE_STRING_MAX_CHARS
#define UNICODE_STRING_MAX_CHARS (32767) 
#endif

#ifndef UNICODE_STRING_MAX_BYTES
#define UNICODE_STRING_MAX_BYTES ((USHORT)65534) 
#endif

#define _NT_MAX_NAME_LENGTH                    (260)
#define _NT_MAX_PATH_LENGTH                    UNICODE_STRING_MAX_CHARS
#define _NT_MAX_ALTERNATE_STREAM_NAME_LENGTH   (_NT_MAX_NAME_LENGTH+8)  // ex) ":nnn...n:$DATA"
#define _NT_MAX_VOLUME_LENGTH                  (48)   // ex) "\??\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}"

#define _NT_PATH_FULL_LENGTH (_NT_MAX_VOLUME_LENGTH \
                             +_NT_MAX_PATH_LENGTH \
                             +_NT_MAX_ALTERNATE_STREAM_NAME_LENGTH)

#define _NT_PATH_FULL_LENGTH_BYTES (_NT_PATH_FULL_LENGTH * sizeof(WCHAR))

EXTERN_C
VOID
NTAPI
RtlSetLastWin32Error(
    ULONG ErrorCode
    );

EXTERN_C
BOOLEAN 
NTAPI
RtlPrefixUnicodeString( 
    IN PUNICODE_STRING  String1, 
    IN PUNICODE_STRING  String2, 
    IN BOOLEAN  CaseInSensitive 
    );

EXTERN_C
ULONG
__cdecl
DbgPrint(
	PCHAR,
	...);

EXTERN_C
NTSTATUS
NTAPI
NtOpenProcessToken(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    OUT PHANDLE TokenHandle
    );

EXTERN_C
NTSTATUS
NTAPI
NtAdjustPrivilegesToken(
	HANDLE TokenHandle,
	BOOLEAN DisableAllPrivileges,
	PTOKEN_PRIVILEGES NewState,
	ULONG BufferLength,
	PTOKEN_PRIVILEGES PreviousState,
	PULONG ReturnLength
	);

FORCEINLINE
LUID
NTAPI_INLINE
RtlConvertLongToLuid(
    __in LONG Long
    )
{
    LUID TempLuid;
    LARGE_INTEGER TempLi;

    TempLi.QuadPart = Long;
    TempLuid.LowPart = TempLi.u.LowPart;
    TempLuid.HighPart = TempLi.u.HighPart;
    return(TempLuid);
}

#define SE_SECURITY_PRIVILEGE             (8L)
