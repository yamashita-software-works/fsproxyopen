#pragma once

#pragma pack(1)

typedef struct _FS_PIPE_MSG_OPENFILE 
{
	ULONG64 ProcessId;
	union {
		HANDLE Handle;
		ULONG64 Handle64; // for 32-bit support
	};
	ULONG DesiredAccess;
	ULONG ShareAccess;
	ULONG OpenOptions;
	ULONG FileAttributes;
	ULONG NameLength;
	WCHAR Name[1];
} FS_PIPE_MSG_OPENFILE;

typedef struct _FS_PIPE_MSG_CREATEFILE
{
	ULONG64 ProcessId;
	union {
		HANDLE Handle;
		ULONG64 Handle64; // for 32-bit support
	};
	ULONG DesiredAccess;
	ULONG ShareAccess;
	ULONG CreateOptions;
	ULONG FileAttributes;
	ULONG CreateDisposition;
	ULONG NameLength;
	WCHAR Name[1];
} FS_PIPE_MSG_CREATEFILE;

typedef struct _FS_PIPE_MESSAGE
{
	union {
		struct {
			ULONG Type;
			ULONG Length;
			ULONG Result;
			ULONG ErrorCode;
		};
		ULONG Header[16]; // Header size : 64byte
	};
	union
	{
		FS_PIPE_MSG_OPENFILE OpenFile;
		FS_PIPE_MSG_CREATEFILE CreateFile;
	};
} FS_PIPE_MESSAGE;

#pragma pack()

#define FST_OPENFILE         0x0
#define FST_CREATEFILE       0x1

#define FSPO_ERROR_REASON_PROCESS                 0x00000001
#define FSPO_ERROR_REASON_DUPLICATE_HANDLE        0x00000002
#define FSPO_ERROR_REASON_OPEN_VOLUME_ROOT        0x00000004
#define FSPO_ERROR_REASON_OPEN_ROOT_RELATIVE_PATH 0x00000008

#define FS_PIPENAMEPATH      L"\\\\.\\pipe\\fileproxyopen"
#define FS_DEFAULTPIPENAME   L"fileproxyopen"
#define FS_PIPE_MSGBUFSIZE   (sizeof(FS_PIPE_MESSAGE) + _NT_PATH_FULL_LENGTH_BYTES)
