#ifndef SHIM_WINDOWS_H
#define SHIM_WINDOWS_H

#include <stdint.h>
#include <stddef.h>

typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef unsigned int        DWORD;
typedef int                 BOOL;
typedef BOOL                *LPBOOL;
typedef int                 INT;
typedef unsigned int        UINT;
typedef long                LONG;
typedef unsigned long       ULONG;
typedef unsigned long long  DWORD64;
typedef unsigned long long  ULONG64;
typedef long long           LONGLONG;
typedef char                CHAR;
typedef wchar_t             WCHAR;
typedef char                TCHAR;
typedef void                *LPVOID;
typedef const void          *LPCVOID;
typedef void                *PVOID;
typedef char                *LPSTR;
typedef const char          *LPCSTR;
typedef WCHAR               *LPWSTR;
typedef const WCHAR         *LPCWSTR;
typedef DWORD               *LPDWORD;
typedef BYTE                *LPBYTE;
typedef void                *HANDLE;
typedef void                *HMODULE;
typedef void                *HINSTANCE;
typedef void                *FARPROC_;
typedef FARPROC_            FARPROC;
typedef void                *HKEY;
typedef void                *SC_HANDLE;
typedef void                *HGLOBAL;
typedef void                *HRSRC;
typedef void                *HCURSOR;
typedef unsigned long long  ULONG_PTR;
typedef long long           LONG_PTR;
typedef unsigned long       SIZE_T_;
typedef SIZE_T_             SIZE_T;
typedef long                NTSTATUS;
typedef ULONG               *PULONG;
typedef ULONG               *PVOID_;
typedef union {
    struct { DWORD LowPart; LONG HighPart; } u;
    LONGLONG QuadPart;
} LARGE_INTEGER;

#define MAX_PATH            260
#define TRUE                1
#define FALSE               0
#define INVALID_HANDLE_VALUE       ((HANDLE)-1)
#define INVALID_FILE_ATTRIBUTES    0xFFFFFFFFu
#define STILL_ACTIVE               259
#define INFINITE                   0xFFFFFFFFu
#define WAIT_TIMEOUT               0x00000102
#define WAIT_OBJECT_0              0

#define MEM_COMMIT                 0x1000
#define MEM_RESERVE                0x2000
#define MEM_RELEASE                0x8000
#define PAGE_NOACCESS              0x01
#define PAGE_READONLY              0x02
#define PAGE_READWRITE             0x04
#define PAGE_WRITECOPY             0x08
#define PAGE_EXECUTE               0x10
#define PAGE_EXECUTE_READ          0x20
#define PAGE_EXECUTE_READWRITE     0x40
#define PAGE_EXECUTE_WRITECOPY     0x80

#define GENERIC_READ               0x80000000
#define GENERIC_WRITE              0x40000000
#define CREATE_NEW                 1
#define CREATE_ALWAYS              2
#define OPEN_EXISTING              3
#define OPEN_ALWAYS                4
#define FILE_ATTRIBUTE_NORMAL      0x80
#define FILE_ATTRIBUTE_DIRECTORY   0x10
#define FILE_SHARE_READ            1
#define FILE_SHARE_WRITE           2
#define FILE_BEGIN                 0
#define FILE_CURRENT               1
#define FILE_END                   2

#define TH32CS_SNAPPROCESS         2
#define TH32CS_SNAPMODULE          8
#define TH32CS_SNAPTHREAD          4
#define NTAPI
#define WINAPI
#define CALLBACK

#define PROCESS_TERMINATE          1
#define PROCESS_CREATE_THREAD      2
#define PROCESS_VM_OPERATION       8
#define PROCESS_VM_READ            16
#define PROCESS_VM_WRITE           32
#define PROCESS_QUERY_INFORMATION  1024
#define PROCESS_SUSPEND_RESUME     0x0800
#define THREAD_SUSPEND_RESUME      2
#define THREAD_GET_CONTEXT         8
#define THREAD_SET_CONTEXT         16

#define IMAGE_DOS_SIGNATURE        0x5A4D
#define IMAGE_NT_SIGNATURE         0x00004550
#define IMAGE_FILE_MACHINE_I386    0x014c
#define IMAGE_FILE_MACHINE_AMD64   0x8664

typedef struct _STARTUPINFOA {
    DWORD  cb;
    LPSTR  lpReserved;
    LPSTR  lpDesktop;
    LPSTR  lpTitle;
    DWORD  dwX, dwY, dwXSize, dwYSize;
    DWORD  dwFlags;
    WORD   wShowWindow;
} STARTUPINFOA;

typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD  dwProcessId;
    DWORD  dwThreadId;
} PROCESS_INFORMATION;

typedef struct _SECURITY_ATTRIBUTES {
    DWORD  nLength;
    LPVOID lpSecurityDescriptor;
    BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES;

typedef struct _WIN32_FIND_DATAA {
    DWORD    dwFileAttributes;
    DWORD    nFileSizeHigh;
    DWORD    nFileSizeLow;
    CHAR     cFileName[MAX_PATH];
} WIN32_FIND_DATAA;

typedef struct _PROCESSENTRY32 {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ProcessID;
    DWORD th32ParentProcessID;
    DWORD cntThreads;
    DWORD th32ParentProcessID_;
    LONG  pcPriClassBase;
    CHAR  szExeFile[MAX_PATH];
} PROCESSENTRY32;

typedef struct _MODULEENTRY32 {
    DWORD dwSize;
    DWORD th32ModuleID;
    DWORD th32ProcessID;
    BYTE  *modBaseAddr;
    DWORD modBaseSize;
    HMODULE hModule;
    CHAR  szModule[256];
    CHAR  szExePath[MAX_PATH];
} MODULEENTRY32;

typedef struct _THREADENTRY32 {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ThreadID;
    DWORD th32OwnerProcessID;
    LONG  tpBasePri;
} THREADENTRY32;

typedef struct _SERVICE_STATUS {
    DWORD dwServiceType;
    DWORD dwCurrentState;
    DWORD dwControlsAccepted;
    DWORD dwWin32ExitCode;
    DWORD dwServiceSpecificExitCode;
    DWORD dwCheckPoint;
    DWORD dwWaitHint;
} SERVICE_STATUS;

typedef struct _SERVICE_STATUS_PROCESS {
    DWORD dwServiceType;
    DWORD dwCurrentState;
    DWORD dwControlsAccepted;
    DWORD dwWin32ExitCode;
    DWORD dwWaitHint;
    DWORD dwProcessId;
    DWORD dwServiceFlags;
} SERVICE_STATUS_PROCESS;

#define SERVICE_STOP               0x00000001
#define SERVICE_QUERY_STATUS       0x00000004
#define SERVICE_ALL_ACCESS         0x000F01FF
#define SERVICE_DEMAND_START       0x00000003
#define SERVICE_ERROR_IGNORE       0x00000000
#define SC_MANAGER_ALL_ACCESS      0x000F003F
#define SC_MANAGER_CONNECT         0x00000001
#define SC_STATUS_PROCESS_INFO     0
#define KEY_SET_VALUE              0x0002
#define KEY_WRITE                  0x20006
#define TOKEN_ADJUST_PRIVILEGES    0x0020
#define TOKEN_QUERY                0x0008
#define TOKEN_PRIVILEGES_          20

typedef struct _TOKEN_PRIVILEGES {
    DWORD PrivilegeCount;
    struct { DWORD LowPart; LONG HighPart; DWORD Attr; } Privileges[1];
} TOKEN_PRIVILEGES;

typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME;

typedef struct _CRITICAL_SECTION { void *ptr; } CRITICAL_SECTION;

#define TH32CS_SNAPMODULE32          16
#define CP_ACP                       0

typedef struct _MODULEENTRY32W {
    DWORD dwSize;
    DWORD th32ProcessID;
    BYTE  *modBaseAddr;
    DWORD modBaseSize;
    HMODULE hModule;
    WCHAR szModule[256];
    WCHAR szExePath[MAX_PATH];
} MODULEENTRY32W;

int MultiByteToWideChar(unsigned codepage, DWORD flags, LPCSTR src, int srclen,
                        LPWSTR dst, int dstlen);
int WideCharToMultiByte(unsigned codepage, DWORD flags, LPCWSTR src, int srclen,
                        LPSTR dst, int dstlen, LPCSTR defchr, LPBOOL defchr_used);
DWORD GetLastError(void);
HMODULE GetModuleHandleA(LPCSTR name);
void Sleep(DWORD ms);
DWORD GetProcessId(HANDLE process);
HANDLE CreateToolhelp32Snapshot(DWORD flags, DWORD pid);
BOOL Module32FirstW(HANDLE snap, MODULEENTRY32W *me);
BOOL Module32NextW(HANDLE snap, MODULEENTRY32W *me);

int _stricmp_null_safe(const char *a, const char *b);

DWORD GetFileAttributesA(LPCSTR lpFileName);
BOOL SetFileAttributesA(LPCSTR lpFileName, DWORD dwFileAttributes);
DWORD GetTickCount(void);
unsigned long long GetTickCount64(void);
#endif
