/*
 *     _____               _____                                     
 *  __|__   |__ __    _ __|__   |__  ______  ______   ____   __   _  
 * |     |     |\ \  //|     \     ||      >|   ___| /   /_ |  | | | 
 * |    _|     | \ \// |      \    ||     < |   |  ||   _  ||  |_| | 
 * |___|     __| /__/  |______/  __||______>|______||______|'----__| 
 *     |_____|             |_____|                                    
 *
 * PyDBG64 - OS X PyDbg with 64 bits support
 * 
 * Original OS X port by Charlie Miller
 * Fixes and 64 bits support by fG!, reverser@put.as - http://reverse.put.as
 *
 * windows.h
 *
 */
#define MEM_COMMIT                     0x00001000
#define MEM_DECOMMIT                   0x00004000
#define MEM_IMAGE                      0x01000000
#define MEM_RELEASE                    0x00008000

#define PAGE_NOACCESS                  0x00000001
#define PAGE_READONLY                  0x00000002
#define PAGE_READWRITE                 0x00000004
#define PAGE_WRITECOPY                 0x00000008
#define PAGE_EXECUTE                   0x00000010
#define PAGE_EXECUTE_READ              0x00000020
#define PAGE_EXECUTE_READWRITE         0x00000040
#define PAGE_EXECUTE_WRITECOPY         0x00000080
#define PAGE_GUARD                     0x00000100
#define PAGE_NOCACHE                   0x00000200
#define PAGE_WRITECOMBINE              0x00000400


#define BOOL short
#define WORD short
#define DWORD long
#define LPVOID void *
#define LPDWORD int *
#define PDWORD int *
#define DWORD_PTR long *
#define LPSYSTEM_INFO SYSTEM_INFO *
#define HMODULE int
#define LPCSTR char *
#define LPCTSTR char *
#define HANDLE int
#define FARPROC int
#if __LP64__
#define PVOID unsigned long
#else
#define PVOID unsigned int
#endif
#define ULONG_PTR unsigned long *
#define LPCVOID void *
#define SIZE_T size_t
#define UINT unsigned int
#define BYTE char
#define TCHAR char
#define LPMODULEENTRY32 MODULEENTRY32 *
#define LPPROCESSENTRY32 PROCESSENTRY32 *
#define LONG long
#define LPTHREADENTRY32 THREADENTRY32 *
#define LPCONTEXT CONTEXT *
#define LPTSTR char *
#define LPSECURITY_ATTRIBUTES void *
#define LPBYTE char *
#define PHANDLE int

#define MAX_PATH 260
#define EXCEPTION_MAXIMUM_PARAMETERS 15
#define MAX_MODULE_NAME32 255
#define ANYSIZE_ARRAY 1

#define EXCEPTION_DEBUG_EVENT 1


typedef struct _SYSTEM_INFO {
    union {
        DWORD dwOemId;
        struct {
            WORD wProcessorArchitecture;
            WORD wReserved;
        };
    };
    DWORD dwPageSize;
    LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD wProcessorLevel;
    WORD wProcessorRevision;
} SYSTEM_INFO;

typedef struct _EXCEPTION_RECORD {
  DWORD ExceptionCode;
  DWORD ExceptionFlags;
  struct _EXCEPTION_RECORD* ExceptionRecord;
  // fixme : pvoid is unsigned int
  PVOID ExceptionAddress;
  DWORD NumberParameters;
  ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, 
 *PEXCEPTION_RECORD;

typedef struct _EXCEPTION_DEBUG_INFO {
  EXCEPTION_RECORD ExceptionRecord;
  DWORD dwFirstChance;
} EXCEPTION_DEBUG_INFO, 
 *LPEXCEPTION_DEBUG_INFO;

typedef struct _DEBUG_EVENT {
  DWORD dwDebugEventCode;
  DWORD dwProcessId;
  DWORD dwThreadId;

  union {
    EXCEPTION_DEBUG_INFO Exception;
  } u;
} DEBUG_EVENT, 
 *LPDEBUG_EVENT;

typedef struct tagMODULEENTRY32 {
  DWORD dwSize;
  DWORD th32ModuleID;
  DWORD th32ProcessID;
  DWORD GlblcntUsage;
  DWORD ProccntUsage;
  BYTE* modBaseAddr;
  DWORD modBaseSize;
  HMODULE hModule;
  TCHAR szModule[MAX_MODULE_NAME32 + 1];
  TCHAR szExePath[MAX_PATH];
} MODULEENTRY32, 
 *PMODULEENTRY32;

typedef struct tagPROCESSENTRY32 {
  DWORD dwSize;
  DWORD cntUsage;
  DWORD th32ProcessID;
  ULONG_PTR th32DefaultHeapID;
  DWORD th32ModuleID;
  DWORD cntThreads;
  DWORD th32ParentProcessID;
  LONG pcPriClassBase;
  DWORD dwFlags;
  TCHAR szExeFile[MAX_PATH];
} PROCESSENTRY32, 
 *PPROCESSENTRY32;

typedef struct tagTHREADENTRY32 {
  DWORD dwSize;
  DWORD cntUsage;
  DWORD th32ThreadID;
  DWORD th32OwnerProcessID;
  LONG tpBasePri;
  LONG tpDeltaPri;
  DWORD dwFlags;
} THREADENTRY32, 
 *PTHREADENTRY32;

#define MAXIMUM_SUPPORTED_EXTENSION     512
#define SIZE_OF_80387_REGISTERS      80

typedef struct _FLOATING_SAVE_AREA {
    DWORD   ControlWord;
    DWORD   StatusWord;
    DWORD   TagWord;
    DWORD   ErrorOffset;
    DWORD   ErrorSelector;
    DWORD   DataOffset;
    DWORD   DataSelector;
    BYTE    RegisterArea[SIZE_OF_80387_REGISTERS];
    DWORD   Cr0NpxState;
} FLOATING_SAVE_AREA;

// FIXME - split into two structures to save space? or who cares, ram is cheap!
typedef struct _CONTEXT {
    DWORD ContextFlags;
    DWORD   Dr0;
    DWORD   Dr1;
    DWORD   Dr2;
    DWORD   Dr3;
    DWORD   Dr6;
    DWORD   Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD   SegGs;
    DWORD   SegFs;
    DWORD   SegEs;
    DWORD   SegDs;
    DWORD   Edi;
    DWORD   Esi;
    DWORD   Ebx;
    DWORD   Edx;
    DWORD   Ecx;
    DWORD   Eax;
    DWORD   Ebp;
    DWORD   Eip;
    DWORD   SegCs;            
	DWORD   EFlags;            
    DWORD   Esp;
    DWORD   SegSs;
    DWORD   Rip;
    DWORD   Rax;
    DWORD   Rbx;
    DWORD   Rcx;
    DWORD   Rdx;
	DWORD   Rdi;
    DWORD   Rsi;
    DWORD   Rbp;
    DWORD   Rsp;
	DWORD   RFlags;            	
	DWORD	R8;
	DWORD	R9;
	DWORD	R10;
	DWORD	R11;
	DWORD	R12;
	DWORD	R13;
	DWORD	R14;
	DWORD	R15;
    // remaining arm
    DWORD   R0;
    DWORD   R1;
    DWORD   R2;
    DWORD   R3;
    DWORD   R4;
    DWORD   R5;
    DWORD   R6;
    DWORD   R7;
    DWORD   SP;
    DWORD   LR;
    DWORD   PC;
    DWORD   CPSR;
    BYTE    ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
} CONTEXT;

typedef struct _STARTUPINFO {
  DWORD cb;
  LPTSTR lpReserved;
  LPTSTR lpDesktop;
  LPTSTR lpTitle;
  DWORD dwX;
  DWORD dwY;
  DWORD dwXSize;
  DWORD dwYSize;
  DWORD dwXCountChars;
  DWORD dwYCountChars;
  DWORD dwFillAttribute;
  DWORD dwFlags;
  WORD wShowWindow;
  WORD cbReserved2;
  LPBYTE lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
} STARTUPINFO, 
 *LPSTARTUPINFO;

typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess;
  HANDLE hThread;
  DWORD dwProcessId;
  DWORD dwThreadId;
} PROCESS_INFORMATION, 
 *LPPROCESS_INFORMATION;

typedef struct _MEMORY_BASIC_INFORMATION {
  PVOID BaseAddress;
  PVOID AllocationBase;
  DWORD AllocationProtect;
  SIZE_T RegionSize;
  DWORD State;
  DWORD Protect;
  DWORD Type;
} MEMORY_BASIC_INFORMATION, 
 *PMEMORY_BASIC_INFORMATION;

typedef struct _LUID {
	DWORD LowPart;
	LONG HighPart;
} LUID,
 *PLUID;
 
 typedef struct _LUID_AND_ATTRIBUTES {
  LUID Luid;
  DWORD Attributes;
} LUID_AND_ATTRIBUTES, 
 *PLUID_AND_ATTRIBUTES;

 typedef struct _TOKEN_PRIVILEGES {
  DWORD PrivilegeCount;
  LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
} TOKEN_PRIVILEGES, 
 *PTOKEN_PRIVILEGES;

typedef struct _Tone{
	BYTE BaseMid;
	BYTE Flags1;
	BYTE Flags2;
	BYTE BaseHi;
} Tone;

typedef struct _Ttwo{
	DWORD BaseMid;
	DWORD Type;
	DWORD Dpl;
	DWORD Pres;
	DWORD LimitHi;
	DWORD Sys;
	DWORD Reserved_0;
	DWORD Default_big;
	DWORD Granularity;
	DWORD BaseHi;
} Ttwo;

typedef struct _BLAH{
	Tone Bytes;
	Ttwo Bits;
} BLAH; 

typedef struct _LDT_ENTRY { 
	WORD LimmitLow;
	WORD BaseLow;
	BLAH HighWord;
} LDT_ENTRY,
  *LPLDT_ENTRY;
