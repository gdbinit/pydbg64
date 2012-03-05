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
 * macdll.c
 *
 */

#include "MacDll.h"
//#include "dyld.h"
//#include "implementation.h"
//#include "Exception.h"

#define EXPORT __attribute__((visibility("default")))
#define DEBUG 1

// Globals
static mach_port_t exception_port;
static int current_pid;
static BOOL kill_on_exit;
static struct kinfo_proc *kinfo;
static int kinfo_max;
static int kinfo_cur;
static thread_act_port_array_t thread_list;
static mach_msg_type_number_t thread_max;
static int thread_cur;
static long allocated_fs_base;
static pid_t target_pid;

//Initializer.
__attribute__((constructor))
static void initializer(void) 
{
	kinfo = 0;
	allocated_fs_base = 0;
	//printf("[%s] initializer for me()\n", __FILE__);
}
      
// Finalizer.
__attribute__((destructor))
static void finalizer(void) 
{
	//printf("[%s] finalizer()\n", __FILE__);
}
          
EXPORT
void GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)
{
	host_name_port_t myhost;
	host_basic_info_data_t hinfo;
	vm_size_t page_size;
	mach_msg_type_number_t count;
	
	myhost = mach_host_self();
	count = HOST_BASIC_INFO_COUNT;
	host_info(myhost, HOST_BASIC_INFO, (host_info_t) &hinfo, &count);
	host_page_size(myhost, &page_size);
	
	lpSystemInfo->dwPageSize = page_size;
	lpSystemInfo->dwNumberOfProcessors = hinfo.avail_cpus;
	return;
}

EXPORT
BOOL CloseHandle(HANDLE hObject)
{
#pragma unused(hObject)
    
	if(kinfo){
		free(kinfo);
		kinfo = 0;
	}
	
	// memory leak on thread stuff?
	return 1;
}

// fG - 10/03/2011
// CLEANME
EXPORT
BOOL StartProcess(DWORD dwProcessId)
{
//	int error = 0;
//	printf("[DEBUG] Calling PT_CONTINUE %d!\n",(int)dwProcessId);
////	error = ptrace(PT_CONTINUE, dwProcessId, (char *) 1, 0);
//    kill(target_pid, SIGCONT);
//	if errno printf("Errno: %s\n", strerror(errno));		
//	fflush(stdout);
//	return(error);
//    
    task_t targetTask;
    mach_port_t me = mach_task_self();
	thread_act_port_array_t thread_list;
	mach_msg_type_number_t thread_count,i;
	kern_return_t kr;
	task_for_pid(me, target_pid, &targetTask);
	kr = task_threads(targetTask, &thread_list, &thread_count);
	if (thread_count > 0)
	{
		i = thread_count;
		printf("[INFO] Available threads:\n");
		while (i--)
		{
			printf("[%d] %d\n", i, thread_list[i]);
            resume_thread(thread_list[i]);
		}
	}
	return(0);

}

/*
 * success != 0
 * failure = 0
 */
EXPORT
BOOL DebugActiveProcess(DWORD dwProcessId)
{
#if DEBUG
    printf("[DEBUG] Initializing debug port\n");
#endif
	kill_on_exit = 0;
	current_pid  = dwProcessId;

	/* stuff that needs to be set each time you attach to a process */
	kinfo = 0;
	allocated_fs_base = 0;
	return attach(dwProcessId, &exception_port);
}

EXPORT
BOOL WaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds)
{
	int ret, ec, id;
	unsigned long eat, eref;
	ret = my_msg_server(exception_port, dwMilliseconds, &id, &ec, &eat, &eref);
	
	lpDebugEvent->dwThreadId = id;
	lpDebugEvent->dwDebugEventCode = EXCEPTION_DEBUG_EVENT; // FIXME for other events???
	lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode = ec;
	lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress = eat;
	lpDebugEvent->u.Exception.ExceptionRecord.ExceptionInformation[0] = 0; // just a guess
	lpDebugEvent->u.Exception.ExceptionRecord.ExceptionInformation[1] = (ULONG_PTR) eref;
	lpDebugEvent->dwProcessId = 0; // shouldn't need...
//	printf("Exception Address in WaitForDebugEvent %p\n", (void *)lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);
	return ret;
}

EXPORT
BOOL ContinueDebugEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus)
{
#pragma unused(dwProcessId)
#pragma unused(dwContinueStatus)

    // FIXME? why the state code? not being used...
//#if __LP64__
//	x86_thread_state64_t state;
//#else
//	i386_thread_state_t state;
//#endif
//	
//	get_context(dwThreadId, &state);	
	return resume_thread(dwThreadId);
}

EXPORT
BOOL DebugSetProcessKillOnExit(BOOL KillOnExit)
{
	kill_on_exit = KillOnExit;
	return 1;
}

EXPORT
BOOL DebugActiveProcessStop(DWORD dwProcessId)
{
	int ret = detach(dwProcessId, &exception_port);
	if(kill_on_exit){
		TerminateProcess(dwProcessId, 0);
	}
    return ret;
}

EXPORT
BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode)
{
#pragma unused(uExitCode)
    
	int sts = kill(hProcess, 9);
//	printf("Just did kill on %d", hProcess);
	sts++;
	return sts;
}

EXPORT
HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
{
#pragma unused(dwFlags)
    
//	fprintf(stderr, "CreateToolhelp32Snapshot %lx %ld\n", dwFlags, th32ProcessID);
	int ctl[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
	size_t size = 0;
	
/* Collect process info */
	sysctl(ctl, 4, NULL,  &size, NULL, 0); //Figure out the size we'll need
	kinfo = calloc(1, size);
	sysctl(ctl, 4, kinfo, &size, NULL, 0); //Acutally go get it.
	kinfo_max = size / sizeof(struct kinfo_proc);
	kinfo_cur = 0;
		
/* Collect Thread info */
	get_task_threads(th32ProcessID, &thread_list, &thread_max);
	thread_cur = 0;

	return 1;
}

EXPORT
BOOL Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte)
{
#pragma unused(hSnapshot)
        
	if(thread_cur < thread_max)
	{
		lpte->th32ThreadID = thread_list[thread_cur];
		lpte->th32OwnerProcessID = current_pid;
//		printf("th32ThreadID: %d th32OwnerProcessID: %d\n", lpte->th32ThreadID, lpte->th32OwnerProcessID);
		thread_cur++;
		return 1;
	} else {
		return 0;
	}
}

EXPORT
BOOL Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte)
{
#pragma unused(hSnapshot)
    
	if(thread_cur < thread_max)
	{
		lpte->th32ThreadID = thread_list[thread_cur];
		lpte->th32OwnerProcessID = current_pid;
		thread_cur++;
		return 1;
	} else {
		return 0;
	}
}

EXPORT
BOOL Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
{
#pragma unused(hSnapshot)
// FIXME - p_comm is restricted to 16 chars so we could improve this
	if(kinfo_cur < kinfo_max)
	{
		lppe->th32ProcessID = kinfo[kinfo_cur].kp_proc.p_pid;
		strncpy(lppe->szExeFile, kinfo[kinfo_cur].kp_proc.p_comm, MAX_PATH-1);  // memory leak?
		lppe->szExeFile[MAX_PATH-1] = 0;
		kinfo_cur++;
		return 1;
	} else {
		return 0;
	}
}

EXPORT
BOOL Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
{
#pragma unused(hSnapshot)
    
	if(kinfo_cur < kinfo_max)
	{
		lppe->th32ProcessID = kinfo[kinfo_cur].kp_proc.p_pid;
		strncpy(lppe->szExeFile, kinfo[kinfo_cur].kp_proc.p_comm, MAX_PATH-1);  // memory leak?
		lppe->szExeFile[MAX_PATH-1] = 0;
		kinfo_cur++;
		return 1;
	} else {
		return 0;
	}
}

EXPORT
BOOL GetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
{
	mach_msg_type_number_t sc;
#if __LP64__
//	printf("64bits GetThreadContext on thread %d\n", hThread);
	x86_thread_state64_t state;
	sc = x86_THREAD_STATE64_COUNT;
	thread_get_state( hThread, x86_THREAD_STATE64, (thread_state_t) &state, &sc);
//	printf("GetThreadContext RIP: %p\n", (void *)state.__rip);
	lpContext->Rax = state.__rax;
	lpContext->Rbx = state.__rbx;
	lpContext->Rcx = state.__rcx;
	lpContext->Rdx = state.__rdx;
	lpContext->Rdi = state.__rdi;
	lpContext->Rsi = state.__rsi;
	lpContext->Rbp = state.__rbp;
	lpContext->Rsp = state.__rsp;
	lpContext->RFlags = state.__rflags;
	lpContext->Rip = state.__rip;
	lpContext->SegCs = state.__cs;
	lpContext->SegFs = state.__fs;
	lpContext->SegGs = state.__gs;
	lpContext->R8 = state.__r8;
	lpContext->R9 = state.__r9;
	lpContext->R10 = state.__r10;
	lpContext->R11 = state.__r11;
	lpContext->R12 = state.__r12;
	lpContext->R13 = state.__r13;
	lpContext->R14 = state.__r14;
	lpContext->R15 = state.__r15;

	x86_debug_state64_t debug;
	sc = x86_DEBUG_STATE64_COUNT;
	thread_get_state( hThread, x86_DEBUG_STATE64, (thread_state_t) &debug, &sc);
	lpContext->Dr0 = debug.__dr0;
	lpContext->Dr1 = debug.__dr1;
	lpContext->Dr2 = debug.__dr2;
	lpContext->Dr3 = debug.__dr3;
	lpContext->Dr6 = debug.__dr6;
	lpContext->Dr7 = debug.__dr7;
	
#else
	i386_thread_state_t state;
	sc = i386_THREAD_STATE_COUNT;
	thread_get_state( hThread, i386_THREAD_STATE, (thread_state_t) &state, &sc);
	lpContext->Eax = state.eax;
	lpContext->Ebx = state.ebx;
	lpContext->Ecx = state.ecx;
	lpContext->Edx = state.edx;
	lpContext->Edi = state.edi;
	lpContext->Esi = state.esi;
	lpContext->Ebp = state.ebp;
	lpContext->Esp = state.esp;
	lpContext->SegSs = state.ss;
	lpContext->EFlags = state.eflags;
	lpContext->Eip = state.eip;
	lpContext->SegCs = state.cs;
	lpContext->SegDs = state.ds;
	lpContext->SegEs = state.es;
	lpContext->SegFs = state.fs;
	lpContext->SegGs = state.gs;
	
	x86_debug_state32_t debug;
	sc = x86_DEBUG_STATE32_COUNT;
	thread_get_state( hThread, x86_DEBUG_STATE32, (thread_state_t) &debug, &sc);
	lpContext->Dr0 = debug.dr0;
	lpContext->Dr1 = debug.dr1;
	lpContext->Dr2 = debug.dr2;
	lpContext->Dr3 = debug.dr3;
	lpContext->Dr6 = debug.dr6;
	lpContext->Dr7 = debug.dr7;
#endif
	return 1;
}

EXPORT
BOOL SetThreadContext(HANDLE hThread, const CONTEXT* lpContext)
{
	mach_msg_type_number_t sc;
	kern_return_t result;

#if __LP64__
	x86_thread_state64_t state;
    state.__rax = lpContext->Rax;
	state.__rbx = lpContext->Rbx;
	state.__rcx = lpContext->Rcx;
	state.__rdx = lpContext->Rdx;
	state.__rdi = lpContext->Rdi;
	state.__rsi = lpContext->Rsi;
	state.__rbp = lpContext->Rbp;
	state.__rsp = lpContext->Rsp;
	state.__rflags = lpContext->RFlags;
	state.__rip = lpContext->Rip;
	state.__cs = lpContext->SegCs;
	state.__fs = lpContext->SegFs;
	state.__gs = lpContext->SegGs;
	state.__r8 = lpContext->R8;
	state.__r9 = lpContext->R9;
	state.__r10 = lpContext->R10;
	state.__r11 = lpContext->R11;
	state.__r12 = lpContext->R12;
	state.__r13 = lpContext->R13;
	state.__r14 = lpContext->R14;
	state.__r15 = lpContext->R15;
	sc = x86_THREAD_STATE64_COUNT;
	result = thread_set_state( hThread, x86_THREAD_STATE64, (thread_state_t) &state, sc);
	if (result != KERN_SUCCESS)
    {
		printf("64bits thread set state failed!\n");
		return 0;
	}
	
	x86_debug_state64_t debug;
	debug.__dr0 = lpContext->Dr0;
	debug.__dr1 = lpContext->Dr1;
	debug.__dr2 = lpContext->Dr2;
	debug.__dr3 = lpContext->Dr3;
	debug.__dr6 = lpContext->Dr6;
	debug.__dr7 = lpContext->Dr7;
	sc = x86_DEBUG_STATE64_COUNT;
	result = thread_set_state( hThread, x86_DEBUG_STATE64, (thread_state_t) &debug, sc);
	if (result != KERN_SUCCESS)
    {
		printf("64 bits thread set state debug failed!\n");
		return 0;
	}
	
#else
	i386_thread_state_t state;
	state.eax = lpContext->Eax;
	state.ebx = lpContext->Ebx;
	state.ecx = lpContext->Ecx;
	state.edx = lpContext->Edx;
	state.edi = lpContext->Edi;
	state.esi = lpContext->Esi;
	state.ebp = lpContext->Ebp;
	state.esp = lpContext->Esp;
	state.ss = lpContext->SegSs;
	state.eflags = lpContext->EFlags;
	state.eip = lpContext->Eip;
	state.cs = lpContext->SegCs;
	state.ds = lpContext->SegDs;
	state.es = lpContext->SegEs;
	state.fs = lpContext->SegFs;
	state.gs = lpContext->SegGs;	
	sc = i386_THREAD_STATE_COUNT;
	result = thread_set_state( hThread, i386_THREAD_STATE, (thread_state_t) &state, sc);
	if (result != KERN_SUCCESS)
    {
		return 0;
	}

	x86_debug_state32_t debug;
	debug.dr0 = lpContext->Dr0;
	debug.dr1 = lpContext->Dr1;
	debug.dr2 = lpContext->Dr2;
	debug.dr3 = lpContext->Dr3;
	debug.dr6 = lpContext->Dr6;
	debug.dr7 = lpContext->Dr7;
	sc = x86_DEBUG_STATE32_COUNT;
	result = thread_set_state( hThread, x86_DEBUG_STATE32, (thread_state_t) &debug, sc);
	if (result != KERN_SUCCESS)
    {
		return 0;
	}
#endif	
	return 1;
}

/*
 * non-zero return is success
 */
EXPORT
BOOL CreateProcessA(LPCTSTR lpApplicationName, 
                    LPTSTR lpCommandLine, 
                    LPSECURITY_ATTRIBUTES lpProcessAttributes,
                    LPSECURITY_ATTRIBUTES lpThreadAttributes, 
                    BOOL bInheritHandles, 
                    DWORD dwCreationFlags, 
                    LPVOID lpEnvironment,
                    LPCTSTR lpCurrentDirectory,
                    LPSTARTUPINFO lpStartupInfo, 
                    LPPROCESS_INFORMATION lpProcessInformation )
{

	// problem here in OS X because we are not suspending the target so it will happily run ! :-)
	// we need to use ptrace to start the new target in a suspended state, which happens in Win32 with
	// the DEBUG_PROCESS/DEBUG_ONLY_THIS_PROCESS flags to CreateProcessA
	// fG! - 04/10/2010
#if DEBUG
	printf("[DEBUG] Creating process %s %s\n", lpApplicationName, lpCommandLine);
#endif
    posix_spawnattr_t attr;
    int retval      = 0;
    size_t copied   = 0;
    short flags     = 0;
    // default target is 32bits
    cpu_type_t cpu  = CPU_TYPE_I386;

    if (dwCreationFlags & TARGET_IS_64BITS)
        cpu = CPU_TYPE_X86_64;

    retval = posix_spawnattr_init (&attr);
    // set process flags
    // the new process will start in a suspended state and permissions reset to real uid/gid
    flags = POSIX_SPAWN_RESETIDS | POSIX_SPAWN_START_SUSPENDED;
    // disable ASLR, default is YES
    // Snow Leopard will just ignore this flag
    if (dwCreationFlags & _POSIX_SPAWN_DISABLE_ASLR)
        flags |= _POSIX_SPAWN_DISABLE_ASLR;
    
    retval = posix_spawnattr_setflags(&attr, flags);

    // reset signals, ripped from LLDB :-]
    sigset_t no_signals;
    sigset_t all_signals;
    sigemptyset (&no_signals);   
    sigfillset (&all_signals);
    posix_spawnattr_setsigmask(&attr, &no_signals);
    posix_spawnattr_setsigdefault(&attr, &all_signals);
    // set the target cpu to be used, due to fat binaries
    retval = posix_spawnattr_setbinpref_np(&attr, 1, &cpu, &copied);
    
    char *spawnedEnv[] = { NULL };
    
    int cmd_line_len = strlen(lpCommandLine);
    if (cmd_line_len >= ARG_MAX)
    {
        fprintf(stderr, "[ERROR] arg list too long\n");
        exit(1);
    }

    if (cmd_line_len)
    {
        // parse command line;
        int i = 0;
        char *p = strchr(lpCommandLine, ' ');
        char *q = lpCommandLine;

        char **argv = malloc(sizeof(char*) * 256);
        while (p && i < 253) 
        {
            *p = '\0';
            argv[i++] = q;
            q = p + 1;
            p = strchr(q, ' ');
        }
        errno = 0;
        argv[i] = q;
        argv[i+1] = NULL;
#if DEBUG
        printf("[DEBUG] Spawning %s %s %s\n", argv[0], argv[1], argv[2]);
#endif
        fflush(stdout);
        retval = posix_spawn(&target_pid, argv[0], NULL, &attr, argv, spawnedEnv);
        if(retval)
        {
            fprintf(stderr, "[ERROR] Could not spawn debuggee: %s\n", strerror(retval));
            exit(1);
        }        
        free(argv);
    }
    else 
    {
        fflush(stdout);
        // execute with no arguments
        char *argv[] = {lpApplicationName, NULL};
#if DEBUG
        printf("[DEBUG] Spawning %s...\n", lpApplicationName);
#endif
        retval = posix_spawnp(&target_pid, argv[0], NULL, &attr, argv, spawnedEnv);
        if (retval) 
        {
            fprintf(stderr, "[ERROR] Could not spawn debuggee: %s\n", strerror(retval));
            exit(1);
        }
    }
    // parent
    // initialize the mach port into the debugee
    retval = DebugActiveProcess(target_pid);
    // failed to attach
    if (retval == 0)
    {
        kill(target_pid, SIGCONT); // leave no zombies behind!
        kill(target_pid, SIGKILL);
        return 0;
    }
    // suspend all threads
    suspend_all_threads(target_pid);
    // and now we can continue the process, threads are still suspended!
    kill(target_pid, SIGCONT);
    fflush(stdout);
    lpProcessInformation->hProcess    = target_pid;
    lpProcessInformation->dwProcessId = target_pid;
	
	return 1;
}

EXPORT
HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
	return dwProcessId;
}

EXPORT
HANDLE OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId)
{
	return dwThreadId;
}

// WORKING
EXPORT
BOOL ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{

	short sts = read_memory(hProcess, (mach_vm_address_t) lpBaseAddress, nSize, lpBuffer);
	*lpNumberOfBytesRead = nSize;
	return sts;
}

// WORKING
EXPORT
BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{

	short sts = write_memory(hProcess, (mach_vm_address_t) lpBaseAddress, (mach_msg_type_number_t) nSize, (char *) lpBuffer);
	*lpNumberOfBytesWritten = nSize;
	return sts;
}

EXPORT
DWORD ResumeThread(HANDLE hThread)
{
	return resume_thread(hThread);
}

EXPORT
DWORD SuspendThread(HANDLE hThread)
{
	return suspend_thread(hThread);
} 

// ignores allocationtype and protection
EXPORT
LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{

	mach_vm_address_t addr = (mach_vm_address_t) lpAddress;
	
	unsigned int addy = (unsigned int) allocate(hProcess, addr, dwSize);
	return (LPVOID) addy;
}

EXPORT
BOOL VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{

	mach_vm_address_t addr = (mach_vm_address_t) lpAddress;
	
	return virtual_free(hProcess, addr, dwSize);
}


// WORKING
EXPORT
SIZE_T VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
{
	unsigned int prot = 0;
	mach_vm_size_t size = 0;

	mach_vm_address_t addr = (mach_vm_address_t)lpAddress;

	if(virtual_query(hProcess, &addr, &prot, &size))
    {
		return 0;
	}

	lpBuffer->BaseAddress = addr;
	lpBuffer->Protect = prot;
	lpBuffer->RegionSize = size;
	lpBuffer->State = MEM_COMMIT; // dunno what this means or the equiv for mac, but needed for snapshotting.

	return sizeof(MEMORY_BASIC_INFORMATION);
}

EXPORT
DWORD GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh){
	struct stat sb;
	fstat(hFile, &sb);
	return sb.st_size;
}

//EXPORT
//BOOL VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect){
EXPORT
BOOL VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect)
{

	//CLEANME
//	printf("VirtualProtectEx called! Parameters are: Process: %d Address:%p Size: %x NewProtect: %x\n", hProcess, (void *)lpAddress, dwSize, flNewProtect);

	// Find old protection
//	MEMORY_BASIC_INFORMATION Buffer;
//	VirtualQueryEx(hProcess, lpAddress, &Buffer, dwSize);
//	*lpflOldProtect = Buffer.Protect;

	// Set new protection
#if __LP64__
	if ((mach_vm_address_t)lpAddress < 0x0000000100000000)
	{
		//fprintf(stderr, "Trying to protect a memory address (%p)located in PAGEZERO!\n", (void *)lpAddress);
		return 1;
	}
#endif
//	printf("Calling virtual_protect in VirtualProtectEx: Process:%d Address:%lx Size:%x new protection:%x\n", hProcess, lpAddress, dwSize, flNewProtect);
	return virtual_protect(hProcess, (mach_vm_address_t) lpAddress, (mach_vm_size_t) dwSize, (vm_prot_t) flNewProtect);
}

// FIXME - teb for 64bits ???
EXPORT
BOOL GetThreadSelectorEntry(HANDLE hThread, DWORD dwSelector, LPLDT_ENTRY lpSelectorEntry)
{
//	fprintf(stderr, "GetThreadSelectorEntry %d %ld\n", hThread, dwSelector);
/*
** Note: technically, some functions are called with threadid's instead of pids
**       which would break things except the pid is only really needed in those
**       fuctions the first time one of them is called.  What a hack 
*/
	if(!allocated_fs_base){
		char *fake_data = (char *) malloc(0x40);
		// Allocate some memory to put our fake data structures
		mach_vm_address_t allocateme;
//		allocated_fs_base = (int) allocate(hThread, 0, 128);
		allocated_fs_base = (long) allocate(hThread, allocateme, 128);
		
		if(!allocated_fs_base){
			//printf("Couldn't allocate memory\n");
			return 0;
		}
//		printf("GetThreadSelectorEntry calling virtual_protect %lx\n", allocated_fs_base);
		virtual_protect(hThread, allocated_fs_base, 128, PAGE_READWRITE);
		// Put some fake data to access
		memset(fake_data, 0x0, 0x40);
		memcpy(fake_data,	"\xff\xff\xff\xff" /*SEH*/ 
							"\xff\xff\xff\xbf" /* stack top */ 
							"\x00\x00\x00\xbf" /* stack bottom */
											, 12);
		int *p = (int *) (fake_data + 0x30); // SEH
		*p = htonl(allocated_fs_base);
		write_memory(hThread, allocated_fs_base, 0x40, fake_data);
	}

	lpSelectorEntry->BaseLow = allocated_fs_base & 0xffff;
	lpSelectorEntry->HighWord.Bytes.BaseMid = (allocated_fs_base & 0xff0000) >> 16;
	lpSelectorEntry->HighWord.Bytes.BaseHi = (allocated_fs_base & 0xff000000) >> 24;

	return 1;
}

//////////////////////////////////////TODOs//////////////////////////

EXPORT
HMODULE LoadLibraryA(LPCTSTR lpFileName)
{
	//printf("LoadLibraryA '%s' %d\n", lpFileName,(int)strlen(lpFileName));
	void* library;
	
	if (strlen(lpFileName)==0)
	{
		//printf("Extracting symbols from all images\n");
		library = dlopen(NULL, RTLD_LAZY);
		//If dlsym() is called with the special handle RTLD_DEFAULT, then all mach-o images in the process
		//(except those loaded with dlopen(xxx,RTLD_LOCAL)) are searched in the order they were loaded.
		//This can be a costly search and should be avoided.

	}
	else
	{
		printf("Extracting symbols from library %s\n",lpFileName);
		library = dlopen(lpFileName, RTLD_LAZY);
	}

	if(library == NULL) 
	{
		// report error ...
		//printf("ERROR: Couldn't open library %s\n", lpFileName);
		return 1;
	} 
	else 
	{
		//printf("OK: Library %s opened! handle %x\n", lpFileName, library);
		return (HMODULE)library;
	}
	
}

EXPORT
BOOL FreeLibrary(HMODULE hModule)
{
    // FIXME: dlopen returns void * not int
	if (dlclose((void*)hModule) == 0)
	{
		return 0;
	}
	else 
	{
//		printf("Error while trying to free library!\n");
		return 1;
	}

}

EXPORT
FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
	// here we should use dlsym, which is the equivalent function in UNIX
	//printf("Handle is 0x%08x and will search for %s\n", hModule, lpProcName);
	FARPROC* initializer;
	Dl_info info;
	
	initializer = dlsym(hModule, lpProcName);
	if (initializer == NULL)
	{
		//printf("[ERROR][MacDLL] %s\n", dlerror());
		return 1;
	}
	
//	printf("Address of %s is %x\n", lpProcName, (unsigned int)initializer);
	if (dladdr(initializer, &info)) {
	 printf(" Info on dependencies():\n");
	 printf("    Pathname: %s\n",          info.dli_fname);
	 printf("    Base address: %p\n",      info.dli_fbase);
	 printf("    Nearest symbol: %s\n",    info.dli_sname);
	 printf("    Symbol address: %p\n",    info.dli_saddr);
	 printf("    Original address: 0x%08x\n",  (unsigned int)(info.dli_saddr-info.dli_fbase));
	 }
	
	return (FARPROC)initializer;
}

EXPORT
DWORD GetImageCount() 
{
	uint32_t imagecount;
	int i;
	imagecount = _dyld_image_count();	
	for (i=0; i < imagecount; i++)
	{
		printf("Image name: %s %x %x\n", _dyld_get_image_name(i),_dyld_get_image_vmaddr_slide(i),_dyld_get_image_header(i));
	}
	return imagecount;
}


EXPORT
BOOL FlushInstructionCache(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize)
{
	return 0;
}


EXPORT
BOOL Module32First(HANDLE hSnapshot, LPMODULEENTRY32 lpme)
{
	return 0;
}

EXPORT
BOOL Module32Next(HANDLE hSnapshot, LPMODULEENTRY32 lpme)
{
	return 0;
}

EXPORT
HANDLE GetCurrentProcess(void)
{
	return 0;
}

EXPORT
DWORD GetLastError(void)
{
	return 0;
}

EXPORT
DWORD FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPTSTR lpBuffer, DWORD nSize, va_list* Arguments)
{
	//printf("Error!\n");
	exit(1);
}

EXPORT
HANDLE CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCTSTR lpName)
{
	return 0;
}

EXPORT
LPVOID MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)
{
	return 0;
}

EXPORT
DWORD GetMappedFileName(HANDLE hProcess, LPVOID lpv, LPTSTR lpFilename, DWORD nSize)
{
	return 0;
}

EXPORT
BOOL UnmapViewOfFile(LPCVOID lpBaseAddress)
{
	return 0;
}

EXPORT
BOOL OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle)
{
	return 1;
}

EXPORT
BOOL LookupPrivilegeValueA(LPCTSTR lpSystemName, LPCTSTR lpName, PLUID lpLuid)
{
	return 1;
}

EXPORT
BOOL AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength)
{
	return 1;
}

EXPORT
BOOL NtSystemDebugControl()
{
	uuid_t id;
	struct timespec wait;
	wait.tv_sec = 0;
	wait.tv_nsec = 0;
	int error;
	
	error = gethostuuid(id, &wait);
	return 0;
}
