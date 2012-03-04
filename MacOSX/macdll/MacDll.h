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
 * macdll.h
 *
 */

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> 
#include <dlfcn.h>
#include <stdint.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
#include <mach/thread_status.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <sys/syslimits.h>

#include "windows.h"

#define	_POSIX_SPAWN_DISABLE_ASLR	0x00000100
#define TARGET_IS_64BITS            0x00001000

// All prototypes compliments of MSDN

// "Implemented"
void GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
BOOL CloseHandle(HANDLE hObject);
BOOL DebugActiveProcess(DWORD dwProcessId);
BOOL WaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds);
BOOL ContinueDebugEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus);
BOOL DebugSetProcessKillOnExit(BOOL KillOnExit);
BOOL StartProcess(DWORD dwProcessId);
BOOL DebugActiveProcessStop(DWORD dwProcessId);
BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode);
HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
BOOL Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
BOOL Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
BOOL Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
BOOL Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
BOOL GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
BOOL CreateProcessA(LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
HANDLE OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
BOOL ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
DWORD ResumeThread(HANDLE hThread);
BOOL SetThreadContext(HANDLE hThread, const CONTEXT* lpContext);
DWORD SuspendThread(HANDLE hThread);
LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
SIZE_T VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
DWORD GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);
//BOOL VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
BOOL VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect);
BOOL GetThreadSelectorEntry(HANDLE hThread, DWORD dwSelector, LPLDT_ENTRY lpSelectorEntry);
BOOL NtSystemDebugControl();


// TODO
HMODULE LoadLibraryA(LPCTSTR lpFileName);
BOOL FreeLibrary(HMODULE hModule);
FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
DWORD GetImageCount(void);
BOOL FlushInstructionCache(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize);
BOOL Module32First(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
BOOL Module32Next(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
HANDLE GetCurrentProcess(void);
DWORD GetLastError(void);
DWORD FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPTSTR lpBuffer, DWORD nSize, va_list* Arguments);
HANDLE CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCTSTR lpName);
LPVOID MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
DWORD GetMappedFileName(HANDLE hProcess, LPVOID lpv, LPTSTR lpFilename, DWORD nSize);
BOOL UnmapViewOfFile(LPCVOID lpBaseAddress);
BOOL OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
BOOL LookupPrivilegeValueA(LPCTSTR lpSystemName, LPCTSTR lpName, PLUID lpLuid);
BOOL AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);

void test(int pid);

extern int attach(pid_t pid, mach_port_t *ep);
extern int detach(pid_t pid, mach_port_t *ep);
extern int my_msg_server(mach_port_t exception_port, int milliseconds, int *id, int *except_code, unsigned long *eat, unsigned long *eref);
extern void get_task_threads(int pid, thread_act_port_array_t *thread_list, mach_msg_type_number_t *thread_count);
extern int suspend_thread(unsigned int thread);
extern int suspend_all_threads(pid_t target_pid);
extern int resume_thread(unsigned int thread);
#if __LP64__
extern int get_context(thread_act_t thread, x86_thread_state64_t *state);
#else
extern int get_context(thread_act_t thread, i386_thread_state_t *state);
#endif
extern int virtual_query(int pid, mach_vm_address_t *baseaddr, unsigned int *prot, mach_vm_size_t *size);
extern int virtual_protect(int pid, mach_vm_address_t address, mach_vm_size_t size, vm_prot_t type);
extern int write_memory(int pid, mach_vm_address_t addr, mach_msg_type_number_t len, char *data);
extern int read_memory(int pid, mach_vm_address_t addr, mach_vm_size_t len, char *data);
extern int virtual_free(int pid, mach_vm_address_t address, mach_vm_size_t size);
extern char *allocate(int pid, mach_vm_address_t address,  mach_vm_size_t size);
