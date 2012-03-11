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
 * implementation.h
 *
 */

#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <mach/mach.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>

#if !defined (__arm__)
#include <mach/mach_vm.h>
#include <sys/ptrace.h>
#endif

#include <string.h>
#include <mach/thread_status.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>

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

#if defined (__arm__)
extern kern_return_t mach_vm_protect
(
 vm_map_t target_task,
 mach_vm_address_t address,
 mach_vm_size_t size,
 boolean_t set_maximum,
 vm_prot_t new_protection
 );
#endif

// PROTOTYPES
int attach(pid_t pid, mach_port_t *exceptionport);
int detach(pid_t pid, mach_port_t *exceptionport);
void get_task_threads(int pid, thread_act_port_array_t *thread_list, mach_msg_type_number_t *thread_count);

int virtual_query(int pid, mach_vm_address_t *baseaddr, unsigned int *prot, mach_vm_size_t *size);
int virtual_protect(int pid, mach_vm_address_t address, mach_vm_size_t size, vm_prot_t type);
int write_memory(int pid, mach_vm_address_t addr, mach_msg_type_number_t len, char *data);
int read_memory(int pid, mach_vm_address_t addr, mach_vm_size_t len, char *data);
char *allocate(int pid, mach_vm_address_t address,  mach_vm_size_t size);
int virtual_free(int pid, mach_vm_address_t address, mach_vm_size_t size);

int get_context(thread_act_t thread, thread_state_t *state);

int suspend_all_threads(pid_t target_pid);
int suspend_thread(unsigned int thread);
int resume_thread(unsigned int thread);
//int set_context(thread_act_t thread, i386_thread_state_t *state);

int allocate_in_thread(int threadId, int size);
task_t getport(pid_t pid);

// EXTERNAL
extern mach_port_t install_debug_port(pid_t pid);

