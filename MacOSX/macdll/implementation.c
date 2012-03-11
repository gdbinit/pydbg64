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
 * implementation.c
 *
 */

#include <implementation.h>
#include "Exception.h"

#define DEBUG 1

#define EXPORT __attribute__((visibility("default")))

/* NOTE:
#define VM_PROT_NONE    ((vm_prot_t) 0x00)
#define VM_PROT_READ    ((vm_prot_t) 0x01)
#define VM_PROT_WRITE   ((vm_prot_t) 0x02)
#define VM_PROT_EXECUTE ((vm_prot_t) 0x04)
*/

static task_t our_port = -1;  // initialized in attach

task_t 
getport(pid_t pid)
{
	if(our_port == -1)
    {
		task_t port;
        if(task_for_pid(mach_task_self(), pid, &port))
        {
                //fprintf(stderr, "Cannot get port, are you root?\n");
                return -1;
        }
		our_port = port;
	}
	return our_port;
}

int 
attach(pid_t pid, mach_port_t *exceptionport)
{
        //fprintf(stderr, "attach %x - calls exn_init\n", pid);
    our_port = -1;  // each time we attach, get a new port
    getport(pid);   // make sure port gets set
    
    *exceptionport = install_debug_port(pid);
    // failure
    if (*exceptionport == 0) return 0;
    // success
    return 1;
}

int
detach(pid_t pid, mach_port_t *exceptionport)
{
	//fprintf(stderr, "detatch %x\n", pid);
    mach_port_t me = mach_task_self();

	kern_return_t err = mach_port_deallocate(me, *exceptionport);
	if(err!= KERN_SUCCESS)
    {
		//printf("Failed to deallocate port!\n");
		if (err==KERN_INVALID_TASK){
			//fprintf(stderr, "Invalid task\n");
		} else if (err==KERN_INVALID_NAME) {
			//fprintf(stderr, "Invalid name\n");
		} else if (err==KERN_INVALID_RIGHT) {
			//fprintf(stderr, "Invalid right\n");
		}
	} else {
		//fprintf(stderr, "Deallocated port\n");
	}
    
    return 0;
}

// FIXME
void 
get_task_threads(int pid, thread_act_port_array_t *thread_list, mach_msg_type_number_t *thread_count)
{
//	fprintf(stderr, "get_task_threads %x\n", pid);
    task_t port = getport(pid);
    task_threads(port, thread_list, thread_count);
//	fprintf(stderr, "Got %d threads from %d\n", *thread_count, pid);
}

int 
virtual_free(int pid, mach_vm_address_t address, mach_vm_size_t size)
{
    int sts;
    vm_map_t port = getport(pid);
	//fprintf(stderr, "virtual_free %x %x %x\n", pid, address, size);
#if defined (__arm__)
    kern_return_t err = vm_deallocate(port, address, size);
#else
    kern_return_t err = mach_vm_deallocate(port, address, size);
#endif
    
    if(err!= KERN_SUCCESS){
        sts = 0;
    } else {
        sts = 1;
    }
    return sts;
}

static vm_prot_t 
winToXProtection(int type)
{
    vm_prot_t mac_prot = 0;
    switch(type)
    {
        case PAGE_NOACCESS:
            break;
        case PAGE_READONLY:
            mac_prot = VM_PROT_READ;
            break;
        case PAGE_READWRITE:
#if defined (__arm__)
            mac_prot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY;
#else
            mac_prot = VM_PROT_READ | VM_PROT_WRITE;
#endif
            break;
        case PAGE_EXECUTE:
            mac_prot = VM_PROT_EXECUTE;
            break;
        case PAGE_EXECUTE_READ:
            mac_prot = VM_PROT_EXECUTE | VM_PROT_READ;
            break;
        case PAGE_EXECUTE_READWRITE:
            // this will not work in iOS!
            mac_prot = VM_PROT_EXECUTE | VM_PROT_READ | VM_PROT_WRITE;
            break;
        case PAGE_GUARD:
        case PAGE_NOCACHE:
        case PAGE_WRITECOMBINE:
        default:
            ;
    }
    return mac_prot;
}

static int 
XToWinProtection(vm_prot_t mac)
{
    int ret;
    switch(mac)
    {
        case VM_PROT_READ:
            ret = PAGE_READONLY;
            break;
        case VM_PROT_READ | VM_PROT_WRITE:
            ret = PAGE_READWRITE;
            break;
        case VM_PROT_EXECUTE:
            ret = PAGE_EXECUTE;
            break;
        case VM_PROT_EXECUTE | VM_PROT_READ:
            ret = PAGE_EXECUTE_READ;
            break;
        case VM_PROT_EXECUTE | VM_PROT_READ | VM_PROT_WRITE:
            ret = PAGE_EXECUTE_READWRITE;
            break;
        default:
            ret = PAGE_NOACCESS;
    }
    return ret;
}

int 
virtual_protect(int pid, mach_vm_address_t address, mach_vm_size_t size, vm_prot_t type)
{
    vm_map_t port = getport(pid);
    int sts;
    // convert from Windows to OS X protection
    vm_prot_t mac_prot = winToXProtection(type);
        
    kern_return_t err = mach_vm_protect(port, address, size, FALSE, mac_prot);
    
    // FIXME: we are always returning success, even when failure occurs...
    if(err == KERN_SUCCESS){
        sts = 1;
    } else if(err == KERN_PROTECTION_FAILURE){
        sts = 1;  // hopefully they are setting up to read only
        fprintf(stderr, "[ERROR] virtual_protect Failed to protect\n");
    } else if(err == KERN_INVALID_ADDRESS){
        sts = 1;
        fprintf(stderr, "[ERROR] virtual_protect The address %p is illegal or specifies a non-allocated region.\n", (void*)address);
    } else {
        fprintf(stderr, "[ERROR] virtual_protect Opps, got %d return from vm_protect\n", err);
        sts = 1;  // Probably memory is not allocated.
    }
    return sts;
}

char *
allocate(int pid, mach_vm_address_t address, mach_vm_size_t size)
{
    char *data;
	//fprintf(stderr, "allocate %d %d %d\n", pid, address, size);
    vm_map_t port = getport(pid);
    
#if defined (__arm__)
    kern_return_t err = vm_allocate(port, (vm_address_t*) &data, size, VM_FLAGS_ANYWHERE);
#else
    kern_return_t err = mach_vm_allocate(port, (mach_vm_address_t*) &data, size, VM_FLAGS_ANYWHERE);
#endif
    
    if(err!= KERN_SUCCESS)
    {
        fprintf(stderr,"[IMPLEMENTATION.C] allocate failed!\n");
        data = NULL;
    } 
    //fprintf(stderr, "ALLOCATE RETURNED WITH %x\n", (unsigned int) data);
    return data;
}

int 
read_memory(int pid, mach_vm_address_t addr, mach_vm_size_t len, char *data)
{
    //		fprintf(stderr, "!read_memory %d %p %x\n", pid, (void *)addr, len);
    
    vm_map_t port = getport(pid);
	
#if defined (__arm__)
    vm_size_t nread;
    vm_read_overwrite(port, addr, len, (vm_address_t)data, &nread);
#else
    mach_vm_size_t nread;
    mach_vm_read_overwrite(port, addr, len, (mach_vm_address_t)data, &nread);
#endif
    if(nread != len){
        //fprintf(stderr, "Error reading memory, requested %d bytes, read %d\n", len, nread);
        //                return 0;  // bad
    }
    /*		if (data != NULL)
     printf("[DEBUG] read %d bytes data is: %x\n", nread, *data);
     */
    return 1;
}

int 
write_memory(int pid, mach_vm_address_t addr, mach_msg_type_number_t len, char *data)
{
    //		fprintf(stderr, "write_memory %d %p %x\n", pid, (void *)addr, len);
    vm_map_t port = getport(pid);
    
#if defined (__arm__)
    kern_return_t ret = vm_write(port, addr, (vm_offset_t) data, len);
#else
    kern_return_t ret = mach_vm_write(port, addr, (vm_offset_t) data, len);
#endif
    
    if(ret != KERN_SUCCESS)
    {
        //fprintf(stderr, "Failed to write to %lx", addr);
        mach_error("mach_vm_write: ", ret);
        if(ret == KERN_PROTECTION_FAILURE)
            fprintf(stderr, "error writing to %p: Specified memory is valid, but does not permit writing\n", (void *)addr);
        if(ret == KERN_INVALID_ADDRESS)
            fprintf(stderr, "error writing to %p: The address is illegal or specifies a non-allocated region\n", (void *)addr);
        return 0;
    }	
    return 1;
}

// FIXME: clean the compiler tests since we are passing thread_state_t
int
get_context(thread_act_t thread, thread_state_t *state)
{
#if defined(__arm__)
    mach_msg_type_number_t sc = ARM_THREAD_STATE_COUNT;
    thread_get_state(thread, ARM_THREAD_STATE, (thread_state_t)state, &sc);    
#elif defined (__x86_64__)
    mach_msg_type_number_t sc = x86_THREAD_STATE64_COUNT;
    thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t)state, &sc);
#elif defined (__i386__)
    mach_msg_type_number_t sc = i386_THREAD_STATE_COUNT;
    thread_get_state(thread, i386_THREAD_STATE, (thread_state_t)state, &sc);
#endif    

    return 0;
}

int 
suspend_thread(unsigned int thread)
{
    int sts;
	//fprintf(stderr, "suspend_thread %x\n", thread);
    sts = thread_suspend(thread);
    if(sts == KERN_SUCCESS){
        sts = 0;
    } else {
        //fprintf(stderr, "Got bad return of %d\n", sts);
        sts = -1;
    }
    return sts;
}

// suspend all available threads in a given pid
int 
suspend_all_threads(pid_t target_pid)
{
#if DEBUG
    printf("[DEBUG] Suspending all threads...\n");
#endif

    task_t targetTask;
    mach_port_t me = mach_task_self();
    thread_act_port_array_t thread_list;
    mach_msg_type_number_t thread_count,i;

    if(task_for_pid(me, target_pid, &targetTask))
    {
        fprintf(stderr, "[ERROR] task for pid failed while trying to suspend threads!\n");
        fprintf(stderr, "Verify if python has the right procmod permissions!\n");
        exit(1);
    }
    if (task_threads(targetTask, &thread_list, &thread_count))
    {
        fprintf(stderr, "[ERROR] task_threads failed at %s\n", __FUNCTION__);
        exit(1);
    }

    if (thread_count > 0)
    {
        i = thread_count;
        while (i--)
        {
            suspend_thread(thread_list[i]);
        }
    }
    return(0);
}
    
int 
resume_thread(unsigned int thread)
{
    int i;
    kern_return_t ret;
    
    unsigned int size = THREAD_BASIC_INFO_COUNT;
    struct thread_basic_info info;
    
    ret = thread_info(thread, THREAD_BASIC_INFO, (thread_info_t) &info, &size);
	
    if(ret != KERN_SUCCESS)
    {
        fprintf(stderr, "Failed to get thread info 1, got %d\n", ret);
        // return ok for the case when the process is going away                return -1;
        return 0;
    }
	
    for(i = 0; i < info.suspend_count; i++)
    {
        ret = thread_resume(thread);
        if(ret != KERN_SUCCESS)
        {
            fprintf(stderr, "Failed to get thread info 2, got %d\n", ret);
            return -1;
        }
    }
    return 0;
}


int 
virtual_query(int pid, mach_vm_address_t *baseaddr, unsigned int *prot, mach_vm_size_t *size)
{
    
    task_t port = getport(pid);
    //fprintf(stderr, "virtual_query %x %x %x\n", pid, *baseaddr, *size);
    
    // since we are using mach_vm_region we should use the new structures - support both 32 and 64 bits
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    struct vm_region_basic_info_64 info;
    mach_port_t objectName = MACH_PORT_NULL;
    mach_vm_address_t requested_base = *baseaddr;
    
    // FIXMEARM - VM_REGION ????
#if defined (__arm__)
    kern_return_t result = vm_region(port, (vm_address_t*)baseaddr, (vm_size_t*)size, VM_REGION_BASIC_INFO_64, (vm_region_info_t) &info, &count, &objectName);
#else
    kern_return_t result = mach_vm_region(port, baseaddr, size, VM_REGION_BASIC_INFO_64, (vm_region_info_t) &info, &count, &objectName);
#endif
	
    // what can go wrong?  
    // No allocated pages at or after the requested addy
    // we just make up one for the rest of memory
    if(result != KERN_SUCCESS){
        //				fprintf(stderr, "[IMPLEMENTATION.C] virtual_query failing case 1\n");
#if __LP64__
        *size = 0xffffffffffffffff - requested_base + 1;
#else
        *size = 0xffffffff - requested_base + 1;
#endif
        *prot = PAGE_NOACCESS;
        return 0;
    }
	
    if (VM_REGION_BASIC_INFO_COUNT_64 != count)
    {
        fprintf(stderr, "vm_region returned a bad info count");
    }
    // Mac scans ahead to the next allocated region, windows doesn't
    // We just make up a region at the base that isn't accessible so that iterating through memory works :/
    // this will bring problems with 64bit binaries because addressing starts at vmaddr 0x0000000100000000
    // and we can have requests for lower addresses
    // FIXME
    if(*baseaddr > requested_base)
    {
        //				fprintf(stderr, "[IMPLEMENTATION.C] virtual_query failing case 2, baseaddr=%p, requested_base=%p\n", (void *)*baseaddr, (void *)requested_base);
        *size = *baseaddr - requested_base;
        *baseaddr = requested_base;
        *prot = PAGE_NOACCESS;
        return 0;
    }
    
    // cool, worked
    *prot = XToWinProtection(info.protection);
    //fprintf(stderr, "Virtual query suceeded\n");
    return 0;
}


		

