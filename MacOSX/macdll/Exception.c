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
 * exception.c
 *
 */

#include "Exception.h"

static int thread_id;
static int exception_code;
static long exception_at;
static long exception_ref;

// Windows exception codes
#define EXCEPTION_ACCESS_VIOLATION          0xC0000005
#define EXCEPTION_BREAKPOINT                0x80000003
#define EXCEPTION_GUARD_PAGE                0x80000001
#define EXCEPTION_SINGLE_STEP               0x80000004
#define EXCEPTION_ILLEGAL_INSTRUCTION       0xC000001D
#define EXCEPTION_INT_DIVIDE_BY_ZERO        0xC0000094
#define EFLAGS_TRAP                         0x00000100

extern boolean_t mach_exc_server(mach_msg_header_t *request,mach_msg_header_t *reply);
static int XToWinException(int exception);

static int
XToWinException(int exception)
{
	int ret;
	switch(exception)
    {
		case EXC_BAD_ACCESS:
			ret = EXCEPTION_ACCESS_VIOLATION;
			break;
		case EXC_BREAKPOINT:
			ret = EXCEPTION_BREAKPOINT;
			break;
		case EXCEPTION_SINGLE_STEP:	// already converted
			ret = EXCEPTION_SINGLE_STEP;
			break;
        case EXC_BAD_INSTRUCTION:
            ret = EXCEPTION_ILLEGAL_INSTRUCTION;
            break;
        case EXC_ARITHMETIC: // arithmetic exceptions 
            ret = EXCEPTION_INT_DIVIDE_BY_ZERO;
            break;
		default:
			ret = EXC_SOFTWARE;  // why not
	}
	return ret;
}

// When we install our exception port, we always specify EXCEPTION_STATE_IDENTITY.  
// This means that the system will always call our catch_exception_raise_state_identity 
// routine.  catch_exception_raise and catch_exception_raise_state are present 
// purely for demostration purposes.

extern kern_return_t catch_mach_exception_raise(
	mach_port_t             exception_port,
	mach_port_t             thread,
	mach_port_t             task,
	exception_type_t        exception,
	exception_data_t        code,
	mach_msg_type_number_t  codeCnt )
{
#pragma unused(exception_port)
#pragma unused(task)
#pragma unused(codeCnt)
    
	kern_return_t kr;
    kern_return_t result;
	mach_msg_type_number_t count;
    thread_state_flavor_t flavor;
    
    // Decide whether to handle it or not.
#if defined (__arm__)
    arm_thread_state_t state;
    count  = ARM_THREAD_STATE_COUNT;
    flavor = ARM_THREAD_STATE;
#elif defined (__x86_64__)
	x86_thread_state64_t state;
	count  = x86_THREAD_STATE64_COUNT;
    flavor = x86_THREAD_STATE64;
#elif defined (__i386__)
	i386_thread_state_t state;	  
	count  = i386_THREAD_STATE_COUNT;
    flavor = i386_THREAD_STATE;
#endif

    // set globals
    thread_id       = thread;
    exception_code  = exception;

    // retrieve thread information
    kr = thread_get_state(thread,                 // target thread
                          flavor,                 // flavor of state to get
                          (thread_state_t)&state, // state information
                          &count);                // in/out size

    uint64_t eip = get_eip((thread_state_t)&state);
    
    // TRAP
    if (exception == EXC_BREAKPOINT) 
	{
		suspend_thread(thread); // ???
        
#if defined (__arm__)
        exception_at = eip - 1;   // Cause of the cc FIXMEARM: ?
        flavor = ARM_EXCEPTION_STATE;
        count  = ARM_EXCEPTION_STATE_COUNT;
        arm_exception_state_t exc_state;
        thread_get_state(thread, flavor, (thread_state_t)&exc_state, &count);
        exception_ref = exc_state.__far;

#elif defined (__x86_64__)
		// determine if single step
		if(state.__rflags & EFLAGS_TRAP || code[0] == EXC_I386_SGL)
		{   // the code[0] is if its a hardware breakpoint.  Windows expects those to be reported as a single step event
			exception_code = EXCEPTION_SINGLE_STEP;
		}
		
		exception_at = eip - 1;   // Cause of the cc
        flavor = x86_EXCEPTION_STATE64;
        count  = x86_THREAD_STATE64_COUNT;
        
        x86_exception_state64_t exc_state;
        thread_get_state(thread, flavor, (thread_state_t)&exc_state, &count);	
		exception_ref = exc_state.__faultvaddr;

#elif defined (__i386__)
		// determine if single step
		if(state.eflags & EFLAGS_TRAP || code[0] == EXC_I386_SGL)
		{   // the code[0] is if its a hardware breakpoint.  Windows expects those to be reported as a single step event
			exception_code = EXCEPTION_SINGLE_STEP;
		}
		
		exception_at = eip - 1;   // Cause of the cc
        flavor = i386_EXCEPTION_STATE;
        count  = i386_EXCEPTION_STATE_COUNT;
        
        i386_exception_state_t exc_state;
        thread_get_state(thread, flavor, (thread_state_t)&exc_state, &count);
		exception_ref = exc_state.faultvaddr;
#endif
        result = KERN_SUCCESS;
    }
    // FAULTS
	else if (exception == EXC_BAD_ACCESS || exception == EXC_BAD_INSTRUCTION)
	{
		// This is bad - or good :) //
        exception_at = eip;
#if defined (__arm__)
        flavor = ARM_EXCEPTION_STATE;
        count  = ARM_EXCEPTION_STATE_COUNT;
        arm_exception_state_t exc_state;
        thread_get_state(thread,flavor, (thread_state_t)&exc_state, &count);		
		exception_ref = exc_state.__far;   
#elif defined (__x86_64__)
        flavor = x86_EXCEPTION_STATE64;
        count  = x86_EXCEPTION_STATE64_COUNT;
        x86_exception_state64_t exc_state;
        thread_get_state(thread,flavor, (thread_state_t)&exc_state, &count);		
		exception_ref = exc_state.__faultvaddr;   
#elif defined (__i386__)
        flavor = x86_EXCEPTION_STATE32;
        count  = x86_EXCEPTION_STATE32_COUNT;
        i386_exception_state_t exc_state;
        thread_get_state(thread,flavor, (thread_state_t)&exc_state, &count);
		exception_ref = exc_state.faultvaddr;
#endif
		result = KERN_SUCCESS;
	} 
	else
	{
        // Other exceptions are SEP (somebody else's problem).
        result = KERN_FAILURE;
    }

    return result;
}

// this is just here because compiler complaints...
extern kern_return_t catch_mach_exception_raise_state(
	mach_port_t             exception_port,
	exception_type_t        exception,
	const exception_data_t  code,
	mach_msg_type_number_t  codeCnt,
	int *                   flavor,
	const thread_state_t    old_state,
	mach_msg_type_number_t  old_stateCnt,
	thread_state_t          new_state,
	mach_msg_type_number_t *new_stateCnt )
{
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise_state_identity(
	mach_port_t             exception_port,
	mach_port_t             thread,
	mach_port_t             task,
	exception_type_t        exception,
	exception_data_t        code,
	mach_msg_type_number_t  codeCnt,
	int *                   flavor,
	thread_state_t          old_state,
	mach_msg_type_number_t  old_stateCnt,
	thread_state_t          new_state,
	mach_msg_type_number_t *new_stateCnt )
{ 
      return KERN_FAILURE;
}

#define MAX_EXCEPTION_PORTS 16

static struct {
    mach_msg_type_number_t count;
    exception_mask_t      masks[MAX_EXCEPTION_PORTS];
    exception_handler_t   ports[MAX_EXCEPTION_PORTS];
    exception_behavior_t  behaviors[MAX_EXCEPTION_PORTS];
    thread_state_flavor_t flavors[MAX_EXCEPTION_PORTS];
} old_exc_ports;

mach_port_t
install_debug_port(pid_t pid)
{
    mach_port_t *exceptionPort = malloc(sizeof(mach_port_t));
    mach_port_t me;
	task_t targetTask;
	// http://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_set_exception_ports.html
    exception_mask_t  mask = EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_ARITHMETIC | EXC_MASK_SOFTWARE | EXC_MASK_BREAKPOINT | EXC_MASK_SYSCALL;
    
    // Create a port by allocating a receive right, and then create a send right 
    // accessible under the same name.
    me = mach_task_self();    
    mach_port_allocate(me, MACH_PORT_RIGHT_RECEIVE, exceptionPort);
	mach_port_insert_right(me, *exceptionPort, *exceptionPort, MACH_MSG_TYPE_MAKE_SEND);
    
	// get info for process
	if(task_for_pid(me, pid, &targetTask) != KERN_SUCCESS)
    {
        fprintf(stderr, "[ERROR] task for pid failed at %s!\n", __FUNCTION__);
        fprintf(stderr, "Verify if python has the right procmod permissions!\n");
		return 0;  // this is bad, probably bad pid.  returning 0 tells pydbg that attach failed.
	}
	
    /* get the old exception ports */
	task_get_exception_ports(targetTask, mask, old_exc_ports.masks, &old_exc_ports.count, old_exc_ports.ports, old_exc_ports.behaviors, old_exc_ports.flavors);

    /* set the new exception port */
	task_set_exception_ports(targetTask,               // target thread
							 mask,                     // exception types
							 *exceptionPort,           // the port
							 EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, // behavior, we OR with MACH_EXCEPTION_CODES for 64bits
							 THREAD_STATE_NONE);       // flavor

	return *exceptionPort;
}

/* These two structures contain some private kernel data. We don't need to
	struccess any of it so we don't bother defining a proper struct. The
	correct definitions are in the xnu source code. */    
struct {        
	mach_msg_header_t head;        
	char data[256];    
	} reply;    
			   
struct {        
	mach_msg_header_t head;        
	mach_msg_body_t msgh_body;        
	char data[1024];    
	} msg;

/* returns 1 if an event occured, 0 if it times out */
int 
my_msg_server(mach_port_t exception_port, int milliseconds, int *id, int *except_code, unsigned long *eat, unsigned long *eref)
{
	mach_msg_return_t r;

	r = mach_msg(&msg.head,
		MACH_RCV_MSG|MACH_RCV_LARGE|MACH_RCV_TIMEOUT,
		0,
		sizeof(msg),
		exception_port,
		milliseconds,
		MACH_PORT_NULL);

	if (r == MACH_RCV_TIMED_OUT) {
//        printf("receive timeout!\n");
		return 0;
	} else if (r != MACH_MSG_SUCCESS) {
		//printf("Got bad Mach message\n");
//		exit(-1);
	}

	/* Handle the message (calls catch_exception_raise) */
	// we should use mach_exc_server for 64bits
	mach_exc_server(&msg.head, &reply.head);

	*id = thread_id;
	*except_code = XToWinException(exception_code);
	*eat = exception_at;
	*eref = exception_ref;

	printf("**************************************Got exception code %x\n", *except_code);
	
	r = mach_msg(
		&reply.head,
		MACH_SEND_MSG|MACH_SEND_TIMEOUT,
		reply.head.msgh_size,
		0,
		MACH_PORT_NULL,
		milliseconds,
		MACH_PORT_NULL);

	if(r == MACH_SEND_TIMED_OUT)
    {
//        printf("send timeout!\n");
		return 0;
	} else if(r != MACH_MSG_SUCCESS){
		//printf("Got bad Mach message\n");
//		exit(-1);
	}

	return 1;
}

/* Retrieve EIP/RIP so we can work later in a platform independent way */
uint64_t get_eip (thread_state_t stateptr)
{	
#if defined (__arm__)
    arm_thread_state_t *state = (arm_thread_state_t *)stateptr;
    return(state->__pc);
#elif defined (__x86_64__)
	x86_thread_state64_t *state = (x86_thread_state64_t *)stateptr;
	return(state->__rip);
#elif defined (__i386__)
	i386_thread_state_t *state = (i386_thread_state_t *)stateptr;
	return(state->eip);
#endif
}

