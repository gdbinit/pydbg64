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
 * dyld.h
 *
 */

#include <mach-o/ldsyms.h>
#include <mach/mach_types.h>

#if !defined (__arm__)
#include <mach/mach_vm.h>
#endif

#include <mach/mach.h>
#include <stdlib.h>

#define EXPORT __attribute__((visibility("default")))

int dyld_starts_here_p (task_t port, mach_vm_address_t addr);
int macosx_locate_dyld(int pid, unsigned int *addr);

extern task_t getport(pid_t pid);

