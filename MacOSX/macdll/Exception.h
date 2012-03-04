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
 * exception.h
 *
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>

int my_msg_server(mach_port_t exception_port, int milliseconds, int *id, int *except_code, unsigned long *eat, unsigned long *eref);

void call_msg_server(mach_port_t exceptionPort);
mach_port_t install_debug_port(pid_t pid);
int XToWinException(int ec);
extern int suspend_thread(unsigned int thread);
extern kern_return_t catch_mach_exception_raise(mach_port_t             exception_port,
                                                mach_port_t             thread,
                                                mach_port_t             task,
                                                exception_type_t        exception,
                                                exception_data_t        code,
                                                mach_msg_type_number_t  codeCnt
                                                );

extern kern_return_t catch_mach_exception_raise_state(mach_port_t             exception_port,
                                                      exception_type_t        exception,
                                                      const exception_data_t  code,
                                                      mach_msg_type_number_t  codeCnt,
                                                      int *                   flavor,
                                                      const thread_state_t    old_state,
                                                      mach_msg_type_number_t  old_stateCnt,
                                                      thread_state_t          new_state,
                                                      mach_msg_type_number_t *new_stateCnt
                                                      );
kern_return_t catch_mach_exception_raise_state_identity(mach_port_t             exception_port,
                                                        mach_port_t             thread,
                                                        mach_port_t             task,
                                                        exception_type_t        exception,
                                                        exception_data_t        code,
                                                        mach_msg_type_number_t  codeCnt,
                                                        int *                   flavor,
                                                        thread_state_t          old_state,
                                                        mach_msg_type_number_t  old_stateCnt,
                                                        thread_state_t          new_state,
                                                        mach_msg_type_number_t *new_stateCnt
                                                        );

uint64_t get_eip (thread_state_t stateptr);

