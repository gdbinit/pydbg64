from pydbg import *
import time
import sys
global debug
# initialize instance
debug = pydbg()
# load our target
debug.load("/Applications/Calculator.app/Contents/MacOS/Calculator", "")

def handler_breakpoint (pydbg):
 # we are responsible for deleting the breakpoint!
 debug.bp_del(0x000000010000cc9a)
 print "About breakpoint hit!"
 debug.dump_context()
 return DBG_CONTINUE

# insert a new breakpoint
debug.bp_set(0x000000010000cc9a, handler=handler_breakpoint)
# start
debug.run()