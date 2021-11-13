#Script used to "deofbuscate" the unpacking function in the first level loader
#@author Hash Miser (@h_miser) <contact@heat-miser.net>
#@category Tinynuke Tools

from ghidra.program.model.lang import OperandType
from ghidra.app.plugin.assembler import Assemblers
from ghidra.program.model.mem import MemoryAccessException

def jumpit(beginning, end):
    print("Jumping blob between 0x%s and 0x%s" % (beginning, end))
    asm = Assemblers.getAssembler(currentProgram)
    inst = getInstructionAt(beginning)
    clearListing(beginning, beginning.add(2))
    asm.assemble(beginning, "JMP 0x%s" % (end.toString()))

def main():
    #Get the thread address
    entry_address = toAddr(askString("Threat function", "enter the function called in the thread"))
    function_end = None

    asm = Assemblers.getAssembler(currentProgram)

    #Get read instructions in that function
    inst = getInstructionAt(entry_address)
    print("Detecting useless instructions")
    #Detects useless instructions
    while inst.getMnemonicString() != "RET":
        if "XMM0" in inst.toString() or "JNP" in inst.toString() or "TEST" in inst.toString() or "LAHF" in inst.toString() or (inst.getMnemonicString() == "MOV" and inst.getOperandType(1) == OperandType.SCALAR):
            beginning = inst.getAddress()
            while "XMM0" in inst.toString() or "JNP" in inst.toString() or "TEST" in inst.toString() or "LAHF" in inst.toString() or (inst.getMnemonicString() == "MOV" and inst.getOperandType(1) == OperandType.SCALAR):
                inst = inst.getNext()
            end = inst.getAddress()
            #Set a JMP instruction at the beginning pointing to the end
            jumpit(beginning, end)
        else:
            inst = inst.getNext()

        next = getInstructionAfter(inst.getAddress())
        inst = next
    
    function_end = inst.getAddress()
    
    #Clear the decompiled code
    print("Clearing listing")
    clearListing(entry_address, function_end)
    #Force the decompiler to reanalyze the function
    print("Re disassembling function")
    disassemble(entry_address)

if __name__ == "__main__":
    main()

    