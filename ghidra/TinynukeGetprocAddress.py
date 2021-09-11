#Script used to comment functions handles loaded via getProcAddress
#@author Hash Miser (@h_miser) <contact@heat-miser.net>
#@category Tinynuke Tools

from ghidra.program.model.lang import OperandType

def main():
    #Get unxor function address
    getproc_addr = toAddr(askString("GetProcAddress handle address", "enter GetProcAddress handle label"))
    #Get references to that function
    refs = getReferencesTo(getproc_addr)
    listing = currentProgram.getListing()

    for ref in refs:
        ref_addr = ref.getFromAddress()
        instr = getInstructionAt(ref_addr)
        if instr.getMnemonicString() != "CALL":
            #skipping refrerences to getProcAdress handles which are not calls
            continue
        
        prev_instr = getInstructionBefore(ref_addr)
        params = []
        while len(params) != 2:
            if prev_instr.getMnemonicString() == "PUSH":
                params.append(prev_instr)
            prev_instr = prev_instr.getPrevious()
        comment = None
        for param in params:
            if param.getOperandType(0) == OperandType.DATA | OperandType.ADDRESS:
                param_addr = param.getOpObjects(0)[0]
                codeUnit = listing.getCodeUnitAt(param_addr)
                comment = codeUnit.getComment(codeUnit.REPEATABLE_COMMENT) + " handle"

        if not comment:
            continue

        next_instr = getInstructionAfter(ref_addr)
        while next_instr.getMnemonicString() != "MOV" or next_instr.getNumOperands() != 2 or next_instr.getOpObjects(1)[0].toString() != "EAX" or next_instr.getOperandType(0) != OperandType.DATA | OperandType.ADDRESS:
            next_instr = getInstructionAfter(next_instr.getAddress())

        #Getting the address of the value (sometimes direct address sometines ECX + Address)
        opObject = next_instr.getOpObjects(0)
        if len(opObject) == 1:
            param_address = next_instr.getOpObjects(0)[0]
        else:
            param_address = next_instr.getOpObjects(0)[1]
        comment_addr = param_address
        if comment_addr:
            codeUnit = listing.getCodeUnitAt(comment_addr)
            codeUnit.setComment(codeUnit.REPEATABLE_COMMENT, comment)
            createLabel(comment_addr, comment.split()[1], True)

if __name__ == "__main__":
    main()

