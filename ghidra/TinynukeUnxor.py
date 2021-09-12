#Script used to unxor strings in Tinynuke DLLs
#@author Hash Miser (@h_miser) <contact@heat-miser.net>
#@category Tinynuke Tools

from ghidra.program.model.lang import OperandType

def get_string_from_memory(address, size):
    res = ""
    counter = 0
    c = getByte(toAddr(address.toString()))
    for counter in xrange(size):
        addr = address.add(counter).toString()
        c = getByte(toAddr(addr))
        res += chr(c)
    return res

def get_string_from_memory_safe(address):
    res = ""
    addr = toAddr(address.toString())
    c = getByte(toAddr(address.toString()))
    while c != 0:
        addr = addr.add(1)
        c = getByte(addr)
        res += chr(c)
    return res

def unxor(encoded_key, encoded_string, size):
	decoded_string = ''
	i = 0
	for i in range(0, size):
		decoded_string = decoded_string + chr(ord(encoded_string[i]) ^ ord(encoded_key[i % len(encoded_key)]))
	
	return str(decoded_string)

def main():
    #Get unxor function address
    unxor_addr = toAddr(askString("Unxor Function", "enter unxor function name"))

    #Get references to that function
    refs = getReferencesTo(unxor_addr)

    print("##############################")
    print("Unxoring Tinynuke's strings...")
    print("##############################\n")
    for ref in refs:
        ref_addr = ref.getFromAddress()


        #Getting the three previous parameters pushed (key, value, size)
        prev_instr = getInstructionBefore(ref_addr)
        params = []
        while len(params) != 3:
            if prev_instr.getMnemonicString() == "PUSH" and prev_instr.getOperandType(0) != OperandType.REGISTER:
                params.append(prev_instr)
            prev_instr = prev_instr.getPrevious()
     
        key_address = None
        value_address = None
        int_size = 0

        if params[0].getOperandType(0) & OperandType.ADDRESS == OperandType.ADDRESS:
            key_address = params[0].getOpObjects(0)[0]

        if params[1].getOperandType(0) & OperandType.ADDRESS == OperandType.ADDRESS:
            value_address = params[1].getOpObjects(0)[0]

        if params[2].getOperandType(0) == OperandType.SCALAR:
            int_size = int(params[2].getOpObjects(0)[0].toString(), 16)
        else:
            #In that case the int is stored in a register and it's not trivial to get it so we guess the length with the safe string (value)
            value = get_string_from_memory_safe(toAddr(value_address.toString()))
            int_size = len(value)
            

        key = get_string_from_memory(toAddr(key_address.toString()), int_size)
        value = get_string_from_memory(toAddr(value_address.toString()), int_size)

        #Locating where the value is stored after the call
        next_instr = getInstructionAfter(ref_addr)
        while next_instr.getMnemonicString() != "MOV" or next_instr.getNumOperands() != 2 or next_instr.getOpObjects(1)[0].toString() != "EAX":
            next_instr = getInstructionAfter(next_instr.getAddress())
        
        #Getting the address of the value (sometimes direct address sometines ECX + Address)
        opObject = next_instr.getOpObjects(0)
        if len(opObject) == 1:
            param_address = next_instr.getOpObjects(0)[0]
        else:
            param_address = next_instr.getOpObjects(0)[1]
        
        #Creating a repeatable comment at address with unxored value
        comment_addr = param_address
        listing = currentProgram.getListing()
        codeUnit = listing.getCodeUnitAt(toAddr(comment_addr.toString()))
        codeUnit.setComment(codeUnit.REPEATABLE_COMMENT, '[*] ' + unxor(key, value, int_size))
        print(unxor(key, value, int_size))


if __name__ == "__main__":
    main()