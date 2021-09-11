import os
from pdb import pm
from miasm2.analysis.sandbox import Sandbox_Win_x86_64
from miasm2.os_dep.win_api_x86_32 import  kernel32_LoadLibrary
import yara
from capstone import *
import pefile

# Python auto completion
filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)


def create_sentinel(jitter):
	a = jitter.get_str_ansi(jitter.cpu.RAX)
	print a
	if "php" in jitter.get_str_ansi(jitter.cpu.RAX):
	    jitter.run = False
	return True
	
def stop(jitter):
	print "No admin found !"
	jitter.run = False
	return True



def get_breakpoint_address(filename):

	yara_rule = """	rule ahmed_tinynuke {

		strings:
		$hex = { 33 D2 8B 44  24 20 8B 4C 24 24 F7 F1 8B C2 8B C0 48 8B 4C 24  58 0F BE 04 01 8B 4C 24 28 33 C8 8B C1 8B 4C 24  20 48 8B 54 24 30 88 04 0A }

		
		condition:
			uint16(0) == 0x5A4D and
			$hex
	}
"""

	r = yara.compile(source=yara_rule)
	m=r.match(filename)
	pe = pefile.PE(filename)
	offset = m[0].strings[0][0]
	s = pe.get_section_by_offset(offset)
	f = open(filename,'rb')
	f.seek(offset)
	offset_instruction = pe.OPTIONAL_HEADER.ImageBase  + pe.get_rva_from_offset(offset)
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	stop = False
	addr_to_break=0
	while not stop:
	    code = f.read(64)
	    
	    for i in md.disasm(code, offset_instruction):
	        if i.mnemonic =='ret':
	            stop = True
	            addr_to_break=i.address
	    offset_instruction = offset_instruction + 8
	    if stop:
	        break
	return addr_to_break


parser = Sandbox_Win_x86_64.parser(description="PE sandboxer")
parser.add_argument("filename", help="PE Filename")
options = parser.parse_args()

sb = Sandbox_Win_x86_64(options.filename, options, globals())


sb.jitter.add_breakpoint(get_breakpoint_address(options.filename), create_sentinel)
sb.jitter.cpu.RDX = 0x1
sb.run()
