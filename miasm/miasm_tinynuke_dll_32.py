import os
from pdb import pm
from miasm2.analysis.sandbox import Sandbox_Win_x86_32
import yara
from capstone import *
import pefile

# Python auto completion
filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)


def create_sentinel(jitter):
	a = jitter.get_str_ansi(jitter.cpu.EAX)
	print a
	if ".php" in jitter.get_str_ansi(jitter.cpu.EAX):
	    jitter.run = False
	return True

def stop(jitter):
	print "No admin found !"
	jitter.run = False
	return True



def get_breakpoint_address(filename):

	yara_rule = """	rule dll_tinynuke {

		strings:
		$hex = { 32 04 31 88 06 8B 45 10 40 89 45 10 3B C3 72 D2 5E 8B C7 5F 5B 5D C3 55 8B EC }


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
	md = Cs(CS_ARCH_X86, CS_MODE_32)
	stop = False
	addr_to_break=0
	while not stop:
	    code = f.read(8)

	    for i in md.disasm(code, offset_instruction):
	        if i.mnemonic =='ret':
	            stop = True
	            addr_to_break=i.address
	    offset_instruction = offset_instruction + 8
	    if stop:
	        break
	return addr_to_break


parser = Sandbox_Win_x86_32.parser(description="PE sandboxer")
parser.add_argument("filename", help="PE Filename")
options = parser.parse_args()

sb = Sandbox_Win_x86_32(options.filename, options, globals())


sb.jitter.add_breakpoint(get_breakpoint_address(options.filename), create_sentinel)


sb.run()
