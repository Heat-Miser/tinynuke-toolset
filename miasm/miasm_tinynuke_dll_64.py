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
    print(a)
    if "php" in jitter.get_str_ansi(jitter.cpu.RAX):
        jitter.run = False
    return True
    
def stop(jitter):
    print("No admin found !")
    jitter.run = False
    return True



def get_breakpoint_address(filename):

    yara_rule = """	rule dll_tinynuke {

        strings:
        $hex = { 4? 8b cf ff 15 ac 05 01 00 33 d2 8b c8 8b c7 ff c7 f7 f1 42 8a 04 3a 42 32 04 36 41 88 06 4? ff c6 3b fd }

        
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
    while True:
        code = f.read(64)
        
        for i in md.disasm(code, offset_instruction):
            if i.mnemonic =='ret':
                addr_to_break=i.address
                return addr_to_break
        offset_instruction = offset_instruction + 64

parser = Sandbox_Win_x86_64.parser(description="PE sandboxer")
parser.add_argument("filename", help="PE Filename")
options = parser.parse_args()

sb = Sandbox_Win_x86_64(options.filename, options, globals())

sb.jitter.add_breakpoint(get_breakpoint_address(options.filename), create_sentinel)
sb.jitter.cpu.RDX = 0x1
sb.run()
