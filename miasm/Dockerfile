FROM miasm/base:latest

USER root

RUN apt-get -qq update && apt-get -qqy install python-pip python-pefile

RUN pip install capstone yara-python

COPY miasm_tinynuke_dll_32.py /tinynuke/
COPY miasm_tinynuke_dll_64.py /tinynuke/

USER miasm2

# Default command
CMD ["/bin/bash"]