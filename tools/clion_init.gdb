set pagination off
set confirm off
set architecture i386
target remote localhost:2345
source /media/jon/C-NVMe-Windows/GitRepositories/WineGdbStub/tools/attach_symbols.py
attach_symbols
