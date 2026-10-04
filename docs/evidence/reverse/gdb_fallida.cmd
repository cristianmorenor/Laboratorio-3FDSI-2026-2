set pagination off
set disassembly-flavor intel
break validate_key
run AAAA
info registers rdi rip
x/s $rdi
x/4xb 0x40208b
x/17xb 0x402090
finish
info registers rax
continue
