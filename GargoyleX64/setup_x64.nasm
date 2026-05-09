BITS 64
DEFAULT REL

STRUC X64Configuration
.initialized: RESQ 1
.setup_addr: RESQ 1
.setup_length: RESQ 1
.VirtualProtectEx: RESQ 1
.MessageBoxA: RESQ 1
.old_protection: RESD 1
.reserved: RESD 1
ENDSTRUC

; Call me like void (*entry)(void* configuration).
; RCX holds the configuration pointer on Win64.

	push rbx
	mov rbx, rcx
	sub rsp, 48 ; 32-byte shadow space, one stack argument, 16-byte alignment.

	cmp qword [rbx + X64Configuration.initialized], 0
	jne payload

	; VirtualProtectEx(GetCurrentProcess(), setup_addr, setup_length,
	;                  PAGE_EXECUTE_READ, &old_protection)
	mov rcx, -1
	mov rdx, [rbx + X64Configuration.setup_addr]
	mov r8, [rbx + X64Configuration.setup_length]
	mov r9d, 0x20
	lea rax, [rbx + X64Configuration.old_protection]
	mov [rsp + 32], rax
	call [rbx + X64Configuration.VirtualProtectEx]

	mov qword [rbx + X64Configuration.initialized], 1

payload:
	xor ecx, ecx
	lea rdx, [gargoyle_text]
	lea r8, [gargoyle_text]
	mov r9d, 0x40
	call [rbx + X64Configuration.MessageBoxA]

	add rsp, 48
	pop rbx
	ret

gargoyle_text:
	db 'gargoyle x64', 0
