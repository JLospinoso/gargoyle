BITS 64
DEFAULT REL

STRUC X64Configuration
.initialized: RESQ 1
.setup_addr: RESQ 1
.setup_length: RESQ 1
.reentry_wait: RESQ 1
.reentry_callback: RESQ 1
.VirtualProtectEx: RESQ 1
.WaitForSingleObjectEx: RESQ 1
.CreateWaitableTimerW: RESQ 1
.SetWaitableTimer: RESQ 1
.MessageBoxA: RESQ 1
.sleep_handle: RESQ 1
.due_time: RESQ 1
.interval: RESD 1
.old_protection: RESD 1
ENDSTRUC

; Call me like void (*entry)(void* configuration).
; RCX holds the configuration pointer on Win64.

	push rbx
	mov rbx, rcx
	sub rsp, 64 ; 32-byte shadow space, two stack arguments, 16-byte alignment.

	cmp qword [rbx + X64Configuration.initialized], 0
	jne payload

	; CreateWaitableTimerW(NULL, FALSE, NULL)
	xor ecx, ecx
	xor edx, edx
	xor r8d, r8d
	call [rbx + X64Configuration.CreateWaitableTimerW]
	mov [rbx + X64Configuration.sleep_handle], rax

	; SetWaitableTimer(timer, &due_time, interval, reentry_callback, config, FALSE)
	mov rcx, rax
	lea rdx, [rbx + X64Configuration.due_time]
	mov r8d, [rbx + X64Configuration.interval]
	mov r9, [rbx + X64Configuration.reentry_callback]
	mov [rsp + 32], rbx
	mov qword [rsp + 40], 0
	call [rbx + X64Configuration.SetWaitableTimer]

	mov qword [rbx + X64Configuration.initialized], 1

payload:
	xor ecx, ecx
	lea rdx, [gargoyle_text]
	lea r8, [gargoyle_text]
	mov r9d, 0x40
	call [rbx + X64Configuration.MessageBoxA]

	mov rcx, rbx
	call [rbx + X64Configuration.reentry_wait]
	jmp payload

gargoyle_text:
	db 'gargoyle x64', 0
