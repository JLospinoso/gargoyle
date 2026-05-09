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

wait_entry:
	jmp wait_body
	times 16 - ($ - wait_entry) db 0x90

callback_entry:
	jmp callback_body
	times 16 - ($ - callback_entry) db 0x90

; Called from setup_x64 as void (*wait_entry)(X64Configuration*).
; This code remains executable while setup_x64.pic is parked PAGE_READONLY.
wait_body:
	push rbx
	mov rbx, rcx
	sub rsp, 48

	; VirtualProtectEx(GetCurrentProcess(), setup_addr, setup_length,
	;                  PAGE_READONLY, &old_protection)
	mov rcx, -1
	mov rdx, [rbx + X64Configuration.setup_addr]
	mov r8, [rbx + X64Configuration.setup_length]
	mov r9d, 0x02
	lea rax, [rbx + X64Configuration.old_protection]
	mov [rsp + 32], rax
	call [rbx + X64Configuration.VirtualProtectEx]

	; WaitForSingleObjectEx(timer, INFINITE, TRUE)
	mov rcx, [rbx + X64Configuration.sleep_handle]
	mov edx, 0xFFFFFFFF
	mov r8d, 1
	call [rbx + X64Configuration.WaitForSingleObjectEx]

	; Returning to setup_x64.pic is only safe after its page is executable again.
	; This is idempotent when the APC callback already restored PAGE_EXECUTE_READ.
	mov rcx, -1
	mov rdx, [rbx + X64Configuration.setup_addr]
	mov r8, [rbx + X64Configuration.setup_length]
	mov r9d, 0x20
	lea rax, [rbx + X64Configuration.old_protection]
	mov [rsp + 32], rax
	call [rbx + X64Configuration.VirtualProtectEx]

	add rsp, 48
	pop rbx
	ret

; Called by the waitable timer APC as:
; void CALLBACK TimerAPCProc(config, timer_low, timer_high).
callback_body:
	push rbx
	mov rbx, rcx
	sub rsp, 48

	; VirtualProtectEx(GetCurrentProcess(), setup_addr, setup_length,
	;                  PAGE_EXECUTE_READ, &old_protection)
	mov rcx, -1
	mov rdx, [rbx + X64Configuration.setup_addr]
	mov r8, [rbx + X64Configuration.setup_length]
	mov r9d, 0x20
	lea rax, [rbx + X64Configuration.old_protection]
	mov [rsp + 32], rax
	call [rbx + X64Configuration.VirtualProtectEx]

	add rsp, 48
	pop rbx
	ret
