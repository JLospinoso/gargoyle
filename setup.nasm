BITS 32

STRUC Configuration
.initialized: RESD 1
.setup_addr: RESD 1
.setup_length: RESD 1
.VirtualProtectEx: RESD 1
.WaitForSingleObjectEx: RESD 1
.CreateWaitableTimer: RESD 1
.SetWaitableTimer: RESD 1
.MessageBox: RESD 1
.trampoline_addr: RESD 1
.sleep_handle: RESD 1
.interval: RESD 1
.gadget: RESD 1
.shadow: RESD 2
.stack: RESB 0x10000
.trampoline: RESD 9
ENDSTRUC

; Call me like void (*__cdecl callable)(void* workspace);

	mov ebx, [esp+4] ; Configuration in ebx now
	lea esp, [ebx + Configuration.trampoline - 4] ; Bottom of "stack"
	mov ebp, esp
	mov edx, [ebx + Configuration.initialized]

	; If we're initialized, skip to trampoline fixup
	cmp edx, 0
	jne reset_trampoline

	; Create the timer
	push 0
	push 0
	push 0
	mov ecx, [ebx + Configuration.CreateWaitableTimer]
	call ecx
	mov [ebx + Configuration.sleep_handle], eax

	; Set the timer
	push 0
	mov ecx, [ebx + Configuration.trampoline_addr]
	push ecx
	mov ecx, [ebx + Configuration.gadget]
	push ecx
	mov ecx, [ebx + Configuration.interval]
	push ecx
	lea ecx, [ebx + Configuration.shadow]
	push ecx
	mov ecx, [ebx + Configuration.sleep_handle]
	push ecx
	mov ecx, [ebx + Configuration.SetWaitableTimer]
	call ecx

	; Set the initialized bit
	mov [ebx + Configuration.initialized], dword 1
	
	; Replace the return address on our trampoline
reset_trampoline:
	mov ecx, [ebx + Configuration.VirtualProtectEx]
	mov [ebx + Configuration.trampoline], ecx

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;;;; Arbitrary code goes here. Note that the
	;;;; default stack is pretty small (65k).
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	; Pop a MessageBox as example
	push 0          ; null
	push 0x656c796f ; oyle
	push 0x67726167 ; garg
	mov ecx, esp
	push 0x40       ; Info box
	push ecx        ; ptr to 'gargoyle' on stack
	push ecx        ; ptr to 'gargoyle' on stack
	push 0
	mov ecx, [ebx + Configuration.MessageBox]
	call ecx
	mov esp, ebp
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;;;; Time to setup tail calls to go down
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	; Setup arguments for WaitForSingleObjectEx x1
	push 1
	push 0xFFFFFFFF
	mov ecx, [ebx + Configuration.sleep_handle]
	push ecx
	push 0 ; Return address never ret'd

	; Setup arguments for WaitForSingleObjectEx x2
	push 1
	push 0xFFFFFFFF
	mov ecx, [ebx + Configuration.sleep_handle]
	push ecx
	; Tail call to WaitForSingleObjectEx
	mov ecx, [ebx + Configuration.WaitForSingleObjectEx]
	push ecx
	
	; Setup arguments for VirtualProtectEx
	lea ecx, [ebx + Configuration.shadow]
	push ecx
	push 2 ; PAGE_READONLY
	mov ecx, [ebx + Configuration.setup_length]
	push ecx
	mov ecx, [ebx + Configuration.setup_addr]
	push ecx
	push dword 0xffffffff
	; Tail call to WaitForSingleObjectEx
	mov ecx, [ebx + Configuration.WaitForSingleObjectEx]
	push ecx

	; Jump to VirtualProtectEx
	mov ecx, [ebx + Configuration.VirtualProtectEx]
	jmp ecx