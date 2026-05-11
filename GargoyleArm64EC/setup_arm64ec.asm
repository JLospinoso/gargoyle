        AREA    |.text|, CODE, READONLY, ALIGN=4
        EXPORT  setup_entry

ArmConfiguration_initialized          EQU 0x00
ArmConfiguration_reentry_wait         EQU 0x18
ArmConfiguration_reentry_callback     EQU 0x20
ArmConfiguration_CreateWaitableTimerW EQU 0x38
ArmConfiguration_SetWaitableTimer     EQU 0x40
ArmConfiguration_MessageBoxA          EQU 0x48
ArmConfiguration_sleep_handle         EQU 0x50
ArmConfiguration_due_time             EQU 0x58
ArmConfiguration_interval             EQU 0x60
ArmConfiguration_mode                 EQU 0x68
ArmConfiguration_remaining_rounds     EQU 0x6C
ArmConfiguration_completed_rounds     EQU 0x70

; Call as void setup_entry(ArmConfiguration* configuration).
; Windows ARM64 passes the configuration pointer in x0.
setup_entry PROC
        stp     x19, x30, [sp, #-16]!
        mov     x19, x0

        ldr     x8, [x19, #ArmConfiguration_initialized]
        cbnz    x8, payload_loop

        ; CreateWaitableTimerW(NULL, FALSE, NULL)
        mov     x0, xzr
        mov     w1, wzr
        mov     x2, xzr
        ldr     x8, [x19, #ArmConfiguration_CreateWaitableTimerW]
        blr     x8
        str     x0, [x19, #ArmConfiguration_sleep_handle]

        ; SetWaitableTimer(timer, &due_time, interval, reentry_callback, config, FALSE)
        add     x1, x19, #ArmConfiguration_due_time
        ldr     w2, [x19, #ArmConfiguration_interval]
        ldr     x3, [x19, #ArmConfiguration_reentry_callback]
        mov     x4, x19
        mov     w5, wzr
        ldr     x8, [x19, #ArmConfiguration_SetWaitableTimer]
        blr     x8

        mov     x8, #1
        str     x8, [x19, #ArmConfiguration_initialized]

payload_loop
        ldr     w8, [x19, #ArmConfiguration_remaining_rounds]
        cbz     w8, setup_return
        sub     w8, w8, #1
        str     w8, [x19, #ArmConfiguration_remaining_rounds]

        ldr     w9, [x19, #ArmConfiguration_completed_rounds]
        add     w9, w9, #1
        str     w9, [x19, #ArmConfiguration_completed_rounds]

        ldr     w10, [x19, #ArmConfiguration_mode]
        cbnz    w10, payload_after

        ; MessageBoxA(NULL, text, caption, MB_ICONINFORMATION)
        mov     x0, xzr
        adr     x1, gargoyle_text
        adr     x2, gargoyle_text
        mov     w3, #0x40
        ldr     x8, [x19, #ArmConfiguration_MessageBoxA]
        blr     x8

payload_after
        ldr     w8, [x19, #ArmConfiguration_remaining_rounds]
        cbz     w8, setup_return

        mov     x0, x19
        ldr     x8, [x19, #ArmConfiguration_reentry_wait]
        blr     x8
        b       payload_loop

setup_return
        ldp     x19, x30, [sp], #16
        ret
        ENDP

        ALIGN   4
gargoyle_text
        DCB     "gargoyle arm64ec", 0

        END
