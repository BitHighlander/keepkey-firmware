/* Research-only entry. The ELF loader initializes data/BSS in Unicorn. */
.syntax unified
.cpu cortex-m3
.thumb
.section .text.monero_arm_start,"ax",%progbits
.global monero_arm_start
.type monero_arm_start,%function
.thumb_func
monero_arm_start:
    ldr sp, =_stack
    bl monero_interop_run
    ldr r1, =monero_arm_result
    str r0, [r1]
    b monero_arm_done
.size monero_arm_start, .-monero_arm_start

.section .text.monero_arm_done,"ax",%progbits
.global monero_arm_done
.type monero_arm_done,%function
.thumb_func
monero_arm_done:
    b monero_arm_done
.size monero_arm_done, .-monero_arm_done

.section .bss.monero_arm_result,"aw",%nobits
.balign 4
.global monero_arm_result
.type monero_arm_result,%object
monero_arm_result:
    .space 4
.size monero_arm_result, 4
