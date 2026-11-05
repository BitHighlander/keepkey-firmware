/* Public-fixture hardware experiment only. Leaf function: no stack frame.
 * r0 = first byte after static data/BSS. Paint up to, excluding, current SP.
 * Return that SP so the caller can measure its subsequent test call chain.
 */
.syntax unified
.thumb
.text
.align 2
.global monero_paint_stack
.type monero_paint_stack, %function
.thumb_func
monero_paint_stack:
    mov r1, sp
    movs r2, #0xa5
1:
    cmp r0, r1
    bhs 2f
    strb r2, [r0], #1
    b 1b
2:
    mov r0, r1
    bx lr
.size monero_paint_stack, .-monero_paint_stack
