# Why take a breakpoint for the last trace?
If the last instruction in the LBR buffer is statically evaluated, like a unconditional br or jmp. We could get the final stack by altering the current stack with the effect of final instruction.
For example, if the last stack is func_a and final instruction is jmp to func_b, the stack will be added the current position. If the final instruction doesn't change the stack(like in if-else branch), the stack remains the same. 
In a nut, we could just get the stack trace when the final instrucion is executed. SO TAKE ONE MORE BREAKPOINT!