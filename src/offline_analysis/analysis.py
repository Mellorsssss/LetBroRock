import angr
from angrutils import *
import pyvex
from angr.code_location import CodeLocation
import subprocess
import os

if os.path.exists("instruction_dependencies.txt"):
    os.remove("instruction_dependencies.txt")

def get_function_addresses(binary_path):
    result = subprocess.run(
        ["nm", "-C", "-n", binary_path],
        stdout=subprocess.PIPE,
        text=True
    )
    lines = result.stdout.splitlines()
    functions = {}
    for line in lines:
        parts = line.split()
        if len(parts) == 3 and parts[1] == "T":  # 过滤出函数符号
            addr = int(parts[0], 16)
            name = parts[2]
            functions[addr] = name
    return functions

import sys

if len(sys.argv) < 2:
    sys.exit(1)

binary_path = sys.argv[1]

# init relevant components
funcs = get_function_addresses(binary_path)

project = angr.Project(binary_path, auto_load_libs=False, load_options={'main_opts': {'base_addr': 0x0}})

cfg = project.analyses.CFGEmulated(starts=list(funcs.keys()), context_sensitivity_level=0, resolve_indirect_jumps=True, enable_advanced_backward_slicing=True, keep_state = True, state_add_options=angr.sim_options.refs)
cdg = project.analyses.CDG(cfg=cfg)

# collect all the block addrs that ddg should perform on
ddg = project.analyses.DDG(cfg=cfg, block_addrs=[x for x in funcs.keys()])
ddg.pp()
print("end of data dependancy graph")

main = cfg.functions.function(name="main")

for func_addr, func_name in funcs.items():
    print(f"\n\nMELOS Processing function: {func_name} at address: {hex(func_addr)}")
    
    # we only analyze the corresponding function
    # vfg = project.analyses.VFG(cfg=cfg, function_start=func_addr)
    # print(vfg.graph)
    # print(vfg.graph.nodes)
    # vsa_ddg = project.analyses.VSA_DDG(vfg)
    
    func = cfg.functions.function(addr=func_addr)
    if not func:
        print(f"Function {func_name} not found in CFG.")
        continue

    control_flow_instructions = []

    func_end_addr = None
    # collect all of the control flow transfer instructions
    stmt_id_to_instr = {}
    for block in func.blocks:
        if block.instruction_addrs:
            stmt_id_to_instr[block.addr] = {}
            vex_block = project.factory.block(block.addr).vex
            print(vex_block)
            
            imark_statements = [stmt for stmt in vex_block.statements if stmt.tag == "Ist_IMark"]
            if len(imark_statements) == 0:
                print("No imarks found, it's very weird")
                continue

            # Create a mapping from statement_id to instruction address
            current_instr_addr = None

            for i, stmt in enumerate(vex_block.statements):
                if stmt.tag == "Ist_IMark":
                    current_instr_addr = stmt.addr
                    if func_end_addr is None or current_instr_addr > func_end_addr:
                        func_end_addr = current_instr_addr
                # after all AbiHint is just a hint, so we remove it
                if hasattr(stmt, 'jumpkind') and stmt.jumpkind in ["Ijk_Boring", "Ijk_Call"]:
                    control_flow_instructions.append((block.addr, i - 1, current_instr_addr))
                stmt_id_to_instr[block.addr][i] = current_instr_addr
            
            # collect all the instructions
            next_target = vex_block.next

            # the stmt that last read/write tmp
            last_tmp_stmt = None
            # only when the next_target is from a tmp, we need to reversely check previous instructions
            if isinstance(next_target, pyvex.expr.RdTmp):
                tmp_id = next_target.tmp 
                for index, stmt in enumerate(reversed(vex_block.statements)):
                    if isinstance(stmt, pyvex.stmt.IMark):
                        break
                    if isinstance(stmt, pyvex.stmt.WrTmp) and stmt.tmp == tmp_id:
                        last_tmp_stmt = stmt
                        control_flow_instructions.append((block.addr, len(vex_block.statements) - index - 1, stmt_id_to_instr[block.addr][len(vex_block.statements) - index - 1]))
                        break
                    elif isinstance(stmt, pyvex.stmt.Put) and isinstance(stmt.data, pyvex.expr.RdTmp) and stmt.data.tmp == tmp_id:
                        last_tmp_stmt = stmt
                        control_flow_instructions.append((block.addr, len(vex_block.statements) - index - 1, stmt_id_to_instr[block.addr][len(vex_block.statements) - index - 1]))
                        break
        
    # perform backward slice analysis on every control flow transfer instruction
    try:
        targets = [CodeLocation(block_addr, index, ins_addr=insn_addr) for block_addr, index, insn_addr in control_flow_instructions]

        # test the ddg by the last stmt
        # if control_flow_instructions:
        #     loc = CodeLocation(*control_flow_instructions[0])
        #     try:
        #         predecessors = list(ddg.get_predecessors(loc))
        #     except Exception as e:
        #         print(f"Error getting predecessors: {e}")
 
        bs = project.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=targets,same_function=True)

        instr_addr_set = set()
        for block in func.blocks:
            num_statements = len(block.vex.statements)
            positive_stmt_ids = []
            for stmt_id in bs.chosen_statements[block.addr]:
                if stmt_id < 0:
                    positive_stmt_id = num_statements + stmt_id
                else:
                    positive_stmt_id = stmt_id
                positive_stmt_ids.append(positive_stmt_id)

            temp_instr = set()
            for stmt_id in positive_stmt_ids:
                if stmt_id in stmt_id_to_instr[block.addr]:
                    instr_addr = stmt_id_to_instr[block.addr][stmt_id]
                    instr_addr_set.add(instr_addr)
                    temp_instr.add(instr_addr)
            print(f"{hex(block.instruction_addrs[-1])} depended on:{' '.join(hex(addr) for addr in sorted(temp_instr))}")
                        
        print(f"for all the instructions, the following instructions are depended on:{' '.join(hex(addr) for addr in sorted(instr_addr_set))}")
        # Ensure all branches within a function follow the same control flow instructions
        if len(instr_addr_set):
            with open("instruction_dependencies.txt", "a") as f:
                    f.write(f"{func_name} {hex(func_addr)} {hex(func_end_addr)}: ")
                    f.write(f"{' '.join(hex(addr) for addr in sorted(instr_addr_set))}\n")
        print(f"instruction {hex(block.instruction_addrs[-1])} depends on instruction:", " ".join(hex(addr) for addr in sorted(instr_addr_set)))
    except Exception as e:
        print(f"Error processing instruction at {hex(block.addr)}: {e}")
    else:
        print(f"Block {hex(block.addr)} has no instructions.")
