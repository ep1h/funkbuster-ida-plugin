import idautils
import idc
import ida_funcs
import ida_segment
import ida_search
import ida_bytes
import ida_typeinf
import idaapi


def get_all_functions() -> list[int]:
    return [func_ea for func_ea in idautils.Functions()]


def get_all_data() -> list[int]:
    return [func_ea for func_ea in idautils.Modules()]


def get_instruction_by_ea(ea: int) -> str:
    return idc.GetDisasm(ea)


def get_name_by_ea(ea: int) -> str:
    # return idc.get_func_name(function_ea)
    return idc.get_name(ea)


def get_ea_by_name(name: str) -> int:
    return idc.get_name_ea_simple(name)


def get_ea_by_name(name: str) -> int:
    return idc.get_name_ea_simple(name)


def get_function_ea_by_instruction_ea(instruction_ea: int) -> int:
    func = ida_funcs.get_func(instruction_ea)
    if func:
        return func.start_ea
    return None


def get_function_size(function_ea: int) -> int:
    return idc.get_func_attr(function_ea, idc.FUNCATTR_END) - idc.get_func_attr(function_ea, idc.FUNCATTR_START)


def get_function_stack_args_size(function_ea: int):
    tinfo = idaapi.tinfo_t()
    idaapi.get_tinfo(tinfo, function_ea)
    funcdata = ida_typeinf.func_type_data_t()
    tinfo.get_func_details(funcdata)
    return funcdata.stkargs


def get_xrefs_to_address(ea: int) -> dict[str, list[dict[str, int]]]:
    result = {}
    result["calls"] = []
    result["data_offset"] = []
    result["data_write"] = []
    result["data_read"] = []
    for xref in idautils.XrefsTo(ea):
        if xref.type == 17:  # Code_Near_Call
            result["calls"].append({"from_ea": xref.frm, "to_ea": xref.to,
                                   "from_func_ea": get_function_ea_by_instruction_ea(xref.frm)})
        elif xref.type == 1:
            from_func_ea = get_function_ea_by_instruction_ea(xref.frm)
            result["data_offset"].append(
                {"from_ea": xref.frm, "to_ea": xref.to, "from_func_ea": from_func_ea if from_func_ea else xref.frm})
        elif xref.type == 2:
            from_func_ea = get_function_ea_by_instruction_ea(xref.frm)
            result["data_write"].append(
                {"from_ea": xref.frm, "to_ea": xref.to, "from_func_ea": from_func_ea if from_func_ea else xref.frm})
        elif xref.type == 3:
            from_func_ea = get_function_ea_by_instruction_ea(xref.frm)
            result["data_read"].append(
                {"from_ea": xref.frm, "to_ea": xref.to, "from_func_ea": from_func_ea if from_func_ea else xref.frm})
        elif xref.type == 21 or xref.type == 19:  # Ordinary_Flow or Code_Near_Jump
            continue
    return result


def get_xrefs_from_function(function_ea: int) -> dict[str, list[dict[str, int]]]:
    result = {}
    result["calls"] = []
    result["data_offset"] = []
    result["data_write"] = []
    result["data_read"] = []
    for head in idautils.FuncItems(function_ea):
        for xref in idautils.XrefsFrom(head):
            if xref.type == 17:  # Code_Near_Call
                result["calls"].append({"from_ea": xref.frm, "to_ea": xref.to})
            elif xref.type == 1:
                result["data_offset"].append(
                    {"from_ea": xref.frm, "to_ea": xref.to})
            elif xref.type == 2:
                result["data_write"].append(
                    {"from_ea": xref.frm, "to_ea": xref.to})
            elif xref.type == 3:
                result["data_read"].append(
                    {"from_ea": xref.frm, "to_ea": xref.to})
            elif xref.type == 21 or xref.type == 19:  # Ordinary_Flow or Code_Near_Jump
                continue
    return result


def search_for_signature_in_function(function_ea: int, pattern: str) -> list[int]:
    match_addresses = []
    func_start = idc.get_func_attr(function_ea, idc.FUNCATTR_START)
    func_end = idc.get_func_attr(function_ea, idc.FUNCATTR_END)
    if func_start == idc.BADADDR or func_end == idc.BADADDR:
        return match_addresses

    start_address = func_start
    while True:
        match_address = ida_search.find_binary(
            start_address, func_end, pattern, 16, idc.SEARCH_DOWN | idc.SEARCH_CASE)

        if match_address == idc.BADADDR:
            break

        match_addresses.append(match_address)
        start_address = match_address + 1

    return match_addresses


def get_potential_vmt_calls(function_ea: int):
    vtable_calls = []
    for head in idautils.FuncItems(function_ea):
        if idc.print_insn_mnem(head) == "call":
            op_type = idc.get_operand_type(head, 0)
            if op_type == idc.o_phrase or op_type == idc.o_displ:
                vtable_calls.append(
                    {"call_ea": head, "vmt_offset": idc.get_operand_value(head, 0)})
    return vtable_calls
