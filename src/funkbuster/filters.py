from funcs_keeper import fk
from idaif import get_function_ea_by_instruction_ea


def apply_signature_filter(func_ea_list: list, signature: str, inverted: bool = False) -> list[int]:
    result = []
    for func_ea in func_ea_list:
        matched_addresses = fk.get_matched_signatures(func_ea, signature)
        if len(matched_addresses) > 0:
            if not inverted:
                result.append(func_ea)
        else:
            if inverted:
                result.append(func_ea)
    return result


def apply_xref_filter(
        func_ea_list: list, ea: int, to_flag: bool, frm_flag: bool,
        call_flag: bool, read_flag: bool, write_flag: bool, access_flag: bool,
        inverted: bool = False) -> list[int]:
    result = []
    for func_ea in func_ea_list:
        match_found = False
        if frm_flag:
            if call_flag:
                calls_from_func_ea = fk.get_calls_from_function(func_ea)
                for call_ea in calls_from_func_ea:
                    if ea == get_function_ea_by_instruction_ea(call_ea["to_ea"]):
                        match_found = True
                        if not inverted:
                            result.append(func_ea)
                            break
            if not match_found and read_flag:
                data_reads_from_func_ea = fk.get_data_reads_from_function(
                    func_ea)
                for read_ea in data_reads_from_func_ea:
                    if ea == read_ea["to_ea"]:
                        match_found = True
                        if not inverted:
                            result.append(func_ea)
                            break
            if not match_found and write_flag:
                data_writes_from_func_ea = fk.get_data_writes_from_function(
                    func_ea)
                for write_ea in data_writes_from_func_ea:
                    if ea == write_ea["to_ea"]:
                        match_found = True
                        if not inverted:
                            result.append(func_ea)
                            break
            if not match_found and access_flag:
                data_accesses_from_func_ea = fk.get_data_offsets_from_function(
                    func_ea)
                for access_ea in data_accesses_from_func_ea:
                    if ea == access_ea["to_ea"]:
                        match_found = True
                        if not inverted:
                            result.append(func_ea)
                            break
        if to_flag and not match_found:
            if call_flag:
                calls_to_func_ea = fk.get_function_calls_to_address(func_ea)
                for call_ea in calls_to_func_ea:
                    if ea == get_function_ea_by_instruction_ea(call_ea["from_ea"]):
                        match_found = True
                        if not inverted:
                            result.append(func_ea)
                            break
            if not match_found and access_flag:
                data_accesses_to_func_ea = fk.get_data_offsets_to_address(
                    func_ea)
                for access_ea in data_accesses_to_func_ea:
                    if ea == get_function_ea_by_instruction_ea(access_ea["from_ea"]):
                        match_found = True
                        if not inverted:
                            result.append(func_ea)
                            break
        if inverted and not match_found:
            result.append(func_ea)
    return result


def apply_flow_filter(func_ea_list: list, function_ea: int, depth: int, to_flag: bool, from_flag: bool, inverted: bool = False) -> list[int]:
    result = []
    for func_ea in func_ea_list:
        if to_flag:
            flows_to = fk.get_call_flows(func_ea, function_ea, depth)
            if len(flows_to) > 0:
                if not inverted:
                    result.append(func_ea)
            elif inverted:
                result.append(func_ea)
        if from_flag:
            flows_from = fk.get_call_flows(function_ea, func_ea, depth)
            if len(flows_from) > 0:
                if not inverted:
                    result.append(func_ea)
            elif inverted:
                result.append(func_ea)
    return result


def apply_size_filter(func_ea_list: list, size_min: int, size_max: int, apply_min: bool = True, apply_max: bool = True, inverted: bool = False) -> list[int]:
    def is_in_range(size: int) -> bool:
        if apply_min and size < size_min:
            return False
        if apply_max and size > size_max:
            return False
        return True

    if inverted:
        return [func_ea for func_ea in func_ea_list if not is_in_range(fk.get_function_size(func_ea))]
    else:
        return [func_ea for func_ea in func_ea_list if is_in_range(fk.get_function_size(func_ea))]


def apply_xrefs_to_number_filter(func_ea_list: list, min: int, max: int, min_enabled: bool, max_enabled: bool, inverted: bool = False) -> list[int]:
    result = []
    if min_enabled:
        for func_ea in func_ea_list:
            xrefs_to_number = len(fk.get_function_calls_to_address(func_ea))
            if xrefs_to_number >= min:
                if not inverted:
                    result.append(func_ea)
            else:
                if inverted:
                    result.append(func_ea)
    if max_enabled:
        if min_enabled:
            func_ea_list = result
            result = []
        for func_ea in func_ea_list:
            xrefs_to_number = len(fk.get_function_calls_to_address(func_ea))
            if xrefs_to_number <= max:
                if not inverted:
                    result.append(func_ea)
            else:
                if inverted:
                    result.append(func_ea)
    return result


def apply_xrefs_from_number_filter(func_ea_list: list, min: int, max: int, min_enabled: bool, max_enabled: bool, inverted: bool = False) -> list[int]:
    result = []
    if min_enabled:
        for func_ea in func_ea_list:
            xrefs_from_number = len(fk.get_calls_from_function(func_ea))
            if xrefs_from_number >= min:
                if not inverted:
                    result.append(func_ea)
            else:
                if inverted:
                    result.append(func_ea)
    if max_enabled:
        if min_enabled:
            func_ea_list = result
            result = []
        for func_ea in func_ea_list:
            xrefs_from_number = len(fk.get_calls_from_function(func_ea))
            if xrefs_from_number <= max:
                if not inverted:
                    result.append(func_ea)
            else:
                if inverted:
                    result.append(func_ea)
    return result


def apply_stack_args_size_filter(func_ea_list: list, min: int, max: int, min_enabled: bool, max_enabled: bool, inverted: bool = False) -> list[int]:
    result = []
    if min_enabled:
        for func_ea in func_ea_list:
            stack_args_size = fk.get_function_stack_args_size(func_ea)
            if stack_args_size >= min:
                if not inverted:
                    result.append(func_ea)
            else:
                if inverted:
                    result.append(func_ea)
    if max_enabled:
        if min_enabled:
            func_ea_list = result
            result = []
        for func_ea in func_ea_list:
            stack_args_size = fk.get_function_stack_args_size(func_ea)
            if stack_args_size <= max:
                if not inverted:
                    result.append(func_ea)
            else:
                if inverted:
                    result.append(func_ea)
    return result


def apply_vmt_calls_number_filter(func_ea_list: list, min: int, max: int, min_enabled: bool, max_enabled: bool, inverted: bool = False) -> list[int]:
    result = []
    if min_enabled:
        for func_ea in func_ea_list:
            vmt_calls_number = len(fk.get_vmt_calls(func_ea))
            if vmt_calls_number >= min:
                if not inverted:
                    result.append(func_ea)
            else:
                if inverted:
                    result.append(func_ea)
    if max_enabled:
        if min_enabled:
            func_ea_list = result
            result = []
        for func_ea in func_ea_list:
            vmt_calls_number = len(fk.get_vmt_calls(func_ea))
            if vmt_calls_number <= max:
                if not inverted:
                    result.append(func_ea)
            else:
                if inverted:
                    result.append(func_ea)
    return result
