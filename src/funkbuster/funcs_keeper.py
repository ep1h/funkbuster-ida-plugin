import idaif


class FunctionInfo:
    def __init__(self):
        self.name = None
        self.size = None
        self.stack_args_size = None
        self.xrefs_to = None
        self.xrefs_from = None
        self.matched_signatures = {}
        self.vmt_calls = None


class FunctionsKeeper:
    def __init__(self):
        self.funcs = {}

    def get_function_info(self, function_ea: int) -> FunctionInfo:
        if function_ea not in self.funcs:
            self.funcs[function_ea] = FunctionInfo()
        return self.funcs[function_ea]

    def get_function_name(self, function_ea: int) -> str:
        fi = self.get_function_info(function_ea)
        if fi.name is None:
            fi.name = idaif.get_name_by_ea(function_ea)
        return fi.name

    def get_function_size(self, function_ea: int) -> int:
        fi = self.get_function_info(function_ea)
        if fi.size is None:
            fi.size = idaif.get_function_size(function_ea)
        return fi.size

    def get_function_stack_args_size(self, function_ea: int) -> int:
        fi = self.get_function_info(function_ea)
        if fi.stack_args_size is None:
            fi.stack_args_size = idaif.get_function_stack_args_size(
                function_ea)
        return fi.stack_args_size

    def get_calls_from_function(self, function_ea: int):
        fi = self.get_function_info(function_ea)
        if fi.xrefs_from is None:
            fi.xrefs_from = idaif.get_xrefs_from_function(function_ea)
        return fi.xrefs_from["calls"]

    def get_data_offsets_from_function(self, function_ea: int):
        fi = self.get_function_info(function_ea)
        if fi.xrefs_from is None:
            fi.xrefs_from = idaif.get_xrefs_from_function(function_ea)
        return fi.xrefs_from["data_offset"]

    def get_data_reads_from_function(self, function_ea: int):
        fi = self.get_function_info(function_ea)
        if fi.xrefs_from is None:
            fi.xrefs_from = idaif.get_xrefs_from_function(function_ea)
        return fi.xrefs_from["data_read"]

    def get_data_writes_from_function(self, function_ea: int):
        fi = self.get_function_info(function_ea)
        if fi.xrefs_from is None:
            fi.xrefs_from = idaif.get_xrefs_from_function(function_ea)
        return fi.xrefs_from["data_write"]

    def get_function_calls_to_address(self, function_ea: int) -> list[int]:
        fi = self.get_function_info(function_ea)
        if fi.xrefs_to is None:
            fi.xrefs_to = idaif.get_xrefs_to_address(function_ea)
        return fi.xrefs_to["calls"]

    def get_data_offsets_to_address(self, function_ea: int) -> list[int]:
        fi = self.get_function_info(function_ea)
        if fi.xrefs_to is None:
            fi.xrefs_to = idaif.get_xrefs_to_address(function_ea)
        return fi.xrefs_to["data_offset"]

    def get_matched_signatures(self, function_ea: int, signature: str) -> list[int]:
        function_info = self.get_function_info(function_ea)
        signature = signature.upper()

        # Check if the signature is already in matched_signatures
        if signature in function_info.matched_signatures:
            return function_info.matched_signatures[signature]

        # If the signature is not in matched_signatures, search for it in the function
        matched_addresses = idaif.search_for_signature_in_function(
            function_ea, signature)
        function_info.matched_signatures[signature] = matched_addresses

        # Remove any cached signatures that are substrings of the new signature
        for existing_signature in list(function_info.matched_signatures.keys()):
            if existing_signature != signature and existing_signature in signature:
                function_info.matched_signatures.pop(existing_signature, None)
        return matched_addresses

    def get_vmt_calls(self, function_ea: int):
        fi = self.get_function_info(function_ea)
        if fi.vmt_calls is None:
            fi.vmt_calls = idaif.get_potential_vmt_calls(function_ea)
        return fi.vmt_calls

    def get_call_flows(self, src_ea, dst_ea, depth):
        if depth == 0 or dst_ea == None:
            return []
        result = []

        calls_to_dst = self.get_function_calls_to_address(dst_ea)
        for call in calls_to_dst:
            caller_function_ea = call["from_func_ea"]
            if caller_function_ea == src_ea:
                result.append([caller_function_ea])
            else:
                flows = self.get_call_flows(
                    src_ea, caller_function_ea, depth - 1)
                for flow in flows:
                    flow.append(caller_function_ea)
                    result.append(flow)
        return result
    # def get_call_flows(self, src_ea, dst_ea, depth):
    #     if depth == 0:
    #         return []
    #     result = []

    #     calls_to_dst = self.get_function_calls_to_address(dst_ea)
    #     for call in calls_to_dst:
    #         caller_function_ea = idaif.get_function_ea_by_instruction_ea(call["from_ea"])
    #         if caller_function_ea == src_ea:
    #             result.append([caller_function_ea])
    #         else:
    #             flows = self.get_call_flows(src_ea, caller_function_ea, depth - 1)
    #             for flow in flows:
    #                 flow.append(caller_function_ea)
    #                 result.append(flow)
    #     return result


fk = FunctionsKeeper()
