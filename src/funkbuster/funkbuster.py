import idaapi
import ida_kernwin

import idaif
import funcs_keeper
from funcs_keeper import fk
from funcs_keeper import FunctionsKeeper
from funcs_keeper import FunctionInfo
from filters import apply_signature_filter
from filters import apply_xref_filter
from filters import apply_flow_filter

import gui


import idc

# TODO: REMOVE ON RELEASE BEGIN
# import idatopy


def reload_submodules():
    import importlib
    import sys
    for module_name in sorted(sys.modules.keys()):
        if module_name.startswith(__name__) or module_name.startswith("idaif") or module_name.startswith("filters") or module_name.startswith("funcs_keeper") or module_name.startswith("gui"):
            del sys.modules[module_name]
# REMOVE ON RELEASE END


class FunkbusterPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Searching for functions and data"
    help = "Help message"
    wanted_name = "Funkbuster Plugin"
    wanted_hotkey = "Ctrl-Shift-D"

    def init(self):
        reload_submodules()
        # self.f = filters.Filters()
        return idaapi.PLUGIN_OK

    def run(self, arg):
        self.init_gui()

    def term(self):
        pass

    def init_gui(self):
        self.gui = gui.FunkbusterForm()
        self.gui.Show("Funkbuster")
        self.gui.set_on_analyze_clicked(self.on_analyze_button_clicked)
        self.gui.set_on_result_item_clicked(self.on_result_item_clicked)
        self.gui.set_on_result_item_doublelicked(
            self.on_result_item_doubleclicked)
        self.gui.set_on_info_xrefs_from_item_doubleclicked(
            self.on_info_xrefs_from_item_doubleclicked)
        self.gui.set_on_info_xrefs_to_item_doubleclicked(
            self.on_info_xrefs_to_item_doubleclicked)
        self.gui.set_on_info_potentional_vmt_calls_item_doubleclicked(
            self.on_potentional_vmt_calls_item_doubleclicked)
        # send functions to gui
        functions_for_gui = [(func_addr, fk.get_function_name(func_addr))
                             for func_addr in idaif.get_all_functions()]
        self.gui.set_results(functions_for_gui)
        # print("names!: ", len(idaif.get_all_data()), idaif.get_all_data())
        # print("flow from 0x404F00 to 0x401840:")
        # flows = fk.get_call_flows(0x404F00, 0x401840, 4)
        # for flow in flows:
        #     print("")
        #     x = 0
        #     for func in flow:
        #         print(x * " ", hex(func))
        #         x += 1

        # print(idaif.get_function_flows(0x404F00, 0x408FF0, 4))

    def on_analyze_button_clicked(self, only_current: bool):
        print("analyze_button_clicked: ", only_current)

        target_list = []
        if only_current:
            target_list = self.gui.get_results()
        else:
            target_list = idaif.get_all_functions()

        filters = self.gui.get_filters_configuration()

        for filter in filters:
            if filter["type"] == "signature":
                print("Signature filter")
                print("Inverted: ", filter["invert"])
                print("Data: ", filter["data"])
                target_list = apply_signature_filter(
                    target_list, filter["data"], filter["invert"])
            elif filter["type"] == "xrefs":
                print("Xrefs filter")
                print("Inverted: ", filter["invert"])
                print("To: ", filter["to"])
                print("From: ", filter["from"])
                print("Call: ", filter["call"])
                print("Read: ", filter["read"])
                print("Write: ", filter["write"])
                print("Access: ", filter["access"])
                if filter["data_type"] == "name":
                    filter["data"] = idaif.get_ea_by_name(filter["data"])
                print("Data: ", filter["data"])
                target_list = apply_xref_filter(target_list, filter["data"], filter["to"], filter["from"],
                                                filter["call"], filter["read"], filter["write"], filter["access"], filter["invert"])
            elif filter["type"] == "flow":
                print("Flow filter")
                print("To: ", filter["to"])
                print("From: ", filter["from"])
                print("Depth: ", filter["depth"])
                print("Inverted: ", filter["invert"])
                if filter["data_type"] == "name":
                    filter["data"] = idaif.get_ea_by_name(filter["data"])
                print("Data: ", filter["data"])
                target_list = apply_flow_filter(
                    target_list, filter["data"], filter["depth"], filter["to"], filter["from"], filter["invert"])

        functions_for_gui = [(func_addr, idaif.get_name_by_ea(func_addr))
                             for func_addr in target_list]
        self.gui.set_results(functions_for_gui)

    def on_result_item_clicked(self, func_ea: int):
        print("#on_result_item_clicked: ", func_ea)
        # Build function info to display in gui
        function_info = {}
        function_info["address"] = func_ea
        function_info["name"] = fk.get_function_name(func_ea)
        function_info["size"] = fk.get_function_size(func_ea)
        function_info["calls_from"] = fk.get_calls_from_function(func_ea)
        function_info["reads_from"] = fk.get_data_reads_from_function(func_ea)
        function_info["writes_from"] = fk.get_data_writes_from_function(
            func_ea)
        function_info["offsets_from"] = fk.get_data_offsets_from_function(
            func_ea)
        function_info["calls_to"] = fk.get_function_calls_to_address(func_ea)
        function_info["offsets_to"] = fk.get_data_offsets_to_address(func_ea)
        function_info["vmt_calls"] = fk.get_vmt_calls(func_ea)

        self.gui.set_info(function_info)
        # print(function_info)

    def on_result_item_doubleclicked(self, func_ea: int):
        print("#on_result_item_doubleclicked: ", func_ea)
        ida_kernwin.jumpto(func_ea)

    def on_info_xrefs_from_item_doubleclicked(self, item, column):
        print(f'From _ Item "{item}" in column {column} was double clicked.')
        if column == 0:
            info = self.gui.get_info()
            ida_kernwin.jumpto(info["address"] + int(item, 16))
        elif column == 1:
            ida_kernwin.jumpto(int(item, 16))

    def on_info_xrefs_to_item_doubleclicked(self, item, column):
        print(f'To _ Item "{item}" in column {column} was double clicked.')
        if column == 0:
            ida_kernwin.jumpto(int(item, 16))
        elif column == 2:
            ida_kernwin.jumpto(int(item, 16))

    def on_potentional_vmt_calls_item_doubleclicked(self, item, column):
        print(f'Vmt _ Item "{item}" in column {column} was double clicked.')
        if column == 0:
            ida_kernwin.jumpto(int(item, 16))


def funkbuster_entry():
    return FunkbusterPlugin()
