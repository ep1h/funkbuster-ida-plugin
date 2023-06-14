import atexit
import idaapi

ui_hooks = 0

def init(on_click_callback):
    # Register the custom action
    action_desc = idaapi.action_desc_t(
        'custom_action_name',
        'Funkbuster: inspect function',
        IDAActionHandler(on_click_callback),
        "Ctrl+F3",
        'Custom Action Tooltip',
        -1,
    )
    idaapi.register_action(action_desc)
    global ui_hooks
    ui_hooks = IDAUIHooks()
    ui_hooks.hook()
    atexit.register(unhook_ui_hooks)

class IDAActionHandler(idaapi.action_handler_t):
    def __init__(self, on_click):
        idaapi.action_handler_t.__init__(self)
        self.on_click = on_click

    def activate(self, ctx):
        self.on_click()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET
        if ctx.widget_type == idaapi.BWN_FUNCS:
            return idaapi.AST_ENABLE_FOR_WIDGET
        else:
            return idaapi.AST_DISABLE_FOR_WIDGET

class IDAUIHooks(idaapi.UI_Hooks):
    def populating_widget_popup(self, widget, popup):
        idaapi.attach_action_to_popup(widget, popup, 'custom_action_name')

def unhook_ui_hooks():
    global ui_hooks
    ui_hooks.unhook()
