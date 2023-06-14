import os
import sys

plugin_subdir = os.path.join(os.path.dirname(__file__), "funkbuster")
sys.path.insert(0, plugin_subdir)
from funkbuster import funkbuster_entry

def PLUGIN_ENTRY():
    return funkbuster_entry()

sys.path.remove(plugin_subdir)
