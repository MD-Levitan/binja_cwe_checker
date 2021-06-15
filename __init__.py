import json
from binaryninja import *

GHIDRA_BASE_ADDR = 0x100000

def get_addr(addr, bv):
    if len(list(filter(lambda r: addr in range(r.start, r.end), bv.allocated_ranges))) == 0:
        new_addr = addr - GHIDRA_BASE_ADDR
        if len(list(filter(lambda r: new_addr in range(r.start, r.end), bv.allocated_ranges))) == 0:
            return bv.allocated_ranges[0].start
        else:
            return new_addr
    return addr

class BackGroundTask(BackgroundTaskThread):
    def __init__(self, bv):
        self.bv = bv
        self.cwe_tag = self.bv.create_tag_type("CWE", "!")

    def bookmark_cwe(self, address, text):
        self.bv.create_user_data_tag(address, self.cwe_tag, text)

    def comment_cwe(self, address, text):
        self.bv.set_comment_at(address, text)

    def parse_warnings(self, warnings):
        bv = self.bv
        for warning in warnings:
            if len(warning['addresses']) == 0:
                cwe_text =  '[' + warning['name'] + '] ' + warning['description']
                address = bv.allocated_ranges[0].start
                
                self.bookmark_cwe(address, cwe_text)
                self.comment_cwe(address, cwe_text)
            else:
                address_string = warning['addresses'][0]
                address = get_addr(int(address_string, 16), bv)
                self.bookmark_cwe(address, warning['description'])
                self.comment_cwe(address, warning['description'])

    def parse_file(self, filepath):
        try:
            self.file = open(filepath, "r")
        except Exception as e:
            return False, "Failed to open output file: \"{}\"".format(filepath)
        
        try:
            warnings = json.loads(self.file.read())
            self.parse_warnings(warnings)
        except Exception as e:
            return False, str(e)

        return True, None

    def run(self):
        filepath = OpenFileNameField("cwe_checker output file: ")
        get_form_input([filepath], "Select file containing cwe_checker output")
        filepath = filepath.result

        status, message = self.parse_file(filepath)
        if status is False:
            show_message_box("cwe_checker", message)
            return



def load(bv):
    BackGroundTask(bv).run()


def initialize_ui():
    PluginCommand.register(
        "CWE checker",
        "Load CWE checker", load)
    

initialize_ui()