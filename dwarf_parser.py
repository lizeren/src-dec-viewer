# import json
# from elftools.elf.elffile import ELFFile

# def extract_function_addresses(filename, output_file):
#     with open(filename, 'rb') as f:
#         elffile = ELFFile(f)

#         # Prepare to collect function data
#         functions_data = []

#         # Check if file has DWARF information
#         if not elffile.has_dwarf_info():
#             functions_data.append({"error": "No DWARF info found in this file."})
#         else:
#             # Get DWARF info from the file
#             dwarf_info = elffile.get_dwarf_info()

#             # Iterate over all the Compilation Units (CUs) in the DWARF information
#             for CU in dwarf_info.iter_CUs():
#                 # Each CU contains a tree of DIEs
#                 for DIE in CU.iter_DIEs():
#                     # Check if this DIE represents a subprogram (function)
#                     if DIE.tag == 'DW_TAG_subprogram':
#                         try:
#                             # Retrieve the function name and address range
#                             name = DIE.attributes['DW_AT_name'].value.decode('utf-8')
#                             low_pc = DIE.attributes['DW_AT_low_pc'].value
#                             high_pc = DIE.attributes['DW_AT_high_pc'].value

#                             # High PC might be an offset; calculate end address
#                             if isinstance(high_pc, int):
#                                 high_pc = low_pc + high_pc

#                             # Append function info to the list
#                             functions_data.append({
#                                 "name": name,
#                                 "entry_point": hex(low_pc),
#                                 "end_address": hex(high_pc)
#                             })
#                         except KeyError:
#                             # If any of the expected attributes are missing, skip this entry
#                             continue

#         # Write the collected data to a JSON file
#         with open(output_file, 'w') as out:
#             json.dump(functions_data, out, indent=4)

# if __name__ == '__main__':
#     extract_function_addresses('/mnt/linuxstorage/vlsi-open-source-tool/abc/build/abc', 'output/src_functions_list.json')
#     # extract_function_addresses('/home/lizeren/Downloads/pwgen-2.08/pwgen', 'output/src_functions_list.json')
#     # extract_function_addresses('/home/lizeren/Downloads/curl-8.9.1/build/lib/libcurl.so', 'output/src_functions_list.json')import json
from elftools.elf.elffile import ELFFile
import json
def extract_function_addresses(filename, output_file):
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        functions_data = []

        # Check if the ELF file has a symbol table
        symtab_section = elffile.get_section_by_name('.symtab')
        if symtab_section is None:
            functions_data.append({"error": "No symbol table found in this file."})
        else:
            # Iterate over symbols and extract functions
            for symbol in symtab_section.iter_symbols():
                if symbol['st_info']['type'] == 'STT_FUNC':  # Function symbols only
                    name = symbol.name
                    addr = symbol['st_value']
                    size = symbol['st_size']

                    if name:  # Ensure the function has a valid name
                        functions_data.append({
                            "name": name,
                            "entry_point": hex(addr),
                            "size": hex(size) if size else "Unknown"
                        })

        # Write results to a JSON file
        with open(output_file, 'w') as out:
            json.dump(functions_data, out, indent=4)

if __name__ == '__main__':
    extract_function_addresses('/mnt/linuxstorage/vlsi-open-source-tool/abc/build/abc', 'output/src_functions_list.json')
