# Output function names to a CSV file
#
# @category vlsi
#


from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
from collections import OrderedDict
import json
import os

# Output file location
OUTPUT_FILE = "/mnt/linuxstorage/vlsi-open-source-tool/src_analyzer/output/dec_function_details.json"

def get_data_type_size(data_type):
    """
    Get the size of the data type, using standard C/C++ sizes as a fallback if necessary.
    """
    if data_type is None:
        return 0

    try:
        return data_type.getLength()  # Get length from Ghidra data type if available
    except:
        # Standard sizes in bytes for common C/C++ data types as a fallback
        standard_sizes = {
            "int": 4, "short": 2, "long": 8, "char": 1, "float": 4, "double": 8,
            "long long": 8, "unsigned int": 4, "unsigned short": 2,
            "unsigned long": 8, "unsigned char": 1, "void": 0, "_Bool": 1
        }
        return standard_sizes.get(data_type.getName().lower(), 0)

def gather_function_details(function, basicBlockModel, monitor):
    if not function:
        print("No function was provided.")
        return None

    details = OrderedDict()
    details["function_name"] = function.getName()
    
    # Gather parameter and local variable details
    num_parameters = len(function.getParameters())
    param_stack_size = sum(get_data_type_size(param.getDataType()) for param in function.getParameters())
    local_var_stack_size = sum(get_data_type_size(var.getDataType()) for var in function.getLocalVariables())
    num_local_variables = len(function.getLocalVariables())
    
    # Basic block calculation
    blocks = basicBlockModel.getCodeBlocksContaining(function.getBody(), monitor)
    num_basic_blocks = sum(1 for _ in blocks)
    
    # Adding calculated values to the ordered dictionary
    details["number_of_parameters"] = num_parameters
    details["total_parameter_stack_size_bytes"] = param_stack_size
    details["total_local_variable_stack_size_bytes"] = local_var_stack_size
    details["total_local_variables"] = num_local_variables
    details["number_of_meaningful_basic_blocks"] = num_basic_blocks
             
    # # of parameters, parameter stack size, local variable stack size, # of local variables,# of basic blocks
    details["vector"] = [
        num_parameters,
        param_stack_size,
        local_var_stack_size,
        num_local_variables,
        num_basic_blocks
    ]

    return details

def save_to_json(data):
    if not data:
        return

    output_dir = os.path.dirname(OUTPUT_FILE)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(OUTPUT_FILE, 'w') as jsonfile:
        json.dump(data, jsonfile, indent=4)

    print("Data has been saved to: {}".format(OUTPUT_FILE))

def main():
    print("Starting function details extraction...")
    data = []
    function_manager = currentProgram.getFunctionManager()
    functions = function_manager.getFunctions(True)  # True to iterate forward
    basicBlockModel = BasicBlockModel(currentProgram)
    monitor = ConsoleTaskMonitor()
    for function in functions:
        if function.getSymbol().getSource() != SourceType.DEFAULT:
            # Only process user-defined or imported functions
            function_details = gather_function_details(function, basicBlockModel, monitor)
            if function_details:
                data.append(function_details)

    save_to_json(data)
    print("Function details extraction completed.")
# Entry point
if __name__ == "__main__":
    main()