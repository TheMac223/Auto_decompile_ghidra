from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import Function
from java.io import FileWriter, BufferedWriter

exclude_func = [
    '_start', 'deregister_tm_clones', 'register_tm_clones',
    '__do_global_dtors_aux', 'frame_dummy', '__libc_csu_init', '__libc_csu_fini',
    '_fini', '_init', '__gmon_start__'
]

def decompile_functions():
    decomp_interface = DecompInterface()
    decomp_interface.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()

    results = []
    function_manager = currentProgram.getFunctionManager()
    functions = function_manager.getFunctions(True)

    while functions.hasNext() and not monitor.isCancelled():
        function = functions.next()
        function_name = function.getName()
        
        if function_name in exclude_func:
            continue

        try:
            decompiled_function = decomp_interface.decompileFunction(function, 30, monitor)
            if decompiled_function.decompileCompleted():
                results.append("// Function: {}\n{}\n".format(function_name, decompiled_function.getDecompiledFunction().getC()))
            else:
                print("Failed to decompile function: {}".format(function_name))
        except Exception as e:
            print("Error decompiling function {}: {}".format(function_name, e))

    decomp_interface.dispose()
    return results

def save_decompiled_code(decompiled_code, output_file):
    writer = BufferedWriter(FileWriter(output_file))
    try:
        for code in decompiled_code:
            writer.write(code)
    finally:
        writer.close()

output_file = "{}_decompiled.c".format(currentProgram.getExecutablePath())
decompiled_code = decompile_functions()
save_decompiled_code(decompiled_code, output_file)
print("Decompiled code saved to {}".format(output_file))
