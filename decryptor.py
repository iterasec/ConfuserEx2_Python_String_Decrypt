def _initializer() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-d', '--dir', type=str, help="Specify target directory where obfuscated files are located")
    target_group.add_argument('-f', '--file', type=str, help="Specify a single obfuscated target file")
    parser.add_argument('-e', '--extension', type=str, required=False, help="Use together with the --dir option to filter out target files by extension")
    parser.add_argument('-o', '--output', type=str, required=False, help="Output directory for deobfuscated files")
    parser.add_argument('-l', '--dnlibpath', type=str, required=True, help="Specify where precompiled dnlib dependency is located")
    parser.add_argument('-s', '--powershellpath', type=str, required=False, help="Optional powershell path argument")
    verbosity_group = parser.add_mutually_exclusive_group(required=False)
    verbosity_group.add_argument('-q', '--quite', action='store_true', help="A flag to toggle quite mode")
    verbosity_group.add_argument('-v', '--verbose', action='store_true', help="A flag to toggle verbose mode")
    global args
    args = parser.parse_args()
_initializer()


import clr
clr.AddReference(args.dnlibpath)
from dnlib.DotNet import *
from dnlib.DotNet.Emit import OpCodes, Instruction
from os import remove as remove_file
import dnlib
import subprocess
import os
import logging
import glob


def patch_string(instructions, index, decrypted_str, *str_instructions) -> int:
    if len(str_instructions) != 3:
        return 0
    if str_instructions[0].GetSize() != 5:
        return 0
    str_instructions[0].OpCode = OpCodes.Ldstr
    str_instructions[0].Operand = decrypted_str
    nop_instruction = Instruction.Create(OpCodes.Nop)
    nop_range = str_instructions[1].GetSize() + str_instructions[2].GetSize()
    for _ in range(len(str_instructions) - 1):
        instructions.RemoveAt(index+1)
    for _ in range(nop_range):
        instructions.Insert(index+1, nop_instruction)
    return nop_range


def decrypt_i4(value, mdtoken, target) -> str:
    powershellpath = 'powershell.exe'
    if args.powershellpath is not None:
        powershellpath = args.powershellpath
    loadfile = f' -Command "[Reflection.Assembly]::LoadFile(\'{target}\')'
    resolve_method = f'.ManifestModule.ResolveMethod({mdtoken})'
    invoke_method = f'.MakeGenericMethod([string]).Invoke($null, @({value}))"'
    cmd = powershellpath + loadfile + resolve_method + invoke_method
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    result = p.communicate()
    try:
        decrypted_str = result[0].decode()
        new_line_carriage_return = -2
        return decrypted_str[:new_line_carriage_return]
    except UnicodeDecodeError as e:
        logging.error(f'Failed to decode a string. {e}')


def get_mdtoken_from_method(method_name, method_to_mdtoken) -> str:
    for method in method_to_mdtoken:
        if method_name in method:
            return method_to_mdtoken[method]


def decrypt_strings(instructions, method_to_mdtoken, target) -> None:
    i = 0
    while i < len(instructions)-3:
        instruction1 = instructions[i]
        instruction2 = instructions[i+1]
        instruction3 = instructions[i+2]
        instruction3_str = instruction3.ToString()
        # change the signature if a bug is encountered
        if instruction1.OpCode.Code == OpCodes.Ldc_I4.Code and \
           instruction2.OpCode.Code == OpCodes.Br_S.Code and \
           instruction3.OpCode.Code == OpCodes.Call.Code and \
           'System.String <Module>::' in instruction3_str:
                method_name = instruction3_str.split(':')[3].split('<')[0]
                mdtoken = get_mdtoken_from_method(method_name, method_to_mdtoken)
                instruction1_val_str = str(instruction1.GetLdcI4Value())
                decrypted_str = decrypt_i4(instruction1_val_str, mdtoken, target)
                if decrypted_str is None: break
                logging.debug(f'Decrypted the "{decrypted_str}" string')
                offset = patch_string(
                                     instructions,
                                     i,
                                     decrypted_str,
                                     instruction1,
                                     instruction2,
                                     instruction3
                                     )
                if offset == 0:
                    logging.error(f'Failed to patch string instructions')
                i += offset
        i += 1


def patch_anticall(instructions, index, *anticall_instructions) -> None:
    nop_instruction = Instruction.Create(OpCodes.Nop)
    nop_range = 0
    for anticall_instruction in anticall_instructions:
        nop_range += anticall_instruction.GetSize()
    for _ in range(len(anticall_instructions)):
        instructions.RemoveAt(index)
    for _ in range(nop_range):
        instructions.Insert(index, nop_instruction)


def remove_anticall_protection(instructions) -> None:
    i = 0
    while i < len(instructions)-4:
        instruction1 = instructions[i]
        instruction2 = instructions[i+1]
        instruction3 = instructions[i+2]
        instruction4 = instructions[i+3]
        # change the signature if a bug is encountered
        if instruction1.OpCode.Code == OpCodes.Call.Code and \
           instruction2.OpCode.Code == OpCodes.Call.Code and \
           instruction3.OpCode.Code == OpCodes.Callvirt.Code and \
           'GetExecutingAssembly' in instruction1.ToString() and \
           'GetCallingAssembly' in instruction2.ToString():
                patch_anticall(
                                instructions,
                                i,
                                instruction1,
                                instruction2,
                                instruction3,
                                instruction4
                               )
                logging.debug(f'Removed anticall protection from a protected function')
                break
        i += 1


def process_target_module_decrypt(target) -> str:
    out_path = target + '.decrypted'
    module = ModuleDefMD.Load(target)
    types = module.GetTypes()
    method_to_mdtoken = {}
    for type_ in types:
        methods = type_.Methods
        for method in methods:
            method_to_mdtoken[method.ToString()] = '0x' + method.MDToken.ToString()
        for method in methods:
            if not method.HasBody: continue
            instructions = method.Body.Instructions
            decrypt_strings(instructions, method_to_mdtoken, target)
    logging.debug(f'Writing patched DLL with decrypted strings to {out_path}')
    module.Write(out_path)
    return out_path


def process_target_module_anticall(target, output) -> str:
    out_path = target + '.noanticall'
    if output is not None:
        out_path = output
        out_path += '\\' if output[-1] != '\\' else ''
        out_path += os.path.basename(target) + '.noanticall'
    module = ModuleDefMD.Load(target)
    types = module.GetTypes()
    for type_ in types:
        methods = type_.Methods
        for method in methods:
            if not method.HasBody: continue
            instructions = method.Body.Instructions
            remove_anticall_protection(instructions)
    logging.debug(f'Writing patched DLL with no anticall protection to {out_path}')
    module.Write(out_path)
    return out_path


def log_setup():
    log_level = logging.INFO
    if args.quite:
        log_level = logging.ERROR
    elif args.verbose:
        log_level = logging.DEBUG
    logging.basicConfig(
        level=log_level,
        format='[%(levelname)s] %(message)s',
    )


def main() -> None:
    log_setup()
    files = []
    if args.file is not None:
        files = [args.file]
    elif args.dir is not None and args.extension is not None:
        files = glob.glob(f"{args.dir}\*{args.extension}")
    elif args.dir is not None:
        files = glob.glob(f"{args.dir}\*")
    for target in files:
        logging.info(f'Processing {target}')
        noanticall_dll_path = process_target_module_anticall(target, args.output)
        logging.info(f'Successfully written patched DLL with no anticall protection to {noanticall_dll_path}')
        decrypted_dll_path = process_target_module_decrypt(noanticall_dll_path)
        logging.info(f'Successfully written patched DLL with decrypted strings to {decrypted_dll_path}')


if __name__ == '__main__':
    main()
