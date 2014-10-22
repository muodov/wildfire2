#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
#    wildfire2.py - (kinda) Python bytecode packer (c) 2014 @muodov
#    Original wildfire.py by Axel "0vercl0k" Souchet - http://www.twitter.com/0vercl0k
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import sys
import types
import random
import pprint
import collections
import marshal
import struct
import os
import opcode

def encrypt(s):
    return ''.join(chr((ord(c) + 1) & 0xff) for c in s)

def opcodes_to_bytecode(opcodes):
    """Kind of bytecode compiler \o/"""
    bytecode = ''
    for instr in opcodes:
        if instr[0] in opcode.opmap:
            bytecode += chr(opcode.opmap.get(instr[0]))
            if len(instr) > 1:
                bytecode += struct.pack('<H', instr[1])
        else:
            bytecode += instr[0]
    return bytecode

#tt = 0
def generate_random_strings():
    """Generate a random string"""
    charset = map(chr, range(0, 0x100))
    l = random.randint(10, 100)
    return ''.join(random.choice(charset) for i in range(l))
    #global tt
    #tt += 1
    #return 'randomstring' + str(tt)

def find_absolute_instr(code, i_init=0, end=None):
    """Find in code the instructions that use absolute reference, and
    returns the offsets of those instructions.
    Really useful when you want to relocate a code, you just have to patch
    the 2bytes with your relocation offset."""
    i = i_init
    absolute_refs = []
    if end is None:
        end = len(code)

    while i < end:
        byte = ord(code[i])
        i += 1

        if byte >= opcode.HAVE_ARGUMENT:
            absolute_offset = struct.unpack('<H', code[i:i + 2])[0]
            if byte in opcode.hasjabs:
                absolute_refs.append(i)

            i += 2

    return absolute_refs

class UniqueList(list):
    """Set doens't have a .index method, so here a class doing the job"""
    def append(self, r):
        if not list.__contains__(self, r):
            list.append(self, r)

    def extend(self, it):
        for i in it:
            self.append(i)

def add_encryption_layer(c, name, number_layer, debug=False):
    """Add number_layer layers to the function f"""
    original_bytecode = c.co_code

    encryption_marker = '\xBA\xBA\xBA\xBE'
    names = UniqueList(c.co_names)
    varnames = UniqueList(c.co_varnames)
    consts = UniqueList(c.co_consts)
    decryption_layers = []
    relocation_offset = 0
    absolute_jmp_infos = find_absolute_instr(original_bytecode)

    if debug:
        print '    Instructions with absolute offsets found in the original bytecode: %r' % absolute_jmp_infos
        print '    Preparing all the decryption layers..'
    for _ in range(number_layer):
        varnames_to_obfuscated_varnames = collections.OrderedDict()
        varnames_to_obfuscated_varnames['code'] = generate_random_strings()
        varnames_to_obfuscated_varnames['idx_marker'] = generate_random_strings()
        varnames_to_obfuscated_varnames['code_to_decrypt'] = generate_random_strings()
        varnames_to_obfuscated_varnames['code_decrypted'] = generate_random_strings()
        varnames_to_obfuscated_varnames['memmove'] = generate_random_strings()
        varnames_to_obfuscated_varnames['c_char'] = generate_random_strings()
        varnames_to_obfuscated_varnames['padding_marker'] = generate_random_strings()
        varnames_to_obfuscated_varnames['padding_size'] = generate_random_strings()
        varnames_to_obfuscated_varnames['_getframe'] = generate_random_strings()
        varnames_to_obfuscated_varnames['pack'] = generate_random_strings()

        const_to_obfuscated_const = {
            'MARKER': generate_random_strings()
        }

        names.extend([
            name,
            'ctypes',
            'sys',
            '_getframe',
            'memmove',
            'c_char',
            'func_code',
            'co_code',
            'rfind',
            'id',
            'len',
            'chr',
            'ord',
            'from_address',
            'raw',
            'find',
            'f_code',
            'struct',
            'pack',
        ])

        varnames.extend(varnames_to_obfuscated_varnames.values())

        debug_offset = 9 if debug else 0
        init_jump_offset = 1 + debug_offset
        decryptor_offset = 3 + debug_offset

        consts.extend([
            const_to_obfuscated_const['MARKER'],
            len(const_to_obfuscated_const['MARKER']),
            -1,
            init_jump_offset,
            2,
            decryptor_offset,
            name,
            ('memmove', 'c_char'),
            ('_getframe',),
            ('pack',),
            '',
            0xff,
            'ABCDEFGH',
            100,
            'LAYER_STARTED ',
            'LAYER_DECRYPTED ',
            chr(opcode.opmap['JUMP_FORWARD']),
            '<H',
        ])

        if debug:
            stub_decrypt_instrs = [
                # print 'LAYER_STARTED'
                ('LOAD_CONST', consts.index('LAYER_STARTED ')),
                ('LOAD_CONST', consts.index(name)),
                ('BINARY_ADD',),
                ('PRINT_ITEM',),
                ('PRINT_NEWLINE',),
            ]
        else:
            stub_decrypt_instrs = []

        stub_decrypt_instrs += [

            ('JUMP_FORWARD', len(encryption_marker)),
            (encryption_marker, ),

            # from ctypes import memmove, c_char
            ('LOAD_CONST', consts.index(-1)),                               # __import__ level argument
            ('LOAD_CONST', consts.index(('memmove', 'c_char'))),            # __import__ fromlist argument
            ('IMPORT_NAME', names.index('ctypes')),
            ('IMPORT_FROM', names.index('memmove')),
            ('STORE_FAST', varnames.index(varnames_to_obfuscated_varnames['memmove'])),
            ('IMPORT_FROM', names.index('c_char')),
            ('STORE_FAST', varnames.index(varnames_to_obfuscated_varnames['c_char'])),
            ('POP_TOP', ),

            # from sys import _getframe
            ('LOAD_CONST', consts.index(-1)),                               # __import__ level argument
            ('LOAD_CONST', consts.index(('_getframe',))),                   # __import__ fromlist argument
            ('IMPORT_NAME', names.index('sys')),
            ('IMPORT_FROM', names.index('_getframe')),
            ('STORE_FAST', varnames.index(varnames_to_obfuscated_varnames['_getframe'])),
            ('POP_TOP', ),

            # code = _getframe().f_code.co_code
            # original: code = decryption_layer.func_code.co_code
            # original: ('LOAD_GLOBAL', names.index(name)),
            #           ('LOAD_ATTR', names.index('func_code')),
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['_getframe'])),
            ('CALL_FUNCTION', 0),
            ('LOAD_ATTR', names.index('f_code')),

            ('LOAD_ATTR', names.index('co_code')),
            ('STORE_FAST', varnames.index(varnames_to_obfuscated_varnames['code'])),
        ]

        if debug:
            stub_decrypt_instrs += [
                # print id(code)
                ('LOAD_GLOBAL', names.index('id')),
                ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['code'])),
                ('CALL_FUNCTION', 1),
                ('PRINT_ITEM',),
                ('PRINT_NEWLINE',),
            ]

        stub_decrypt_instrs += [

            # from struct import pack
            ('LOAD_CONST', consts.index(-1)),                               # __import__ level argument
            ('LOAD_CONST', consts.index(('pack',))),                   # __import__ fromlist argument
            ('IMPORT_NAME', names.index('struct')),
            ('IMPORT_FROM', names.index('pack')),
            ('STORE_FAST', varnames.index(varnames_to_obfuscated_varnames['pack'])),
            ('POP_TOP', ),

            # padding_marker = 'ABCDEFGH'
            ('LOAD_CONST', consts.index('ABCDEFGH')),
            ('STORE_FAST', varnames.index(varnames_to_obfuscated_varnames['padding_marker'])),

            # padding_size = (c_char * 100).from_address(id(padding_marker)).raw.find(padding_marker)
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['c_char'])),
            ('LOAD_CONST', consts.index(100)),
            ('BINARY_MULTIPLY', ),
            ('LOAD_ATTR', names.index('from_address')),
            ('LOAD_GLOBAL', names.index('id')),
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['padding_marker'])),
            ('CALL_FUNCTION', 1),
            ('CALL_FUNCTION', 1),
            ('LOAD_ATTR', names.index('raw')),
            ('LOAD_ATTR', names.index('find')),
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['padding_marker'])),
            ('CALL_FUNCTION', 1),
            ('STORE_FAST', varnames.index(varnames_to_obfuscated_varnames['padding_size'])),


            # idx_marker = code.rfind('MARKER')
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['code'])),
            ('LOAD_ATTR', names.index('rfind')),
            ('LOAD_CONST', consts.index(const_to_obfuscated_const['MARKER'])),
            ('CALL_FUNCTION', 1),
            ('STORE_FAST', varnames.index(varnames_to_obfuscated_varnames['idx_marker'])),

            # code_to_decrypt = code[idx_marker + len(MARKER) : ]
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['code'])),
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['idx_marker'])),
            ('LOAD_CONST', consts.index(len(const_to_obfuscated_const['MARKER']))),
            ('BINARY_ADD', ),
            # Implements TOS = TOS1[TOS:]
            ('SLICE+1', ),
            ('STORE_FAST', varnames.index(varnames_to_obfuscated_varnames['code_to_decrypt'])),

            # code_decrypted = ''
            ('LOAD_CONST', consts.index('')),
            ('STORE_FAST', varnames.index(varnames_to_obfuscated_varnames['code_decrypted'])),


            # for c in code_to_decrypt:
            #     code_decrypted += chr((ord(c) - 1) & 0xff)
            ('SETUP_LOOP', 1),
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['code_to_decrypt'])),
            ('GET_ITER', ),

            ('FOR_ITER', 33),
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['code_decrypted'])),
            ('ROT_TWO', ),
            ('LOAD_GLOBAL', names.index('chr')),
            ('ROT_TWO', ),
            # ord(c)
            ('LOAD_GLOBAL', names.index('ord')),
            ('ROT_TWO', ),
            ('CALL_FUNCTION', 1),
            # + (-1)
            ('LOAD_CONST', consts.index(-1)),
            ('BINARY_ADD', ),
            # & 0xff
            ('LOAD_CONST', consts.index(0xff)),
            ('BINARY_AND', ),
            # chr()
            ('CALL_FUNCTION', 1),
            # code_decrypted += chr()
            ('BINARY_ADD', ),
            ('STORE_FAST', varnames.index(varnames_to_obfuscated_varnames['code_decrypted'])),
            # original: ('JUMP_ABSOLUTE', 126),
            ('JUMP_ABSOLUTE', 161 + debug_offset + (11 if debug else 0)),
            ('POP_BLOCK', ),

            # memmove(id(code) + padding_size + idx_marker + len(marker), code_decrypted, len(code_decrypted))
            # id(code)
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['memmove'])),
            ('LOAD_GLOBAL', names.index('id')),
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['code'])),
            ('CALL_FUNCTION', 1),

            # + padding_size
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['padding_size'])),
            ('BINARY_ADD', ),
            # + idx_marker
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['idx_marker'])),
            ('BINARY_ADD', ),
            # + len(marker)
            ('LOAD_CONST', consts.index(len(const_to_obfuscated_const['MARKER']))),
            ('BINARY_ADD', ),
            # Push code_decrypted
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['code_decrypted'])),
            # len(code_decrypted)
            ('LOAD_GLOBAL', names.index('len')),
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['code_decrypted'])),
            ('CALL_FUNCTION', 1),
            # memmove call!
            ('CALL_FUNCTION', 3),
            ('POP_TOP', ),

            # patch jump argument to prevent further decryptions
            # memmove(id(code) + padding_size + init_jump_offset, struct.pack('<H', idx_marker + len(marker) - decryptor_offset), 2)
            # id(code)
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['memmove'])),
            ('LOAD_GLOBAL', names.index('id')),
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['code'])),
            ('CALL_FUNCTION', 1),
            # + padding_size
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['padding_size'])),
            ('BINARY_ADD', ),
            # + init_jump_offset
            ('LOAD_CONST', consts.index(init_jump_offset)),
            ('BINARY_ADD', ),
            # push pack function
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['pack'])),
            # '<H'
            ('LOAD_CONST', consts.index('<H')),
            # idx_marker + len(marker) - decryptor_offset
            ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['idx_marker'])),
            ('LOAD_CONST', consts.index(len(const_to_obfuscated_const['MARKER']))),
            ('BINARY_ADD', ),
            ('LOAD_CONST', consts.index(decryptor_offset)),
            ('BINARY_SUBTRACT', ),
            # pack call
            ('CALL_FUNCTION', 2),
            # 2
            ('LOAD_CONST', consts.index(2)),
            # memmove call!
            ('CALL_FUNCTION', 3),
            ('POP_TOP', ),
        ]
        if debug:
            stub_decrypt_instrs += [
                # print id(code)
                ('LOAD_GLOBAL', names.index('id')),
                ('LOAD_FAST', varnames.index(varnames_to_obfuscated_varnames['code'])),
                ('CALL_FUNCTION', 1),
                ('PRINT_ITEM',),
                ('PRINT_NEWLINE',),
            ]

        if debug:
            stub_decrypt_instrs += [

                # print 'LAYER_DECRYPTED ' + name
                ('LOAD_CONST', consts.index('LAYER_DECRYPTED ')),
                ('LOAD_CONST', consts.index(name)),
                ('BINARY_ADD',),
                ('PRINT_ITEM',),
                ('PRINT_NEWLINE',),
            ]

        stub_decrypt_instrs += [
            # jump over the marker
            ('JUMP_FORWARD', len(const_to_obfuscated_const['MARKER'])),
            (const_to_obfuscated_const['MARKER'], )
        ]

        stub_decrypt_opcodes = opcodes_to_bytecode(stub_decrypt_instrs)

        relocation_offset += len(stub_decrypt_opcodes)
        decryption_layers.append(bytearray(stub_decrypt_opcodes))

    # First, patch the absolute references in the original bytecode
    # Note: the original_relocated_bytecode is valid only when it will be prepended by the X layerz
    if debug:
        print '    Relocate the original bytecode (size of all the stubs: %d bytes)' % relocation_offset
    original_relocated_bytecode = bytearray(original_bytecode)

    for patch_offset in absolute_jmp_infos:
        if debug:
            print '    Patching absolute instruction at offset %.8x' % patch_offset
        off = struct.unpack(
            '<H',
            str(original_relocated_bytecode[patch_offset:patch_offset + 2])
        )[0]
        off += relocation_offset
        original_relocated_bytecode[patch_offset:patch_offset + 2] = struct.pack('<H', off)

    # Why 7? It's the size of the 2 first instruction of our payload
    # We don't want to desynchronize our "disassembler"
    # Let's find absolute instruction only in the 170 first bytes, we don't want to
    # search stuff in the final marker ;)
    absolute_jmps_stub = find_absolute_instr(
        str(decryption_layers[0]),
        7 + debug_offset,
        # original: 170
        209 + debug_offset + 11
    )
    stub_relocation_offset = 0
    for layer in reversed(decryption_layers):
        for patch_offset in absolute_jmps_stub:
            off = struct.unpack(
                '<H',
                str(layer[patch_offset:patch_offset + 2])
            )[0]

            off += stub_relocation_offset
            layer[patch_offset:patch_offset + 2] = struct.pack('<H', off)

        stub_relocation_offset += len(layer)

    if debug:
        print '    Now assemble the layers..'

    final_bytecode = str(original_relocated_bytecode)
    for layer in decryption_layers:
        final_bytecode = str(layer) + encrypt(final_bytecode)

    if debug:
        print '    Final payload size: %d' % len(final_bytecode)

    return types.CodeType(
        c.co_argcount, len(varnames), max(c.co_stacksize, 10), c.co_flags,
        final_bytecode,
        tuple(consts), tuple(names), tuple(varnames),
        c.co_filename, c.co_name, c.co_firstlineno, c.co_lnotab,
        c.co_freevars, c.co_cellvars
    )

def main(argc, argv):
    if len(argv) < 2:
        print 'Usage: %s <original_pyc_file> [debug]' % argv[0]
        sys.exit(1)
    fname = argv[1]
    debug = argv[2] == 'debug' if len(argv) > 2 else False
    if debug:
        random.seed(0)
    fcont = open(fname).read()
    prefix = fcont[:8]
    co = marshal.loads(fcont[8:])
    del(fcont)
    callables = []
    for i, c in enumerate(co.co_consts):
        if isinstance(c, types.CodeType):
            callables.append((i, c))
    if debug:
        print 'found codeobjects in co_consts:'
        pprint.pprint(callables)

    new_consts = list(co.co_consts)

    for i, c in callables:
        if debug:
            print 'processing (%d, %s)' % (i, c)
        new_c = add_encryption_layer(c, c.co_name, 1, debug=debug)
        new_consts[i] = new_c

    new_co = types.CodeType(
        co.co_argcount, len(co.co_varnames), co.co_stacksize, co.co_flags,
        co.co_code,
        tuple(new_consts), co.co_names, co.co_varnames,
        co.co_filename, co.co_name, co.co_firstlineno, co.co_lnotab
    )

    tname = os.path.split(fname)
    print 'saving original file as old_%s' % tname[1]
    os.rename(fname, os.path.join(tname[0], 'old_' + tname[1]))
    if debug:
        print 'writing %s...' % fname
    with open(fname, 'w') as f:
        f.write(prefix)
        f.write(marshal.dumps(new_co))


if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))
