import idaapi
import idc

import struct
from collections import defaultdict


################################################################################
# Constants
################################################################################

VITA_MAGIC = "18F09FE518F09FE518F09FE518F09FE518F09FE504F09FE514F09FE514F09FE5".decode("hex")

dump_start = 0x40200000
dump_end = 0x5FD00000
ttbr0 = dump_start + 0x8000
ttbr1 = dump_start + 0xC000
ttbcr_n = 2

DEBUG = True

NORETURN_NIDS = [0xB997493D, 0x391B5B74, 0x00CCE39C, 0x37691BF8, 0x2F2C6046, 0x39AD080B, 0x83A4F46F, 0xB1CD7AC2,
                 0xEC287338]


################################################################################
# Utils
################################################################################

def log(s):
    if DEBUG:
        print s


def _make_unpacker(tag, size):
    def f(data, off=0):
        return struct.unpack("<{}".format(tag), data[off:off+size])[0]
    return f


u8 = _make_unpacker("B", 1)
u16 = _make_unpacker("H", 2)
u32 = _make_unpacker("I", 4)


def p32(x):
    return struct.pack("<I", x)


def pa2off(pa):
    return pa - dump_start


def c_str(addr, max_len=0):
    s = ""
    ea = addr
    while True:
        c = idc.Byte(ea)
        if c == 0:
            break
        ea += 1
        s += chr(c)
        if max_len and len(s) > max_len:
            break
    return s


def chunk(s, l):
    """
        Chunks S into strings of length L, for example:
        >>> chunk("abcd", 2)
        ["ab", "cd"]
        >>> chunk("abcde", 2)
        ['ab', 'cd', 'e']
    """
    return [s[i:i + l] for i in range(0, len(s), l)]


def add_xrefs():
    """
        Searches for MOV / MOVT pair, probably separated by few instructions,
        and adds xrefs to things that look like addresses
    """
    addr = 0
    while addr != idc.BADADDR:
        addr = idc.NextHead(addr)
        if idc.GetMnem(addr) in ["MOV", "MOVW"]:
            reg = idc.GetOpnd(addr, 0)
            if idc.GetOpnd(addr, 1)[0] != "#":
                continue
            val = idc.GetOperandValue(addr, 1)
            found = False
            next_addr = addr
            for x in range(16):
                next_addr = idc.NextHead(next_addr)
                if idc.GetMnem(next_addr) in ["B", "BX"]:
                    break
                # TODO: we could handle a lot more situations if we follow branches, but it's getting complicated
                # if there's a function call and our register is scratch, it will probably get corrupted, bail out
                if idc.GetMnem(next_addr) in ["BL", "BLX"] and reg in ["R0", "R1", "R2", "R3"]:
                    break
                # if we see a MOVT, do the match!
                if idc.GetMnem(next_addr) in ["MOVT", "MOVT.W"] and idc.GetOpnd(next_addr, 0) == reg:
                    if idc.GetOpnd(next_addr, 1)[0] == "#":
                        found = True
                        val += idc.GetOperandValue(next_addr, 1) * (2 ** 16)
                    break
                # if we see something other than MOVT doing something to the register, bail out
                if idc.GetOpnd(next_addr, 0) == reg or idc.GetOpnd(next_addr, 1) == reg:
                    break
            if val & 0xFFFF0000 == 0:
                continue
            if found:
                # pair of MOV/MOVT
                idc.OpOffEx(addr, 1, idc.REF_LOW16, val, 0, 0)
                idc.OpOffEx(next_addr, 1, idc.REF_HIGH16, val, 0, 0)
            else:
                # a single MOV instruction
                idc.OpOff(addr, 1, 0)


def make_func(func, name):
    t_reg = func & 1  # 0 = ARM, 1 = THUMB
    func -= t_reg
    for i in range(4):
        idc.SetReg(func + i, "T", t_reg)
    idc.MakeFunction(func)
    if name:
        idc.MakeName(func, name)


class Chunk:

    def __init__(self, va, sz, ex=False, name=""):
        self.va = va
        self.sz = sz
        self.ex = ex
        self.name = name

    def follows(self, other):
        """ Whether this chunk is a part of the same mapping (follows other) """
        return other.va <= self.va <= other.va + other.sz and self.ex == other.ex


class ModuleSegment:

    def __init__(self, va, sz, perm):
        self.va = va
        self.sz = sz
        self.perm = perm


class ModuleImpexp:

    prefix = "none"

    def __init__(self):
        self.nid_table = None
        self.entry_table = None
        self.libname = None
        self.module = None
        self.num_funcs = None

    def process(self, callback):
        if not self.nid_table:
            assert(not self.entry_table)
            return

        if not self.libname:
            self.libname = "{}_Syslib".format(self.module.name)

        nids = idc.GetManyBytes(self.nid_table, 4 * self.num_funcs)
        funcs = idc.GetManyBytes(self.entry_table, 4 * self.num_funcs)

        pairs = list(zip([u32(x) for x in chunk(nids, 4)], [u32(x) for x in chunk(funcs, 4)]))
        for nid, func in pairs:
            callback(self, func, nid)


class ModuleImport(ModuleImpexp):

    prefix = "imp"

    def __init__(self, data):
        ModuleImpexp.__init__(self)
        if len(data) == 0x24:
            self.num_funcs = u16(data, 0x6)
            self.nid_table = u32(data, 20)
            self.entry_table = u32(data, 24)
            self.libnid = u32(data, 12)
            libname_addr = u32(data, 16)
            self.libname = c_str(libname_addr)
        elif len(data) == 0x34:
            self.num_funcs = u16(data, 0x6)
            self.libnid = u32(data, 16)
            libname_addr = u32(data, 20)
            self.libname = c_str(libname_addr)
            self.nid_table = u32(data, 28)
            self.entry_table = u32(data, 32)
        else:
            raise Exception("unknown len(data) = 0x{:x}".format(len(data)))


class ModuleExport(ModuleImpexp):

    prefix = "exp"

    is_imp = False

    def __init__(self, data):
        ModuleImpexp.__init__(self)
        self.num_funcs = u16(data, 0x6)
        self.nid_table = u32(data, 24)
        self.entry_table = u32(data, 28)
        self.libnid = u32(data, 16)
        libname_addr = u32(data, 20)
        self.libname = c_str(libname_addr) if libname_addr else ""


class Module:

    def __init__(self, data):
        self.name = c_str(u32(data, 0x1C))
        self.prev = u32(data, 0)

        self.segs = []
        self.exports_start = u32(data, 0x20)
        self.exports_end = u32(data, 0x24)
        self.imports_start = u32(data, 0x28)
        self.imports_end = u32(data, 0x2C)

        self.exports = self._parse_arr(self.exports_start, self.exports_end, ModuleExport)
        self.imports = self._parse_arr(self.imports_start, self.imports_end, ModuleImport)

    def _parse_arr(self, start, end, cls):
        out = []
        x = start
        while x < end:
            sz = idc.Byte(x)
            data = idc.GetManyBytes(x, sz)
            c = cls(data)
            c.module = self
            out.append(c)
            x += sz
        return out


################################################################################


class VitaPhysDump:

    def __init__(self, fin):
        self.fin = fin

        self.chunks = []
        self.modules = []
        self.nid_to_name = dict()
        self.comments = defaultdict(list)
        self.used_names = set()
        self.last_module_ptr = None

    def load_nids(self):
        try:
            with open("db.yml", "r") as fin:
                data = fin.read().split("\n")
        except IOError:
            raise Exception("Please place db.yml into the directory with your elfs!")
        for line in data:
            if "0x" in line and "nid: " not in line:
                name, nid = line.strip().split(":")
                name = name.strip()
                nid = int(nid.strip(), 16)
                self.nid_to_name[nid] = name

    def dump_first_level(self):
        for x in xrange(0x1000):
            va = x * 0x100000
            self.fin.seek(pa2off(ttbr0 + 4 * x))
            entry = u32(self.fin.read(4))
            flags = entry & 0b11
            if flags == 0:
                # Fault
                pass
            elif flags == 1:
                # Page table
                log("[0x{:08x}] Page table".format(va))
                self.dump_second_level(va, entry)
            elif flags == 2:
                # Section/supersection
                log("[0x{:08x}] Section".format(va))
                self.dump_section(va, entry)
            elif flags == 4:
                # Reserved
                pass

    def dump_section(self, va, entry):
        # whether it's supersection
        ss = entry & 0x40000
        pa = (entry & 0xFF000000) if ss else (entry & 0xFFF00000)
        sz = 0x1000000 if ss else 0x100000
        xn = entry & 0x10

        self.map_page(pa, va, sz, xn == 0)

    def dump_second_level(self, base_va, entry):
        base_pa = entry & 0xFFFFFC00
        prev = 0xFFFFFFFF
        for x in xrange(0x100):
            self.fin.seek(pa2off(base_pa + 4 * x))
            entry = u32(self.fin.read(4))
            if entry == prev:
                continue
            prev = entry
            va = base_va + 0x1000 * x
            if entry & 0b11 == 1:
                # large page
                pa = entry & 0xFFFF0000
                sz = 0x10000
                xn = entry & 0x8000
            elif entry & 0b10 == 0b10:
                # small page
                pa = entry & 0xFFFFF000
                sz = 0x1000
                xn = entry & 1
            else:
                # unmapped
                continue

            self.map_page(pa, va, sz, xn == 0)
            log("- PA:0x{:08X} VA:0x{:08X} sz=0x{:X}, xn={}".format(pa, va, sz, int(xn != 0)))

    def map_page(self, pa, va, sz, ex):
        """ Loads a part of input file into IDA, src=pa, dst=va. Also creates a corresponding Chunk object. """
        if pa < dump_start or pa > dump_end:
            return
        self.fin.file2base(pa2off(pa), va, va + sz, 1)
        self.chunks.append(Chunk(va, sz, ex))

    def process_chunks(self):
        """ Coalesces chunks and creates IDA segments """
        self.chunks.sort(key=lambda x: x.va)
        self.chunks.append(Chunk(0xFFFFFFFF, 0))  # fake chunk to never coalesce

        # coalesce chunks
        out = []
        i = 0
        while i < len(self.chunks) - 1:
            j = i + 1
            while self.chunks[j].follows(self.chunks[j - 1]):
                j += 1

            out.append(Chunk(self.chunks[i].va,
                             self.chunks[j - 1].va + self.chunks[j - 1].sz - self.chunks[i].va,
                             self.chunks[i].ex))
            i = j
        self.chunks = out

        # insert chunks for modules
        self.insert_module_chunks()

        # print orphaned chunks (not belonging to any modules)
        for ch in self.chunks:
            if not ch.name and ch.ex:
                print "[orphan executable] va:0x{:x} sz:0x{:x}".format(ch.va, ch.sz)

        # create segments
        for ch in self.chunks:
            idaapi.add_segm(0, ch.va, ch.va + ch.sz, ".text" if ch.ex else ".data", "CODE" if ch.ex else "DATA")
            seg = idaapi.getseg(ch.va)
            if ch.ex:
                seg.perm = idaapi.SEGPERM_EXEC | idaapi.SEGPERM_READ
            else:
                seg.perm = idaapi.SEGPERM_READ | idaapi.SEGPERM_WRITE
                # idc.MakeData(chunk.va, 0, chunk.sz, 0)

    def insert_module_chunks(self):
        ptr = self.last_module_ptr
        while ptr:
            mod = Module(idc.GetManyBytes(ptr, 0x400))
            self.modules.append(mod)

            ptr = mod.prev

    def add_nid_cmt(self, func, cmt):
        func = func & ~1
        self.comments[func].append(cmt)
        idc.set_func_cmt(func, " aka ".join(self.comments[func]), 0)

    def func_get_name(self, prefix, libname, nid):
        if nid in self.nid_to_name:
            suffix = self.nid_to_name[nid]
        else:
            suffix = "0x{:08X}".format(nid)
        name = orig_name = "{}.{}.{}".format(prefix, libname, suffix)
        counter = 1
        while name in self.used_names:
            name = "{}.{}".format(orig_name, counter)
            counter += 1
        self.used_names.add(name)
        return name

    def cb_noret(self, _, func, nid):
        if nid in NORETURN_NIDS:
            make_func(func, None)
            idc.SetFunctionFlags(func, idc.GetFunctionFlags(func) | idaapi.FUNC_NORET)

    def cb_exp(self, exp, func, nid):
        name = self.func_get_name("exp", exp.libname, nid)

        make_func(func, name)

        self.add_nid_cmt(func, "[Export libnid: 0x{:08X} ({}), NID: 0x{:08X}]".format(exp.libnid, exp.libname, nid))

    def cb_imp(self, imp, func, nid):
        name = self.func_get_name("imp", imp.libname, nid)

        make_func(func, name)
        idc.SetFunctionFlags(func, idc.GetFunctionFlags(func) | idaapi.FUNC_THUNK | idaapi.FUNC_LIB)

        self.add_nid_cmt(func, "[Import libnid: 0x{:08X} ({}), NID: 0x{:08X}]".format(imp.libnid, imp.libname, nid))

    def resolve_impexp(self):
        # We want to resolve noret functions first
        for mod in self.modules:
            for impexp in mod.exports:
                impexp.process(self.cb_noret)

        for mod in self.modules:
            for impexp in mod.imports:
                impexp.process(self.cb_noret)

        for mod in self.modules:
            for imp in mod.imports:
                imp.process(self.cb_imp)
            for exp in mod.exports:
                exp.process(self.cb_exp)

    def find_module_ptr(self):
        str_ptr = idc.FindBinary(0, idc.SEARCH_DOWN | idc.SEARCH_CASE, '"SceUIDModuleClass"')
        if str_ptr == idc.BADADDR:
            raise RuntimeError("failed to apply str_ptr heuristic")
        log("stage 1: str_ptr at 0x{:08X}".format(str_ptr))

        haystack = " ".join(chunk(p32(str_ptr).encode("hex"), 2))
        cls_ptr = idc.FindBinary(0, idc.SEARCH_DOWN | idc.SEARCH_CASE, haystack)
        if cls_ptr == idc.BADADDR:
            raise RuntimeError("failed to apply cls_ptr heuristic")
        cls_ptr -= 0xC
        log("stage 2: cls_ptr at 0x{:08X}".format(cls_ptr))

        haystack = " ".join(chunk(p32(cls_ptr).encode("hex"), 2))
        ea = 0
        while True:
            ea = idc.FindBinary(ea, idc.SEARCH_DOWN | idc.SEARCH_CASE, haystack)
            if ea == idc.BADADDR:
                raise RuntimeError("failed to find the last module using the heuristic")
            ptr = idc.Dword(ea + 0x20)
            name = c_str(ptr, 0x20)
            if name == "SceKrm":
                self.last_module_ptr = ea + 4
                log("stage 3: last_module_ptr at 0x{:08X}".format(self.last_module_ptr))
                break

            ea = idc.NextAddr(ea)


    def go(self):
        idaapi.set_processor_type("arm", idc.SETPROC_ALL | idc.SETPROC_FATAL)
        inf = idaapi.get_inf_structure()
        inf.af &= ~idc.AF_MARKCODE  # this is so that IDA does not find functions inside .data segments
        inf.af2 &= ~idc.AF2_FTAIL  # don't create function tails
        inf.af2 |= idc.AF2_PURDAT  # control flow to data segment is ignored

        print "0) Loading NIDs"
        self.load_nids()

        print "1) Mapping kernel VA"
        self.dump_first_level()

        print "2) Finding module table using heuristic"
        self.find_module_ptr()

        print "3) Creating segments"
        self.process_chunks()

        print "4) Resolving imports/exports"
        self.resolve_impexp()

        print "5) Waiting for IDA to analyze the program, this will take a while..."
        idc.Wait()

        print "6) Analyzing system instructions"
        from highlight_arm_system_insn import run_script
        run_script()

        print "7) Adding MOVT/MOVW pair xrefs"
        add_xrefs()


################################################################################
# Loader functions
################################################################################

def accept_file(fin, *args, **kwargs):
    fin.seek(0)
    magic = fin.read(0x20)
    if magic != VITA_MAGIC:
        return 0
    return "PS Vita physical dump"


def load_file(fin, *args, **kwargs):
    e = VitaPhysDump(fin)
    e.go()

    return 1
