from vita_phys_dump import VitaPhysDump, Module, ModuleExport, ModuleImport, chunk, u32, add_xrefs


INFO_SIZE = 0x5c
NAME_OFF = 4
NAME_LEN = 27
ENT_TOP_OFF = 0x24
ENT_END_OFF = 0x28
STUB_TOP_OFF = 0x2c
STUB_END_OFF = 0x30


class VirtualModule(Module):

    def __init__(self, ea):
        data = idc.GetManyBytes(ea, 0x400)

        self.name = data[NAME_OFF:NAME_OFF+NAME_LEN].rstrip("\x00")

        ent_len = u32(data, ENT_END_OFF) - u32(data, ENT_TOP_OFF)
        stub_len = u32(data, STUB_END_OFF) - u32(data, STUB_TOP_OFF)

        self.exports_start = ea + INFO_SIZE
        self.exports_end = self.exports_start + ent_len
        self.imports_start = self.exports_end
        self.imports_end = self.imports_start + stub_len

        self.exports = self._parse_arr(self.exports_start, self.exports_end, ModuleExport)
        self.imports = self._parse_arr(self.imports_start, self.imports_end, ModuleImport)



class VitaDump(VitaPhysDump):

    def find_modules(self):
        module_heur = [
            ("\x00\x00\x01Sce", -1),
            ("\x00\x01\x01Sce", -1),
            ("\x00\x02\x01Sce", -1),
            ("\x00\x06\x01Sce", -1),
            ("\x00\x00\x00UnityPlayer", -1),
        ]
        for haystack, off in module_heur:
            ea = 0
            c = " ".join(chunk(haystack.encode("hex"), 2))
            while ea != BADADDR:
                ea = FindBinary(ea, SEARCH_DOWN | SEARCH_CASE, c)
                if ea != BADADDR:
                    self.modules.append(VirtualModule(ea + off))
                ea = NextAddr(ea)

    def go(self):
        print "0) Loading NIDs"
        self.load_nids()

        print "1) Finding modules"
        self.find_modules()

        print "2) Resolving imports/exports"
        self.resolve_impexp()

        print "3) Waiting for IDA to analyze the program, this will take a while..."
        idc.Wait()

        print "4) Analyzing system instructions"
        from highlight_arm_system_insn import run_script
        run_script()

        print "5) Adding MOVT/MOVW pair xrefs"
        add_xrefs()


e = VitaDump(None)
e.go()
