#!/usr/bin/env python3
"""
F-22 - Safe educational metasploit-like console (single file)
Fixed optparse '-tt' issue: supports both '--tt' and legacy '-tt' via argv check.
"""
from optparse import OptionParser
import sys
import shlex
import os
import time
import textwrap

# ----------------------------
# Module system (safe stubs)
# ----------------------------
class ModuleBase:
    name = "base"
    description = "Base module"
    options = {}

    def __init__(self):
        self.opts = {k: v["value"] for k, v in self.options.items()}

    def set_option(self, key, value):
        if key in self.opts:
            self.opts[key] = value
            return True, f"Set {key} => {value}"
        return False, f"No such option: {key}"

    def show_options(self):
        lines = []
        for k,v in self.options.items():
            val = self.opts.get(k, v["value"])
            lines.append(f"{k}\t{val}\t{'yes' if v.get('required') else 'no'}\t{v.get('desc','')}")
        return "\n".join(lines)

    def run(self):
        raise NotImplementedError("Module must implement run()")

class BufferOverflowSim(ModuleBase):
    name = "buffer_overflow"
    description = "Simulated buffer overflow test payload generator (safe)"
    options = {
        "RHOST": {"value": "127.0.0.1", "required": False, "desc": "Target host (NOT used)"},
        "RPORT": {"value": "9999", "required": False, "desc": "Target port (NOT used)"},
        "LHOST": {"value": "", "required": False, "desc": "Local host (NOT used)"},
        "LPORT": {"value": "", "required": False, "desc": "Local port (NOT used)"},
        "OFFSET": {"value": "0", "required": False, "desc": "Offset (for simulation)"},
        "PAYLOAD_LEN": {"value": "512", "required": True, "desc": "Length of test payload (bytes)"},
        "PATTERN": {"value": "pattern", "required": False, "desc": "pattern|repeat"},
        "OUTFILE": {"value": "f22_payload.bin", "required": False, "desc": "Where to save payload (optional)"},
    }

    def generate_pattern(self, n):
        parts = []
        for a in range(65, 91):
            for b in range(97, 123):
                for c in range(48, 58):
                    parts.append(chr(a) + chr(b) + chr(c))
                    if len(parts)*3 >= n:
                        return ("".join(parts))[:n].encode('ascii', errors='ignore')
        return ("".join(parts))[:n].encode('ascii', errors='ignore')

    def generate_repeat(self, n, byte=b'A'):
        return (byte * n)

    def run(self):
        try:
            length = int(self.opts.get("PAYLOAD_LEN", "0"))
        except ValueError:
            return False, "PAYLOAD_LEN must be an integer."
        if length <= 0:
            return False, "PAYLOAD_LEN must be > 0."

        pattern_type = self.opts.get("PATTERN", "pattern")
        if pattern_type == "pattern":
            payload = self.generate_pattern(length)
        else:
            payload = self.generate_repeat(length, byte=b'X')

        outfile = self.opts.get("OUTFILE", "").strip()
        if outfile:
            try:
                with open(outfile, "wb") as f:
                    f.write(payload)
                saved = f"Payload written to {outfile} ({len(payload)} bytes)."
            except Exception as e:
                saved = f"Failed to write payload to {outfile}: {e}"
        else:
            saved = "No outfile specified; payload not saved."

        preview_hex = payload[:64].hex()
        preview_ascii = payload[:64].decode('ascii', errors='replace')
        report = f"""[SIMULATION] Module: {self.name}
Description: {self.description}

Payload length: {len(payload)} bytes
Preview (hex, first 64 bytes): {preview_hex}
Preview (ascii, first 64 bytes): {preview_ascii}
{saved}

NOTE: This is a SIMULATION. No network action was taken.
"""
        return True, report

MODULES = {
    BufferOverflowSim.name: BufferOverflowSim,
}

# ----------------------------
# Console UI
# ----------------------------
class F22Console:
    PROMPT = "F-22> "

    def __init__(self):
        self.current_module = None
        self.modules = MODULES
        self.running = True

    def banner(self):
        b = r"""
        
        
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⡆⠀⢀⡀⣀⢀⡀⠀⠀⣀⢀⡀⣀⠀⢠⣿⣿⠏⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠚⠯⠥⠤⢤⣉⣉⡉⠉⠉⠉⢩⣿⣿⣿⣾⠁⠀⠘⠿⣿⣷⣿⡇⠈⢀⣠⣽⣯⡸⣿⣿⣭⣳⠀⣀⣠⡤⠭⠟⠛⠛⠃⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣀⣤⡤⠴⣶⠶⣶⠶⠟⢛⣒⠿⠿⠿⠿⠿⠿⢿⣏⠙⠒⠒⠒⠒⠒⢹⡿⢛⣉⡄⠀⠀⠀⠀⢾⣿⣿⣷⡆⠀⠈⠏⣿⣿⣿⣿⡛⠟⡿⠿⠿⠿⠿⠿⣿⣿⣯⠀⠉⠉⡟⣽⢿⣿⠷⣾⣶⣶⣤⡤⣄⠀
⣯⣆⣤⣤⣴⠦⢤⣤⣤⣄⣉⠁⠈⠉⠉⠉⠒⠉⠁⠀⠀⠀⠀⢐⣀⢼⡿⢭⡇⠀⠀⣀⣠⣴⡿⢇⢈⣿⣿⣦⣄⣐⣤⣹⣿⣿⣿⣤⣿⡀⣀⡀⠀⠀⢀⣀⣀⣠⣤⣤⠤⢤⣴⣶⣿⣿⡿⠿⠿⠿⠛⠂
⠀⠀⠈⠋⠉⠙⠓⠒⠒⠒⠒⠛⠿⠷⠴⠤⠤⠤⠆⠠⠤⣄⣶⣤⡤⠌⠐⠋⠀⠐⠁⢸⣾⣿⣿⡿⢺⣿⣿⣿⣿⣧⣭⣛⣯⣽⣿⡷⣾⠿⠿⠿⠯⠭⠿⠗⠒⠚⠛⠛⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢇⡇⠀⡤⠚⠁⢰⣾⣿⣼⣾⣇⢸⣿⣿⣿⣿⣿⣯⡏⢿⣿⠻⢿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⢴⣦⣤⣤⣭⣧⡟⡟⠻⡿⡟⢻⣿⣿⣿⣿⣿⣿⣯⣭⣭⣭⡿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣿⣿⣿⣿⣧⢀⠀⠀⠀⠀⠉⢹⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⣮⠀⣢⠔⠊⡑⢸⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢧⣁⣤⡘⢇⣾⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠷⣾⠟⠁⠀⠀⠀
"""
        print(b)

    def help_text(self):
        return textwrap.dedent("""
        Commands:
          help                     Show this help
          show modules             List available modules
          use <module>             Select a module
          show options             Show options for current module
          set <option> <value>     Set an option for current module
          run                      Run the current module (SIMULATION only)
          back                     Deselect module
          exit / quit              Exit F-22
        Global CLI flag: --tt or -tt (legacy)     auto-run buffer_overflow simulation
        """)

    def cmd_show_modules(self):
        print("Available modules:")
        for name, cls in self.modules.items():
            print(f"  {name}\t- {cls.description}")

    def cmd_use(self, args):
        if not args:
            print("use what? try: use buffer_overflow")
            return
        name = args[0]
        if name not in self.modules:
            print(f"Module not found: {name}")
            return
        self.current_module = self.modules[name]()
        print(f"Module {name} selected. Type 'show options' to view module options.")

    def cmd_show_options(self):
        if not self.current_module:
            print("No module selected. Use 'use <module>'.")
            return
        print("Options:\nname\tcurrent\trequired\tdescription")
        print(self.current_module.show_options())

    def cmd_set(self, args):
        if not self.current_module:
            print("No module selected.")
            return
        if len(args) < 2:
            print("Usage: set <option> <value>")
            return
        opt = args[0]
        val = " ".join(args[1:])
        ok, msg = self.current_module.set_option(opt, val)
        print(msg)

    def cmd_run(self):
        if not self.current_module:
            print("No module selected.")
            return
        ok, report = self.current_module.run()
        if ok:
            print(report)
        else:
            print(f"[ERROR] {report}")

    def repl(self):
        self.banner()
        while self.running:
            try:
                line = input(self.PROMPT)
            except (EOFError, KeyboardInterrupt):
                print()
                break
            line = line.strip()
            if not line:
                continue
            parts = shlex.split(line)
            cmd = parts[0].lower()
            args = parts[1:]
            if cmd in ("exit", "quit"):
                self.running = False
            elif cmd == "help":
                print(self.help_text())
            elif cmd == "show":
                if args and args[0] == "modules":
                    self.cmd_show_modules()
                elif args and args[0] == "options":
                    self.cmd_show_options()
                else:
                    print("show what? 'show modules' or 'show options'")
            elif cmd == "use":
                self.cmd_use(args)
            elif cmd == "set":
                self.cmd_set(args)
            elif cmd == "run":
                self.cmd_run()
            elif cmd == "back":
                self.current_module = None
                print("Module deselected.")
            else:
                print(f"Unknown command: {cmd}. Type 'help'.")

# ----------------------------
# Top-level CLI parsing (optparse)
# ----------------------------
def main():
    parser = OptionParser(usage="usage: %prog [options]")
    parser.add_option("-t", "--test", dest="test", action="store_true",
                      help="Quick test (no auto module run).")
    parser.add_option("-T", "--trace", dest="trace", action="store_true",
                      help="Enable trace/debug prints.")
    # valid long option (--tt). We'll also accept legacy '-tt' via argv check below.
    parser.add_option("--tt", dest="auto_run_buffer", action="store_true", default=False,
                      help="Automatically use buffer_overflow module, build payload, and run (SIMULATION).")
    parser.add_option("-o", "--outfile", dest="outfile", metavar="FILE",
                      help="If --tt is used, write payload to FILE (optional).")
    (options, args) = parser.parse_args()

    # Accept legacy single-dash '-tt' if user types it (older habit); set option accordingly.
    if "-tt" in sys.argv and not options.auto_run_buffer:
        options.auto_run_buffer = True

    console = F22Console()

    if options.auto_run_buffer:
        mod = BufferOverflowSim()
        mod.set_option("PAYLOAD_LEN", "1024")
        mod.set_option("PATTERN", "pattern")
        if options.outfile:
            mod.set_option("OUTFILE", options.outfile)
        else:
            default = mod.opts.get("OUTFILE") or "f22_payload.bin"
            if os.path.exists(default):
                suffix = int(time.time())
                default = f"f22_payload_{suffix}.bin"
            mod.set_option("OUTFILE", default)
        ok, report = mod.run()
        print(report)
        print("Auto-run complete (simulation). Exiting.")
        return

    console.repl()
    print("Goodbye. (F-22 exited.)")

if __name__ == "__main__":
    main()
