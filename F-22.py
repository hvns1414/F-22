#!/usr/bin/env python3
"""
F-22 SAFE FULL (single-file)
- English code, Turkish CLI/help messages
- SIMULATION ONLY: automates fuzz -> pattern -> offset -> badchars -> build -> attack (local only).
- Does NOT perform real exploitation, remote shell, or process injection.
- Attack networking limited to 127.0.0.1 only.
"""
import os, sys, time, socket, threading, collections, math, shlex
from optparse import OptionParser

# -------------------------
# Helpers: pattern, io, entropy
# -------------------------
def cyclic_pattern(length):
    parts = []
    for a in range(65,91):
        for b in range(97,123):
            for c in range(48,58):
                parts.append(chr(a)+chr(b)+chr(c))
                if len(parts)*3 >= length:
                    return ("".join(parts))[:length].encode('ascii', errors='ignore')
    return ("".join(parts))[:length].encode('ascii', errors='ignore')

def repeat_byte(length, byte=b'A'):
    return byte * length

def write_bin(path, data):
    with open(path, "wb") as f:
        f.write(data)
    return path

def read_bin(path):
    with open(path, "rb") as f:
        return f.read()

def entropy(data: bytes):
    if not data:
        return 0.0
    cnt = collections.Counter(data)
    ent = 0.0
    ln = len(data)
    for _, c in cnt.items():
        p = c / ln
        ent -= p * math.log2(p)
    return ent

def find_subseq(hay, needle):
    try:
        return hay.index(needle)
    except ValueError:
        return -1

# -------------------------
# Safe localhost harness
# -------------------------
HOST_LOCAL = "127.0.0.1"

def start_local_harness(port, trigger_prefix=b"TRIGGER_SHELL", max_recv=8192):
    """Start a safe echo server on 127.0.0.1:port. If payload starts with trigger_prefix,
       server responds with F22-SIM-SHELL-OK"""
    def serv():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST_LOCAL, port))
            s.listen(5)
            print(f"[harness] listening on {HOST_LOCAL}:{port} (localhost only)")
            try:
                while True:
                    conn, addr = s.accept()
                    with conn:
                        data = conn.recv(max_recv)
                        if not data:
                            continue
                        if data.startswith(trigger_prefix):
                            conn.sendall(b"F22-SIM-SHELL-OK\n")
                        else:
                            conn.sendall(data[:max_recv])
            except Exception as e:
                print("[harness] stopped:", e)
    t = threading.Thread(target=serv, daemon=True)
    t.start()
    time.sleep(0.05)
    return t

def safe_send_payload(rhost, rport, infile, read_limit=4096, timeout=5.0):
    """Send the payload file to rhost:rport. Only allows 127.0.0.1 for safety."""
    if rhost != HOST_LOCAL:
        raise ValueError("Bu güvenli mod sadece 127.0.0.1 ile çalışır.")
    if not os.path.exists(infile):
        raise FileNotFoundError("Input file not found: " + infile)
    data = read_bin(infile)[:read_limit]
    print(f"[client] read {len(data)} bytes from {infile}")
    print("[client] preview hex:", data[:64].hex())
    with socket.create_connection((rhost, rport), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(data)
        try:
            resp = s.recv(8192)
        except socket.timeout:
            print("[client] timeout waiting for response")
            return False, b""
    print(f"[client] received {len(resp)} bytes from server")
    return (b"F22-SIM-SHELL-OK" in resp), resp

# -------------------------
# Pipeline: fuzz, offset, badchars, build
# -------------------------
class SafeAuto:
    def __init__(self, workdir=".f22_auto"):
        self.workdir = workdir
        os.makedirs(self.workdir, exist_ok=True)

    def fuzz_generate(self, start=100, step=100, maxlen=2000, mode="pattern"):
        od = os.path.join(self.workdir, "fuzz")
        os.makedirs(od, exist_ok=True)
        results = []
        n = start
        while n <= maxlen:
            if mode == "pattern":
                data = cyclic_pattern(n)
            else:
                data = repeat_byte(n)
            fn = os.path.join(od, f"fuzz_{n}.bin")
            write_bin(fn, data)
            results.append((n, fn))
            n += step
        return results

    def generate_pattern(self, length=2000, outfile=None):
        pat = cyclic_pattern(length)
        out = outfile or os.path.join(self.workdir, "pattern.bin")
        write_bin(out, pat)
        return out, len(pat)

    def find_offset_by_eip(self, pattern_file, eip_hex):
        pat = read_bin(pattern_file)
        try:
            eip = bytes.fromhex(eip_hex)
        except Exception as e:
            raise ValueError("EIP must be hex bytes, e.g. 6c413142")
        idx = find_subseq(pat, eip)
        if idx >= 0:
            return idx
        # try reverse
        idx2 = find_subseq(pat, eip[::-1])
        return idx2  # -1 if not found

    def find_pattern_in_hay(self, pattern_file, hay_file):
        pat = read_bin(pattern_file)
        hay = read_bin(hay_file)
        return find_subseq(hay, pat)

    def detect_badchars(self, infile, baseline_file=None):
        data = read_bin(infile)
        if baseline_file:
            baseline = set(read_bin(baseline_file))
            bads = sorted([b for b in set(data) if b not in baseline])
            return bads, entropy(data)
        # heuristic: if one byte >70% => repeat badchar candidate
        cnt = collections.Counter(data)
        most, num = cnt.most_common(1)[0]
        if num / len(data) > 0.7:
            return [most], entropy(data)
        return [], entropy(data)

    def build_exploit(self, offset, payload_len=1024, eip=b"\xDE\xAD\xBE\xEF", shell_stub=None, outfile=None):
        if offset is None:
            raise ValueError("OFFSET required")
        if isinstance(eip, str):
            eip = bytes.fromhex(eip)
        stub = shell_stub or b"\x90" * 16
        if offset + 4 > payload_len:
            raise ValueError("OFFSET + 4 exceeds payload_len")
        prefix = b"A" * offset
        rest_len = payload_len - (offset + 4 + len(stub))
        if rest_len < 0:
            stub = stub[:max(0, payload_len - (offset + 4))]
            rest = b""
        else:
            rest = b"C" * rest_len
        payload = prefix + eip + stub + rest
        out = outfile or os.path.join(self.workdir, f"exploit_{int(time.time())}.bin")
        write_bin(out, payload)
        return out, len(payload)

# -------------------------
# Simulated shell (safe)
# -------------------------
def simulated_shell():
    print("==== SIMULATED SHELL (safe demo) ====")
    print("type 'help' for commands, 'exit' to quit")
    while True:
        try:
            cmd = input("shell$ ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break
        if not cmd:
            continue
        if cmd == "exit":
            break
        if cmd == "help":
            print("Available (simulated): whoami, id, uname -a, ls")
            continue
        if cmd == "whoami":
            print("simuser")
            continue
        if cmd == "id":
            print("uid=1000(simuser) gid=1000(simuser) groups=1000(simuser)")
            continue
        if cmd == "ls":
            print("bin  etc  home  var")
            continue
        print(f"Simulated: command '{cmd}' executed (output suppressed).")
    print("==== exit simulated shell ====")

# -------------------------
# Integrate into F-22 like console
# -------------------------
class F22ConsoleSafe:
    PROMPT = "F-22> "
    def __init__(self):
        self.auto = SafeAuto()
        self.harness_thread = None
    def banner(self):
        print(r"""
 _____  __   ___    ___ 
|  ___|/ _| / _ \  / _ \
| |_  | |_ / /_\ \/ /_\ \
|  _| |  _||  _  ||  _  |
|_|   |_|  |_| |_||_| |_|
F-22 SAFE AUTO (simulasyon)
Type 'help' for commands.
""")
    def help(self):
        print("""
Komutlar (Türkçe):
  help
  generate_pattern <len> <outfile?>        - pattern üretir
  auto_fuzz [start] [step] [maxlen]        - fuzz dosyaları üretir
  find_offset <pattern_file> <hex_eip>     - pattern içinde eip ara (endianness kontrol)
  find_in_haystack <pattern> <haystack>    - patterni haystack'te ara
  detect_badchars <file> [baseline?]       - badchar tespiti (heuristic)
  build_exploit OFFSET=<n> PAYLOAD_LEN=<n> EIP=<hex> OUT=<file>
  start_harness <port>                      - localhost harness başlat
  attack <ip> <port> <payload_file>         - payload'u gönder (sadece 127.0.0.1 kabul)
  auto_pipeline [interactive]               - otomatik pipeline çalıştırır (interactive=yes|no)
  exit
""")
    def repl(self):
        self.banner()
        while True:
            try:
                line = input(self.PROMPT)
            except (KeyboardInterrupt, EOFError):
                print()
                break
            line = line.strip()
            if not line:
                continue
            parts = shlex.split(line)
            cmd = parts[0].lower()
            args = parts[1:]
            try:
                if cmd in ("exit", "quit"):
                    break
                if cmd == "help":
                    self.help(); continue
                if cmd == "generate_pattern":
                    if len(args) < 1:
                        print("Usage: generate_pattern <len> [outfile]")
                        continue
                    ln = int(args[0]); out = args[1] if len(args)>1 else None
                    fn, l = self.auto.generate_pattern(ln, out)
                    print("Pattern written:", fn, "len", l); continue
                if cmd == "auto_fuzz":
                    start = int(args[0]) if len(args)>0 else 100
                    step = int(args[1]) if len(args)>1 else 100
                    maxlen = int(args[2]) if len(args)>2 else 2000
                    files = self.auto.fuzz_generate(start=start, step=step, maxlen=maxlen)
                    print("Fuzz files generated:", len(files), "in", os.path.join(self.auto.workdir,"fuzz")); continue
                if cmd == "find_offset":
                    if len(args)<2:
                        print("Usage: find_offset <pattern_file> <hex_eip>")
                        continue
                    patf = args[0]; eip = args[1]
                    idx = self.auto.find_offset_by_eip(patf, eip)
                    if idx >= 0:
                        print("Offset found:", idx)
                    else:
                        print("Offset not found.")
                    continue
                if cmd == "find_in_haystack":
                    if len(args)<2:
                        print("Usage: find_in_haystack <pattern_file> <haystack_file>")
                        continue
                    idx = self.auto.find_pattern_in_hay(args[0], args[1])
                    print("Index:", idx if idx>=0 else "not found"); continue
                if cmd == "detect_badchars":
                    if len(args)<1:
                        print("Usage: detect_badchars <file> [baseline]")
                        continue
                    infile = args[0]; baseline = args[1] if len(args)>1 else None
                    bads, ent = self.auto.detect_badchars(infile, baseline)
                    if not bads:
                        print("No badchars detected (heuristic). Entropy:", ent)
                    else:
                        print("Possible badchars:", ["0x%02x"%b for b in bads], "Entropy:", ent)
                    continue
                if cmd == "build_exploit":
                    kv = {}
                    for a in args:
                        if "=" in a:
                            k,v = a.split("=",1); kv[k.upper()] = v
                    if "OFFSET" not in kv:
                        print("OFFSET is required.")
                        continue
                    offset = int(kv["OFFSET"]); payload_len = int(kv.get("PAYLOAD_LEN","1024"))
                    eip = kv.get("EIP","DEADBEEF"); out = kv.get("OUT", None)
                    outf, ln = self.auto.build_exploit(offset, payload_len=payload_len, eip=bytes.fromhex(eip), outfile=out)
                    print("Exploit-sim written to", outf, "len", ln)
                    continue
                if cmd == "start_harness":
                    if len(args)<1:
                        print("Usage: start_harness <port>"); continue
                    p = int(args[0]); self.harness_thread = start_local_harness(p); print("Harness started on port", p); continue
                if cmd == "attack":
                    if len(args)<3:
                        print("Usage: attack <ip> <port> <payload_file>"); continue
                    ip = args[0]; port = int(args[1]); infile = args[2]
                    try:
                        ok, resp = safe_send_payload(ip, port, infile)
                    except Exception as e:
                        print("Error during attack simulation:", e); continue
                    if ok:
                        print("server granted SIMULATED shell token. Opening simulated shell.")
                        simulated_shell()
                    else:
                        print("no simulated shell. Attack simulated only.")
                    continue
                if cmd == "auto_pipeline":
                    # run full pipeline non-destructively; asks interactive or not
                    interactive = True
                    if len(args)>0 and args[0].lower() in ("no","false","0"):
                        interactive = False
                    print("Starting automated simulation pipeline (local only).")
                    # 1) pattern
                    patf, plen = self.auto.generate_pattern(2000, os.path.join(self.auto.workdir,"pattern.bin"))
                    print("pattern:", patf, "len", plen)
                    # 2) fuzz
                    files = self.auto.fuzz_generate(start=100, step=200, maxlen=1200)
                    print("fuzz files:", len(files))
                    # 3) simulated crash eip (pick 4 bytes from pattern at 512)
                    pat = read_bin(patf)
                    sim_eip = pat[512:516]
                    print("simulated crash EIP (hex):", sim_eip.hex())
                    idx = self.auto.find_offset_by_eip(patf, sim_eip.hex())
                    if idx >= 0:
                        print("simulated offset found:", idx)
                    else:
                        print("simulated offset not found; using fallback offset 512")
                        idx = 512
                    # 4) badchars detect on a sample fuzz file
                    sample = files[len(files)//2][1]
                    bads, ent = self.auto.detect_badchars(sample)
                    print("badchar heuristic:", bads, "entropy:", ent)
                    # 5) build exploit
                    outf, ln = self.auto.build_exploit(idx, payload_len=1024, eip=sim_eip, outfile=os.path.join(self.auto.workdir,"exploit_sim.bin"))
                    print("exploit simulated written to", outf)
                    # 6) start harness and attack
                    port = 9999
                    self.harness_thread = start_local_harness(port)
                    ok, resp = safe_send_payload(HOST_LOCAL, port, outf)
                    if ok:
                        print("server granted SIMULATED shell token. Opening simulated shell.")
                        simulated_shell()
                    else:
                        print("no simulated shell. pipeline completed.")
                    continue
                print("Unknown command. Type 'help'.")
            except Exception as e:
                print("Runtime error:", e)
        print("Exiting F-22 safe auto.")
# -------------------------
# Main
# -------------------------
def main():
    parser = OptionParser()
    parser.add_option("--tt", dest="auto", action="store_true", default=False, help="run auto pipeline demo")
    (options, args) = parser.parse_args()
    console = F22ConsoleSafe()
    if options.auto:
        # run automatic demo non-interactive
        console.auto.generate_pattern(2000, os.path.join(console.auto.workdir,"pattern.bin"))
        console.auto.fuzz_generate(start=100, step=200, maxlen=1200)
        console.harness_thread = start_local_harness(9999)
        outf, ln = console.auto.build_exploit(512, payload_len=1024, eip=console.auto.generate_pattern(2000)[0] and b"\x41\x41\x41\x41", outfile=os.path.join(console.auto.workdir,"exploit_sim.bin"))
        ok, resp = safe_send_payload(HOST_LOCAL, 9999, outf)
        if ok:
            print("SIMULATED shell would open here.")
        else:
            print("Pipeline finished (non-interactive).")
        return
    console.repl()

if __name__ == "__main__":
    main()
