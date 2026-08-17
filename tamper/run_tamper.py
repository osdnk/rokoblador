#!/usr/bin/env python3
import os
import shutil
import struct
import subprocess
import sys
import tempfile

CRATE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROKOBLADOR_BIN = os.environ.get("ROKOBLADOR_BIN", os.path.join(CRATE_DIR, "target", "release", "rokoblador"))
EXPORT_DIR = os.environ.get("ROKOBLADOR_EXPORT_DIR", os.path.join(CRATE_DIR, "rokoblador-export"))
STATEMENT_VERIFIER = os.path.join(EXPORT_DIR, "statement.verifier.bin")
STATEMENT_PROVER = os.path.join(EXPORT_DIR, "statement.bin")
WITNESS = os.path.join(EXPORT_DIR, "witness.bin")
TIMEOUT_S = 300

USAGE = """usage: python3 tamper/run_tamper.py [--help]

Exercises the shim's checks against a tampered copy of a prior export.
Run `cargo +nightly run --release -- --cut 3` first to produce an export
directory, then run this script.

env overrides:
  ROKOBLADOR_BIN         path to the release rokoblador binary
                          (default: <crate>/target/release/rokoblador)
  ROKOBLADOR_EXPORT_DIR  export directory to tamper with
                          (default: <crate>/rokoblador-export)
"""

if "--help" in sys.argv or "-h" in sys.argv:
    print(USAGE)
    sys.exit(0)


def read_u32(f):
    return struct.unpack("<I", f.read(4))[0]


def read_u64(f):
    return struct.unpack("<Q", f.read(8))[0]


def parse_statement(path):
    with open(path, "rb") as f:
        magic = read_u32(f)
        version = read_u32(f)
        q = read_u64(f)
        digest_off = f.tell()
        f.read(16)
        r = read_u64(f)
        k = read_u64(f)
        betasq_w_total_off = f.tell()
        betasq_w_total = read_u64(f)
        betasq_inner_total_off = f.tell()
        betasq_inner_total = read_u64(f)
        vectors = []
        for _ in range(r):
            n_off = f.tell()
            n_i = read_u64(f)
            betasq_off = f.tell()
            betasq_i = read_u64(f)
            role = read_u32(f)
            flags = read_u32(f)
            vectors.append(
                dict(n=n_i, betasq=betasq_i, role=role, flags=flags, n_off=n_off, betasq_off=betasq_off)
            )
        constraints = []
        for ci in range(k):
            start = f.tell()
            nz = read_u64(f)
            blocks = []
            for _ in range(nz):
                idx = read_u64(f)
                off = read_u64(f)
                length = read_u64(f)
                blocks.append((idx, off, length))
            has_b = read_u64(f)
            b_off = None
            if has_b:
                b_off = f.tell()
                f.seek(64 * 8, 1)
            philen = sum(length for _, _, length in blocks)
            phi_off = f.tell()
            f.seek(philen * 64 * 8, 1)
            constraints.append(
                dict(index=ci, start=start, nz=nz, blocks=blocks, has_b=has_b, b_off=b_off, phi_off=phi_off, philen=philen)
            )
        end = f.tell()
    size = os.path.getsize(path)
    assert end == size, f"{path}: parsed {end} bytes, file is {size} bytes"
    return dict(
        magic=magic,
        version=version,
        q=q,
        digest_off=digest_off,
        r=r,
        k=k,
        betasq_w_total=betasq_w_total,
        betasq_w_total_off=betasq_w_total_off,
        betasq_inner_total=betasq_inner_total,
        betasq_inner_total_off=betasq_inner_total_off,
        vectors=vectors,
        constraints=constraints,
    )


def parse_witness(path):
    with open(path, "rb") as f:
        magic = read_u32(f)
        version = read_u32(f)
        q = read_u64(f)
        r = read_u64(f)
        vectors = []
        for _ in range(r):
            n_off = f.tell()
            n_i = read_u64(f)
            coeffs_off = f.tell()
            f.seek(n_i * 64 * 8, 1)
            vectors.append(dict(n=n_i, n_off=n_off, coeffs_off=coeffs_off))
        end = f.tell()
    size = os.path.getsize(path)
    assert end == size, f"{path}: parsed {end} bytes, file is {size} bytes"
    return dict(r=r, vectors=vectors)


def read_i64_at(path, byte_off):
    with open(path, "rb") as f:
        f.seek(byte_off)
        return struct.unpack("<q", f.read(8))[0]


def write_i64_at(path, byte_off, value):
    with open(path, "r+b") as f:
        f.seek(byte_off)
        f.write(struct.pack("<q", value))


def write_u64_at(path, byte_off, value):
    with open(path, "r+b") as f:
        f.seek(byte_off)
        f.write(struct.pack("<Q", value))


def sum_of_squares(path, coeffs_off, count):
    total = 0
    remaining = count
    pos = coeffs_off
    chunk = 1 << 16
    with open(path, "rb") as f:
        while remaining > 0:
            n = min(chunk, remaining)
            f.seek(pos)
            data = f.read(n * 8)
            vals = struct.unpack(f"<{n}q", data)
            total += sum(v * v for v in vals)
            pos += n * 8
            remaining -= n
    return total


def find_negative_i64(path, byte_off, count):
    remaining = count
    pos = byte_off
    chunk = 1 << 16
    with open(path, "rb") as f:
        while remaining > 0:
            n = min(chunk, remaining)
            f.seek(pos)
            data = f.read(n * 8)
            vals = struct.unpack(f"<{n}q", data)
            for i, v in enumerate(vals):
                if v < 0:
                    return pos + i * 8, v
            pos += n * 8
            remaining -= n
    return None


def find_last_w_only_block(stmt):
    for c in reversed(stmt["constraints"]):
        for idx, off, length in c["blocks"]:
            if idx == 1 and length > 0:
                return c["index"], off, length
    raise RuntimeError("no idx==1 block found in any constraint")


def run_shim(stmt_path, wit_path):
    proc = subprocess.run(
        [ROKOBLADOR_BIN, "check", stmt_path, wit_path],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
    )
    return proc.returncode, proc.stdout, proc.stderr


def expect(code, stdout, stderr, want_fail, needles):
    text = stdout + "\n" + stderr
    if want_fail:
        ok = code != 0 and all(n in text for n in needles)
    else:
        ok = code == 0 and all(n in text for n in needles)
    return ok, code, text.strip().splitlines()[-6:]


results = []


def record(name, description, expectation, ok, code, tail_lines, extra_note=""):
    results.append(dict(name=name, description=description, expectation=expectation, ok=ok, code=code, tail=tail_lines, note=extra_note))
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}: {description}")
    print(f"       expected: {expectation}")
    print(f"       exit code: {code}")
    for line in tail_lines:
        print(f"       | {line}")
    if extra_note:
        print(f"       note: {extra_note}")
    print()


def main():
    print(f"parsing {STATEMENT_VERIFIER}")
    stmt = parse_statement(STATEMENT_VERIFIER)
    print(f"parsing {WITNESS}")
    wit = parse_witness(WITNESS)
    print(f"r={stmt['r']} k={stmt['k']} q={stmt['q']}")
    for i, v in enumerate(stmt["vectors"]):
        print(f"  vector {i}: n={v['n']} betasq={v['betasq']} role={v['role']} flags={v['flags']}")
    print()

    tmpdir = tempfile.mkdtemp(prefix="rokoblador_tamper_")
    print(f"working in {tmpdir}\n")

    d = os.path.join(tmpdir, "t1_witness_coeff")
    os.makedirs(d)
    stmt_copy = os.path.join(d, "statement.verifier.bin")
    wit_copy = os.path.join(d, "witness.bin")
    shutil.copyfile(STATEMENT_VERIFIER, stmt_copy)
    shutil.copyfile(WITNESS, wit_copy)
    ci, off, length = find_last_w_only_block(stmt)
    v1 = wit["vectors"][1]
    target_off = v1["coeffs_off"] + off * 64 * 8
    found = find_negative_i64(wit_copy, target_off, length * 64)
    if found is None:
        record("t1_witness_coeff_plus1", "increment one negative coefficient in vector 1's w segment by 1", "simple_verify FAIL", False, -1, [], "no negative coefficient found in the sampled w-only block")
    else:
        byte_off, old_val = found
        write_i64_at(wit_copy, byte_off, old_val + 1)
        code, out, err = run_shim(stmt_copy, wit_copy)
        ok, code, tail = expect(code, out, err, True, ["simple_verify: FAIL"])
        record(
            "t1_witness_coeff_plus1",
            f"vector1 coeff at byte {byte_off} (constraint {ci} w-block off={off} len={length}): {old_val} -> {old_val + 1}",
            "simple_verify FAIL (nonzero exit, its error line)",
            ok, code, tail,
        )

    d = os.path.join(tmpdir, "t2_statement_b")
    os.makedirs(d)
    stmt_copy = os.path.join(d, "statement.verifier.bin")
    wit_copy = os.path.join(d, "witness.bin")
    shutil.copyfile(STATEMENT_VERIFIER, stmt_copy)
    shutil.copyfile(WITNESS, wit_copy)
    last_c = stmt["constraints"][-1]
    assert last_c["b_off"] is not None, "last constraint (an eval claim) must carry b"
    b_off = last_c["b_off"]
    old_b0 = read_i64_at(stmt_copy, b_off)
    new_b0 = (old_b0 + 1) % stmt["q"]
    write_i64_at(stmt_copy, b_off, new_b0)
    code, out, err = run_shim(stmt_copy, wit_copy)
    ok, code, tail = expect(code, out, err, True, ["simple_verify: FAIL"])
    record(
        "t2_statement_b_flip",
        f"constraint {last_c['index']} (last, an eval claim) b[0] at byte {b_off}: {old_b0} -> {new_b0} (mod q)",
        "simple_verify FAIL (nonzero exit, its error line)",
        ok, code, tail,
    )

    d = os.path.join(tmpdir, "t3_betasq0_below_honest")
    os.makedirs(d)
    stmt_copy = os.path.join(d, "statement.verifier.bin")
    wit_copy = os.path.join(d, "witness.bin")
    shutil.copyfile(STATEMENT_VERIFIER, stmt_copy)
    shutil.copyfile(WITNESS, wit_copy)
    v0 = wit["vectors"][0]
    honest_normsq0 = sum_of_squares(WITNESS, v0["coeffs_off"], v0["n"] * 64)
    tampered_betasq0 = honest_normsq0 - 1
    write_u64_at(stmt_copy, stmt["vectors"][0]["betasq_off"], tampered_betasq0)
    code, out, err = run_shim(stmt_copy, wit_copy)
    ok, code, tail = expect(code, out, err, True, ["recomputed normsq", "exceeds statement betasq"])
    record(
        "t3_betasq0_below_honest",
        f"vector0 betasq {stmt['vectors'][0]['betasq']} -> {tampered_betasq0} (honest normsq is {honest_normsq0})",
        "shim's normsq<=betasq check FAIL",
        ok, code, tail,
    )

    d = os.path.join(tmpdir, "t4_betasq_inner_total_below_B0")
    os.makedirs(d)
    stmt_copy = os.path.join(d, "statement.verifier.bin")
    wit_copy = os.path.join(d, "witness.bin")
    shutil.copyfile(STATEMENT_VERIFIER, stmt_copy)
    shutil.copyfile(WITNESS, wit_copy)
    b0 = stmt["vectors"][0]["betasq"]
    tampered_inner_total = b0 - 1
    write_u64_at(stmt_copy, stmt["betasq_inner_total_off"], tampered_inner_total)
    code, out, err = run_shim(stmt_copy, wit_copy)
    ok, code, tail = expect(code, out, err, True, ["exceeds betasq_inner_total"])
    record(
        "t4_betasq_inner_total_below_B0",
        f"betasq_inner_total {stmt['betasq_inner_total']} -> {tampered_inner_total} (B0 is {b0})",
        "shim's Sigma-bound recheck FAIL",
        ok, code, tail,
    )

    d = os.path.join(tmpdir, "t5_digest_flip")
    os.makedirs(d)
    stmt_copy = os.path.join(d, "statement.verifier.bin")
    shutil.copyfile(STATEMENT_VERIFIER, stmt_copy)
    with open(stmt_copy, "r+b") as f:
        f.seek(stmt["digest_off"])
        b = f.read(1)
        f.seek(stmt["digest_off"])
        f.write(bytes([b[0] ^ 0xFF]))
    with open(stmt_copy, "rb") as f:
        tampered_bytes = f.read()
    with open(STATEMENT_PROVER, "rb") as f:
        prover_bytes = f.read()
    files_now_differ = tampered_bytes != prover_bytes
    record(
        "t5_digest_flip",
        "flip one digest byte in a copy of statement.verifier.bin, compare against statement.bin",
        "tampered file no longer byte-equals statement.bin (the cross-derivation check the rust STATEMENT MATCH assertion performs; the C shim itself would still accept this file since it only uses the digest as its own internal Fiat-Shamir seed, never checked against an external reference -- the byte-compare, run before the shim in the real pipeline, is what catches this)",
        files_now_differ, None, [],
    )

    d = os.path.join(tmpdir, "t6_control")
    os.makedirs(d)
    stmt_copy = os.path.join(d, "statement.verifier.bin")
    wit_copy = os.path.join(d, "witness.bin")
    shutil.copyfile(STATEMENT_VERIFIER, stmt_copy)
    shutil.copyfile(WITNESS, wit_copy)
    code, out, err = run_shim(stmt_copy, wit_copy)
    ok, code, tail = expect(code, out, err, False, ["ROKOBLADOR composite_verify: OK"])
    record(
        "t6_control_untampered",
        "untampered statement.verifier.bin + witness.bin",
        "full OK, exit 0",
        ok, code, tail,
    )

    width_name = max(len(r["name"]) for r in results)
    print("=" * (width_name + 60))
    print(f"{'TEST':<{width_name}}  {'RESULT':<6}  {'EXIT':<5}  EXPECTATION")
    print("-" * (width_name + 60))
    all_ok = True
    for r in results:
        status = "PASS" if r["ok"] else "FAIL"
        all_ok = all_ok and r["ok"]
        code_str = str(r["code"]) if r["code"] is not None else "n/a"
        print(f"{r['name']:<{width_name}}  {status:<6}  {code_str:<5}  {r['expectation']}")
    print("=" * (width_name + 60))
    print(f"tampered artifacts left in {tmpdir}")

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
