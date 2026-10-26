#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate HBC v89 metadata directly from Meta's MIT-licensed Hermes v0.12.0."""
import os
import pathlib
import re
import shlex
import subprocess

root = pathlib.Path(__file__).resolve().parent
hermes = root / "vendor/hermes"
revision = "7d3e091b59ff5e5a9e722718c01d81dab52d4300"
definitions = hermes / "include/hermes/BCGen/HBC/BytecodeList.def"
version_file = hermes / "include/hermes/BCGen/HBC/BytecodeVersion.h"
license_file = hermes / "LICENSE"
if not all(path.is_file() for path in (definitions, version_file, license_file)):
    raise SystemExit("Initialize Hermes first: git submodule update --init --recursive")
actual_revision = subprocess.run(
    ["git", "-C", str(hermes), "rev-parse", "HEAD"], text=True, capture_output=True, check=True
).stdout.strip()
if actual_revision != revision:
    raise SystemExit(f"Unexpected Hermes revision {actual_revision}; run git submodule update --init --recursive")
if not re.search(r"BYTECODE_VERSION\s*=\s*89\s*;", version_file.read_text()):
    raise SystemExit("Expected the pinned Hermes HBC v89 definitions")
macros = ["#define DEFINE_OPERAND_TYPE(name, type) TYPE(name, type)"]
for count in range(7):
    parameters = "name" + (", ..." if count else "")
    expansion = "name" + (", __VA_ARGS__" if count else "")
    macros.append(f"#define DEFINE_OPCODE_{count}({parameters}) OPCODE({expansion})")
macros += [
    "#define OPERAND_STRING_ID(name, index) STRING(name, index)",
    "#define OPERAND_FUNCTION_ID(name, index) FUNCTION(name, index)",
    f'#include "{definitions.as_posix()}"',
]
preprocessed = subprocess.run(
    shlex.split(os.environ.get("HOST_CC", "cc")) + ["-E", "-P", "-DHERMES_RUN_WASM=1", "-x", "c", "-"],
    input="\n".join(macros), text=True, capture_output=True, check=True,
).stdout
widths = {"uint8_t": 1, "int8_t": 1, "uint16_t": 2, "uint32_t": 4, "int32_t": 4, "double": 8}
types, instructions, identifiers = {}, [], []
for kind, arguments in re.findall(r"\b(TYPE|OPCODE|STRING|FUNCTION)\(([^()]*)\)", preprocessed):
    parts = [part.strip() for part in arguments.split(",")]
    if kind == "TYPE":
        types[parts[0]] = widths[parts[1]]
    elif kind == "OPCODE":
        instructions.append((parts[0], parts[1:]))
    else:
        identifiers.append((kind, parts[0], int(parts[1])))
assert 0 < len(instructions) < 256 and len({name for name, _ in instructions}) == len(instructions)
indices = {name: i for i, (name, _) in enumerate(instructions)}
tables = {name: [0] * 256 for name in (
    "hbc_sizes", "hbc_string_offsets", "hbc_string_widths", "hbc_function_offsets", "hbc_function_widths"
)}
for opcode, (_, operands) in enumerate(instructions):
    tables["hbc_sizes"][opcode] = 1 + sum(types[operand] for operand in operands)
for kind, name, index in identifiers:
    opcode = indices[name]
    operands = instructions[opcode][1]
    assert 1 <= index <= len(operands)
    prefix = "hbc_string" if kind == "STRING" else "hbc_function"
    tables[prefix + "_offsets"][opcode] = 1 + sum(types[operand] for operand in operands[:index - 1])
    tables[prefix + "_widths"][opcode] = types[operands[index - 1]]
output = [
    "/* SPDX-License-Identifier: MIT",
    " * Copyright (c) Meta Platforms, Inc. and affiliates.",
    " * Generated from Hermes v0.12.0 BytecodeList.def (HBC v89).",
    f" * Upstream: https://github.com/facebook/hermes/tree/{revision}",
    " * Regenerate from the pinned submodule with make opcodes.",
    " *",
    *[" * " + line if line else " *" for line in license_file.read_text().strip().splitlines()],
    " */",
]
output += [f"#define HBC_{name} {opcode}" for opcode, (name, _) in enumerate(instructions)]
for name, values in tables.items():
    output.append(f"static const unsigned char {name}[256] = {{")
    output += ["    " + ",".join(map(str, values[i:i + 16])) + "," for i in range(0, 256, 16)]
    output.append("};")
(root / "hbc_opcodes.h").write_text("\n".join(output) + "\n")
print(f"Generated {len(instructions)} HBC v89 opcodes from official Hermes definitions")
