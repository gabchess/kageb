#!/usr/bin/env python3
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


ALLOWED_LICENSES = {
    "0BSD",
    "Apache-2.0",
    "BSD-1-Clause",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "CC0-1.0",
    "CDLA-Permissive-2.0",
    "ISC",
    "MIT",
    "MIT-0",
    "MPL-2.0",
    "MPL-2.0+",
    "Unicode-3.0",
    "Unlicense",
    "Zlib",
    "bzip2-1.0.6",
}
ALLOWED_EXCEPTIONS = {"LLVM-exception"}
LICENSE_FILE_MARKERS = (
    "apache license",
    "permission is hereby granted, free of charge",
    "redistribution and use in source and binary forms",
    "mozilla public license",
    "isc license",
    "the unlicense",
    "boost software license",
)
TOKEN = re.compile(r"\(|\)|\bAND\b|\bOR\b|\bWITH\b|[A-Za-z0-9][A-Za-z0-9.+-]*")


class LicenseExpression:
    def __init__(self, expression):
        self.tokens = TOKEN.findall(expression.replace("/", " OR "))
        self.position = 0

    def parse(self):
        if not self.tokens:
            return False
        result = self.parse_or()
        if self.position != len(self.tokens):
            return False
        return result

    def parse_or(self):
        result = self.parse_and()
        while self.take("OR"):
            alternative = self.parse_and()
            result = result or alternative
        return result

    def parse_and(self):
        result = self.parse_primary()
        while self.take("AND"):
            condition = self.parse_primary()
            result = result and condition
        return result

    def parse_primary(self):
        if self.take("("):
            result = self.parse_or()
            if not self.take(")"):
                return False
            return result
        if self.position >= len(self.tokens):
            return False
        license_id = self.tokens[self.position]
        self.position += 1
        result = license_id in ALLOWED_LICENSES
        if self.take("WITH"):
            if self.position >= len(self.tokens):
                return False
            exception = self.tokens[self.position]
            self.position += 1
            result = result and exception in ALLOWED_EXCEPTIONS
        return result

    def take(self, token):
        if self.position < len(self.tokens) and self.tokens[self.position] == token:
            self.position += 1
            return True
        return False


def main():
    explicit_cargo = os.environ.get("CARGO")
    if explicit_cargo:
        cargo = shutil.which(explicit_cargo)
        if cargo is None and Path(explicit_cargo).is_file() and os.access(explicit_cargo, os.X_OK):
            cargo = explicit_cargo
        if cargo is None:
            raise SystemExit("CARGO does not name an executable")
    else:
        cargo = shutil.which("cargo")
        home_cargo = Path.home() / ".cargo" / "bin" / "cargo"
        if cargo is None and home_cargo.is_file() and os.access(home_cargo, os.X_OK):
            cargo = str(home_cargo)
        if cargo is None:
            raise SystemExit(
                "cargo was not found; set CARGO, add cargo to PATH, "
                "or install it at HOME/.cargo/bin/cargo"
            )
    result = subprocess.run(
        [cargo, "metadata", "--locked", "--format-version", "1"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    metadata = json.loads(result.stdout)
    failures = []
    for package in metadata["packages"]:
        expression = package.get("license")
        if expression:
            if not LicenseExpression(expression).parse():
                failures.append(f"{package['name']} {package['version']}: {expression}")
            continue

        license_file = package.get("license_file")
        if license_file:
            path = Path(package["manifest_path"]).parent / license_file
            if path.is_file():
                contents = path.read_text(encoding="utf-8", errors="ignore").lower()
                if any(marker in contents for marker in LICENSE_FILE_MARKERS):
                    continue
        failures.append(f"{package['name']} {package['version']}: no usable license metadata")

    if failures:
        print("dependencies without an approved license choice:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(f"license policy passed for {len(metadata['packages'])} packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
