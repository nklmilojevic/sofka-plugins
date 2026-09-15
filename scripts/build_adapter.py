"""Build and check a native plugin package without external tools or a cluster."""

import argparse
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

import catalog
import zstandard


def test_adapter(binary: Path, plugin: str) -> None:
    fixtures = catalog.PLUGINS / plugin / "fixtures"
    requests = [(fixtures / "request.json", fixtures / "report.json", [])]
    for request in sorted(fixtures.glob("*-request.json")):
        action = request.name.removesuffix("-request.json")
        requests.append((request, fixtures / f"{action}-report.json", [action]))
    for request, expected, args in requests:
        result = subprocess.run(
            [str(binary.resolve()), *args], input=request.read_bytes(),
            capture_output=True, check=True, cwd=catalog.ROOT, timeout=30,
        )
        if json.loads(result.stdout) != json.loads(expected.read_bytes()):
            raise ValueError(f"{plugin}: report differs from {expected.name}")
    result = subprocess.run(
        [str(binary.resolve())], input=b"{", capture_output=True,
        cwd=catalog.ROOT, timeout=30,
    )
    if result.returncode == 0 or result.stdout:
        raise ValueError(f"{plugin}: invalid input was not rejected")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin", choices=catalog.plugin_ids(), required=True)
    parser.add_argument("--target", choices=catalog.TARGETS, required=True)
    args = parser.parse_args()
    if args.target.endswith("-windows-msvc"):
        os.environ["RUSTFLAGS"] = os.environ.get("RUSTFLAGS", "") + " -C target-feature=+crt-static"
    crate = f"sofka-plugin-{args.plugin}"
    subprocess.run(["cargo", "test", "--locked", "--package", crate, "--target", args.target], check=True)
    subprocess.run(["cargo", "build", "--release", "--locked", "--package", crate, "--target", args.target], check=True)
    suffix = ".exe" if args.target.endswith("-windows-msvc") else ""
    binary = catalog.ROOT / "target" / args.target / "release" / (crate + suffix)
    test_adapter(binary, args.plugin)
    version = catalog.publication(args.plugin)["version"]
    package = catalog.ROOT / f"{args.plugin}-{version}-{args.target}.tar.zst"
    catalog.package(argparse.Namespace(plugin=args.plugin, target=args.target, binary=str(binary), output=str(package)))
    with tempfile.TemporaryDirectory() as temporary:
        with zstandard.ZstdDecompressor().stream_reader(package.open("rb")) as source:
            with tarfile.open(fileobj=io.BytesIO(source.read())) as archive:
                archive.extractall(temporary, filter="data")
        staged = Path(temporary)
        adapter = staged / (catalog.ADAPTER + suffix)
        if adapter.read_bytes() != binary.read_bytes():
            raise ValueError("The packaged adapter differs from the built binary")
        for name in ("LICENSE-MIT", "LICENSE-APACHE"):
            if (staged / name).read_bytes() != (catalog.ROOT / name).read_bytes():
                raise ValueError(f"The package has an incorrect {name}")
        test_adapter(adapter, args.plugin)
    print(f"Verified package: {package}")


if __name__ == "__main__":
    main()
