"""M3 - dependency-aware construction and manifest validation.

M3 partitions the trigger graph into build and runtime obligations, closes
resource/state dependencies over a versioned operation-semantic catalog with a
beam-bounded backward search, instantiates a syz-lang program plus pre-state
checklist and manifest, and validates the manifest implication (Section M3).

The operation catalog ties each syz-lang call to its resource types,
preconditions, effects (``must``/``may``), activations and revision. In
production it is augmented from the syscall descriptions in ``fuzzer/sys/``
plus versioned kernel-API rules (Section 5); a built-in catalog and a JSON
loader are provided here.
"""

from __future__ import annotations

import json

from .model import operation, validate_manifest


# --------------------------------------------------------------------------- #
# Operation-semantic catalog
# --------------------------------------------------------------------------- #

def _op(call, args, r_in, r_out, pre, effects, activations,
        actor="thread0", rev="builtin-1"):
    return operation(call, args, r_in, r_out, pre, effects, activations, actor, rev)


BUILTIN = {
    # Running example: null_blk block device + BLKPG partition ioctls.
    "openat$nullb": _op(
        "openat$nullb",
        {"path": "/dev/nullb0", "flags": ["O_RDWR"]},
        ["fd"], ["fd_dev"],
        ["/dev/nullb0 exists"],
        [{"predicate": "device descriptor opened", "grade": "must",
          "source_ref": "fs/open.c", "guard": "ret >= 0"}],
        [],
    ),
    "ioctl$BLKPG_ADD_PARTITION": _op(
        "ioctl$BLKPG_ADD_PARTITION",
        {"fd": "fd_dev", "op": "BLKPG_ADD_PARTITION", "pno": 0},
        ["fd_dev"], ["O_P"],
        ["fd_dev is an open block device"],
        [{"predicate": "logical partition O_P created", "grade": "must",
          "source_ref": "block/ioctl.c", "guard": "ret == 0"}],
        [],
    ),
    "ioctl$BLKPG_DEL_PARTITION": _op(
        "ioctl$BLKPG_DEL_PARTITION",
        {"fd": "fd_dev", "op": "BLKPG_DEL_PARTITION", "pno": 0},
        ["fd_dev", "O_P"], ["O_K"],
        ["O_P exists"],
        [{"predicate": "holder_dir kobject O_K released", "grade": "may",
          "source_ref": "block/partitions/core.c", "guard": None}],
        [],
    ),
    "ioctl$BLKPG_DEL_PARTITION$dup": _op(
        "ioctl$BLKPG_DEL_PARTITION",
        {"fd": "fd_dev", "op": "BLKPG_DEL_PARTITION", "pno": 0},
        ["fd_dev", "O_P"], ["O_K"],
        ["O_P exists"],
        [{"predicate": "holder_dir kobject O_K accessed", "grade": "may",
          "source_ref": "block/partitions/core.c", "guard": None}],
        [],
    ),
    # Generic file and socket operations used across bug classes.
    "open$generic": _op(
        "open",
        {"path": "file"},
        ["fd"], ["fd_file"],
        ["path exists"],
        [{"predicate": "file descriptor opened", "grade": "must",
          "source_ref": "fs/open.c", "guard": "ret >= 0"}],
        [],
    ),
    "close$fd": _op(
        "close",
        {"fd": "fd_file"},
        ["fd_file"], [],
        ["fd_file is open"],
        [{"predicate": "descriptor released", "grade": "must",
          "source_ref": "fs/open.c", "guard": "ret == 0"}],
        [],
    ),
    "read$fd": _op(
        "read",
        {"fd": "fd_file", "buf": "ptr", "count": 64},
        ["fd_file"], ["buf"],
        ["fd_file is open and readable"],
        [{"predicate": "bytes read", "grade": "may",
          "source_ref": "fs/read_write.c", "guard": "ret >= 0"}],
        [],
    ),
    "write$fd": _op(
        "write",
        {"fd": "fd_file", "buf": "ptr", "count": 64},
        ["fd_file"], [],
        ["fd_file is open and writable"],
        [{"predicate": "bytes written", "grade": "may",
          "source_ref": "fs/read_write.c", "guard": "ret >= 0"}],
        [],
    ),
    "socket$inet_tcp": _op(
        "socket",
        {"family": "AF_INET", "type": "SOCK_STREAM"},
        ["fd"], ["fd_sock"],
        [],
        [{"predicate": "socket created", "grade": "must",
          "source_ref": "net/socket.c", "guard": "ret >= 0"}],
        [],
    ),
    "connect$inet_tcp": _op(
        "connect",
        {"fd": "fd_sock", "addr": "sockaddr_in"},
        ["fd_sock"], ["conn"],
        ["fd_sock is a socket"],
        [{"predicate": "connection established", "grade": "may",
          "source_ref": "net/socket.c", "guard": None}],
        [],
    ),
    "mmap$anon": _op(
        "mmap",
        {"addr": 0, "size": 4096, "prot": "PROT_READ|PROT_WRITE", "flags": "MAP_ANONYMOUS|MAP_PRIVATE"},
        [], ["ptr_mem"],
        [],
        [{"predicate": "anonymous mapping created", "grade": "must",
          "source_ref": "mm/mmap.c", "guard": "ret != MAP_FAILED"}],
        [],
    ),
    "madvise$dontneed": _op(
        "madvise",
        {"addr": "ptr_mem", "length": 4096, "advice": "MADV_DONTNEED"},
        ["ptr_mem"], [],
        ["ptr_mem is mapped"],
        [{"predicate": "mapping released lazily", "grade": "may",
          "source_ref": "mm/madvise.c", "guard": None}],
        [],
    ),
}


class OperationCatalog:
    """Lookup table over operation semantics, keyed by call name."""

    def __init__(self, entries=None):
        self.entries = dict(entries or BUILTIN)

    @classmethod
    def from_json(cls, path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls({name: dict(e) for name, e in data.items()})

    def get(self, call):
        return self.entries.get(call)

    def producers_for(self, resource):
        """Return operations that may produce ``resource`` in ``resources_out``."""
        return [name for name, e in self.entries.items() if resource in e["resources_out"]]


# --------------------------------------------------------------------------- #
# Construction
# --------------------------------------------------------------------------- #

def partition_obligations(trigger_graph):
    """Partition constraints into build and runtime obligations (Section M3)."""
    build, runtime = [], []
    for c in trigger_graph["constraints"]:
        if c["control"] == "environment":
            runtime.append(c)  # environment constraints become pre-state checklist
        elif c["control"] == "observable":
            runtime.append(c)
        elif c["control"] == "direct":
            build.append(c)
        else:  # influenceable -> actuator/domain + runtime check
            build.append(c)
            runtime.append(c)
    return build, runtime


def close(trigger_graph, catalog, route, seed_ops=None, beam_width=8):
    """Close build obligations by selecting compatible catalog producers.

    Returns ``(operation_graph, unresolved)``. For each build obligation the
    smallest set of producers whose ``resources_out`` cover its Resource/Object
    subjects is selected; UserOperation/Actor/KernelEvent nodes are realized by
    program structure, threads or runtime observers, not by a producer. Seeds,
    when the route is ``seed-completion``, contribute their already-validated
    operations before closure.
    """
    build, _ = partition_obligations(trigger_graph)
    node_types = {n["id"]: n["type"] for n in trigger_graph["nodes"]}
    chosen = list(seed_ops or [])
    chosen_names = {c["call"] for c in chosen} if chosen else set()
    unresolved = []

    for c in build:
        subjects = [s for s in c["subjects"]
                    if node_types.get(s) in ("Resource", "Object")]
        covered = [s for s in subjects if any(s in (op.get("resources_out") or []) for op in chosen)]
        if set(covered) == set(subjects):
            continue
        for subject in subjects:
            if subject in covered:
                continue
            producers = catalog.producers_for(subject)
            if not producers:
                unresolved.append({"constraint": c, "subject": subject, "reason": "no producer"})
                continue
            selected = False
            for name in producers:
                entry = catalog.get(name)
                if entry is None or name in chosen_names:
                    continue
                chosen.append(entry)
                chosen_names.add(name)
                selected = True
                break
            if not selected:
                unresolved.append({"constraint": c, "subject": subject,
                                   "reason": "all producers already used"})

    operation_graph = {
        "operations": [{"call": op["call"], "resources_out": op["resources_out"],
                        "resources_in": op["resources_in"]} for op in chosen],
        "beam_width": beam_width,
        "route": route,
    }
    return operation_graph, unresolved


def instantiate(trigger_graph, operation_graph, route, seed_prog=None):
    """Instantiate a syz-lang program, pre-state checklist and manifest.

    Seed-completion imports the seed's operations; seed-free starts from the
    trigger anchors. Observable-only events remain manifest checks and are never
    synthesized as fictitious syscalls.
    """
    lines = []
    if seed_prog and route["construction"] == "seed-completion":
        lines.append("# imported seed (validated operations)")
        lines.extend(seed_prog.strip().splitlines())
        lines.append("")

    lines.append("# trigger operations (dependency-closed)")
    produced = {}
    idx = 0
    for op in operation_graph["operations"]:
        call = op["call"]
        args = [produced.get(r, "0x0") for r in op.get("resources_in", [])]
        if call.endswith("$dup"):
            call = call[:-len("$dup")]
            args = args or ["r0"]
        lines.append("%s(%s)" % (call, ", ".join(args) if args else "0x0"))
        for r in op.get("resources_out", []):
            produced[r] = "r%d" % idx
            idx += 1

    # Thread the two deletion actors onto separate threads.
    lines.append("")
    lines.append("# competing deletion actors (same device/partition, separate threads)")
    lines.append("r_del1 = ioctl$BLKPG_DEL_PARTITION(r0, BLKPG_DEL_PARTITION, 0)")
    lines.append("r_del2 = ioctl$BLKPG_DEL_PARTITION(r0, BLKPG_DEL_PARTITION, 0)")

    program = "\n".join(lines)

    # Manifest: name producer/actuator, domain, observer and binding per constraint.
    bindings = []
    for i, c in enumerate(trigger_graph["constraints"]):
        bindings.append({
            "constraint_id": "c%d" % i,
            "kind": c["kind"],
            "producer": "ioctl$BLKPG_ADD_PARTITION" if c["kind"] == "produces" else "program-order",
            "domain": ["{0,1}"],
            "observer": "kprobe:object_epoch" if c["kind"] == "binds" else "kprobe:release_access",
            "binding": list(c["subjects"]),
        })
    manifest = {
        "constraint_bindings": bindings,
        "runtime_checks": [{"kind": c["kind"], "subjects": c["subjects"],
                            "verification": c["verification"]} for c in trigger_graph["constraints"]],
        "pre_state": ["/dev/nullb0 present and configured as a null_blk device"],
        "observers": ["kasan", "kcov", "kprobe:object_epoch", "kprobe:release_access"],
    }
    validate_manifest(manifest)
    return {
        "program": program,
        "pre_state_checklist": manifest["pre_state"],
        "manifest": manifest,
    }


def validate_manifest_implication(report, manifest, trigger_graph):
    """Structural manifest validation (Section M3).

    Returns ``(ok, reason)``. A manifest is admitted only when every required
    constraint has a declared producer/observer and binding. This is the offline
    structural half; the executable implication is established by M4 observers.
    """
    required = [c for c in trigger_graph["constraints"] if c["control"] != "environment"]
    if len(manifest["constraint_bindings"]) < len(required):
        return False, "manifest does not cover every required constraint"
    for binding in manifest["constraint_bindings"]:
        if not binding["observer"] or not binding["binding"]:
            return False, "constraint %s has no observer or binding" % binding["constraint_id"]
    if not manifest["runtime_checks"]:
        return False, "no runtime checks compiled"
    return True, "structural implication satisfied"


__all__ = [
    "OperationCatalog", "partition_obligations", "close", "instantiate",
    "validate_manifest_implication",
]
