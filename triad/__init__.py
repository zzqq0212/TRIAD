"""TRIAD: trigger-driven root-cause inference and agentic diagnosis for kernel bug reproduction.

This package implements the four pipeline stages described in the accompanying
paper:

* ``triad.m1`` - report normalization, readiness and routing (M1)
* ``triad.m2`` - mechanism and trigger-specification inference (M2)
* ``triad.m3`` - dependency-aware construction and manifest validation (M3)
* ``triad.m4`` - execution- and condition-guided refinement plus frozen joint
  confirmation (M4)

The package uses only the Python standard library. Kernel execution requires an
external Ubuntu host with syzkaller, QEMU/KVM and a built target kernel; without
it the pipeline runs in a deterministic offline *dry-run* mode that exercises
every stage against a bundled example report and a scripted runtime trace.
"""

__version__ = "0.3.0"

__all__ = ["__version__"]
