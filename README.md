# TRIAD

TRIAD turns heterogeneous Linux kernel bug reports — fuzzing reports, public CVE
records, customer prose and traces — into *confirmed target-defect reproducers*
rather than arbitrary nearby crashes. It encodes trigger conditions in a typed
trigger constraint graph and runs four stages: report normalization and routing
(M1), mechanism and trigger-specification inference (M2), dependency-aware
construction (M3), and execution- and condition-guided refinement with frozen
joint confirmation (M4).

The Python pipeline lives in `triad/`; the kernel-execution backend (executor,
fuzzing manager and single-program runner) is the fuzzing infrastructure in
`fuzzer/`; the evaluation cohort is in `data/`.

## Features

- **M1 report normalization and routing.** Deterministic parsers for stacks,
  diagnostic classes (KASAN/KCSAN/KFENCE/UBSAN, null-ptr-deref, GPF,
  BUG/WARNING), configurations, origin commits, syzbot report structure and
  syz-lang program shape; an LLM extracts only prose semantics under schema
  validation. Output is a sparse, provenance-preserving `NormalizedBugReport`, a
  readiness vector, a route (`align|infer` × `seed-completion|seed-free`) and a
  target attestation `A_K`.
- **M2 mechanism and trigger inference.** A bounded source graph grades causal
  relations (`G3/G2/G1/G0`); retained hypotheses compile to a typed
  `TriggerConstraintGraph` over resources, objects, operations, kernel events
  and actors, with a seven-list presentation projection.
- **M3 dependency-aware construction.** A versioned operation-semantic catalog
  (block devices, file/socket operations, memory primitives) drives
  build/runtime obligation partition, beam-bounded backward closure, and
  instantiation of a syz-lang program, pre-state checklist and manifest.
- **M4 execution- and condition-guided refinement.** Graded `L0`–`L3` feedback,
  four-state condition matching, an `F1`–`F5` scoped-repair policy, and
  `q`-of-`N_c` frozen joint confirmation over clean resets.
- **LLM adapter with call auditing.** OpenAI-compatible HTTPS backends (OpenAI,
  DeepSeek, GLM/Zhipu, or any compatible endpoint) using only the standard
  library; every call records the model revision, prompt/schema hashes and
  outcome, and an invalid response spends its call budget without changing
  pipeline state. A deterministic mock supports offline runs.
- **Budget accounting and audit.** The controller tracks wall time, executions
  and model calls against the frozen trial configuration and reports explicit
  `Budget-Exhausted(stage)` terminals plus an audit of accepted repairs.
- **Kernel-execution runtime.** `fuzzer/` contains the fuzzing infrastructure:
  the C++ executor, the Go program/runtime packages (including the LLM agent
  flow), Linux syscall descriptions, QEMU VM support, the fuzzing manager and
  the single-program runner. `triad/controller.py`'s `QemuRuntime` delegates
  candidate programs to it.
- **Record tooling and anonymous export.** `validate`/`report` check recorded
  metadata and produce summary tables; `export` builds an allowlisted archive
  with content digests and an automated secret scan.

## Repository Map

| Path | Purpose |
| --- | --- |
| `triad/` | The M1–M4 pipeline and tooling: `m1.py`–`m4.py` (stages), `controller.py` (orchestration, budgets, runtimes), `model.py` (typed representations), `llm.py` (LLM adapter), `records.py` (record validation and export), `cli.py` (CLI and bundled example). |
| `fuzzer/` | The fuzzing infrastructure: `executor/` (C++ in-VM executor), `prog/`/`pkg/` (Go program and runtime packages, including the agent flow), `sys/` (Linux syscall descriptions), `vm/` (QEMU backend), `syz-manager/`, `syz-agent/`, `tools/syz-execprog/` (single-program runner), plus `build-runtime.sh` and `config.example.json`. |
| `tools/syz-report.py` | M1 report normalization. |
| `tools/syz-mechanism.py` | M2 mechanism and trigger inference. |
| `tools/syz-construct.py` | M3 construction and manifest. |
| `tools/syz-confirm.py` | M4 confirmation accounting. |
| `tools/fetch-syzbot.py` | Fetch a public syzbot report title/URL. |
| `tools/build-dataset.py` | Build the formal `samples.jsonl` ledger from the cohort and stored evidence. |
| `config/` | LLM, protocol and target templates; release allowlist. |
| `data/` | Evaluation cohort (`dataset.jsonl`) and four-route summary (`dataset.csv`). |
| `tests/` | Unit tests for the pipeline and record tooling. |
| `scripts/validate-ubuntu.sh` | Ubuntu-only validation entrypoint. |
| `.github/workflows/` | Ubuntu 22.04/24.04 CI. |

Generated summaries belong in `results/`, exports in `dist/`, the fuzzing
workdir in `workdir/`, and operator evidence in `data/raw/` or `data/private/`.
These are ignored by Git.

## Design

TRIAD separates understanding from construction and verification through four
stages connected by versioned contexts (`ctx_R` → `ctx_H` → `ctx_A`):

- **M1** normalizes a report bundle into sparse typed evidence and fixes a
  route. Exact artifacts are parsed deterministically; only prose semantics go
  to the model. A trusted preflight freezes the target attestation `A_K`.
- **M2** grounds the evidence in the target source, grades relations, and emits
  ranked causal hypotheses, each compiled to a `TriggerConstraintGraph` whose
  constraints declare whether they are directly controllable, influenceable,
  observable, or environment pre-state.
- **M3** closes the graph's resource and state dependencies over the operation
  catalog, instantiates a syz-lang program plus a pre-state checklist and
  manifest, and validates that the manifest implies every required constraint.
- **M4** executes each candidate from a clean baseline, matches each condition
  (`satisfied`/`violated`/`unobserved`/`uninstrumented`), repairs the smallest
  evidenced blocker (`F1`–`F5`), and finally re-runs a frozen candidate `N_c`
  times, accepting it only when identity, manifest outcomes and trigger
  semantics hold jointly in at least `q` runs.

Back-edges carry counterevidence to the stage that owns the invalid assumption;
no non-success outcome asserts that the defect is absent.

## Requirements

- **Host:** Ubuntu 22.04 or 24.04. The pipeline and record tooling use only the
  Python standard library (Python 3.10+).
- **Kernel experiments:** Go 1.26+ and a C++ compiler (for the fuzzing runtime),
  QEMU/KVM, a built target kernel with KASAN/KCOV and the manifest-declared
  ftrace/kprobe observers, and an LLM API key.

Pipeline execution is gated to Ubuntu 22.04/24.04; the CLI refuses macOS.

## Install on Ubuntu

From the repository root on an Ubuntu 22.04/24.04 host:

```bash
# 1. System dependencies
sudo apt-get update
sudo apt-get install --no-install-recommends \
    python3 python3-venv git build-essential golang-go

# 2. Python environment
python3 -m venv .venv
. .venv/bin/activate
python3 -m triad doctor
```

`doctor` prints the OS, version, architecture and Python version.

For kernel experiments, build the fuzzing runtime (the executor, the
single-program runner `syz-execprog` and the fuzzing manager). Binaries land in
`fuzzer/bin/linux_amd64/`:

```bash
bash fuzzer/build-runtime.sh amd64
```

Check the syscall descriptions with
`fuzzer/bin/linux_amd64/syz-check -os linux -arch amd64`.

## LLM API key configuration

No key is needed for `doctor`, the offline dry-run, unit tests, record
validation or export. A key is required only for the real LLM-backed semantic
extraction (M1) and mechanism proposals (M2).

1. Create a key through the provider's official account:
   [OpenAI](https://developers.openai.com/api/docs/quickstart),
   [DeepSeek](https://api-docs.deepseek.com/), or
   [Zhipu](https://docs.bigmodel.cn/). Check model access, billing and rate
   limits, and choose an exact account-accessible model ID.
2. Read the key interactively so it is not saved as a shell command:

```bash
read -r -s -p 'API key: ' OPENAI_API_KEY
export OPENAI_API_KEY
echo
cp config/llm.example.json config/local.llm.json
```

3. Edit `config/local.llm.json` to set `model`. For another provider, change
   `provider`, `base_url` and `api_key_env`, then export the corresponding
   variable the same way:

| Provider | Base URL | Variable |
| --- | --- | --- |
| OpenAI | `https://api.openai.com/v1` | `OPENAI_API_KEY` |
| DeepSeek | `https://api.deepseek.com` | `DEEPSEEK_API_KEY` |
| GLM/Zhipu | `https://open.bigmodel.cn/api/paas/v4` | `GLM_API_KEY` |
| Compatible service | Provider's documented endpoint | `TRIAD_LLM_API_KEY` |
| Mock (offline) | — | none |

Check the configuration offline (no request, no key printed):

```bash
python3 -m triad llm-config config/local.llm.json
```

Never put a token in a committed file, command argument, prompt, result bundle
or paper appendix. Rotate any key that was ever shared.

## Usage

The pipeline accepts a JSON report bundle (see `EXAMPLE_REPORT` in
`triad/cli.py` for the shape) and a target attestation
(`config/target.example.json`).

Quick start — offline M1–M4 dry-run over the bundled running example (KASAN
use-after-free in `delete_partition`), with a deterministic mock LLM and mock
runtime; no kernel, VM, model or network work:

```bash
python3 -m triad run-example --n-c 5
```

The output is a JSON result with `terminal_outcome` (`Verified` or
`Unconfirmed-Identity`), the normalized report, route, ranked hypotheses, the
generated syz-lang program, manifest, trials, repairs, confirmation record and
the budget audit.

Run one stage at a time:

```bash
python3 tools/syz-report.py    --report path/to/report.json
python3 tools/syz-mechanism.py --report path/to/report.json
python3 tools/syz-construct.py --report path/to/report.json
python3 tools/syz-confirm.py   --runs path/to/runs.json --q 2 --n-c 5
```

Run the pipeline against a real report with a real LLM backend and a target
attestation:

```bash
python3 -m triad run path/to/report.json \
  --target config/target.example.json \
  --llm-config config/local.llm.json
```

## Experiment execution

Reproducing the paper's measured results uses the real `QemuRuntime`
(`triad/controller.py`), which delegates candidate programs to the
`syz-execprog` built by `fuzzer/build-runtime.sh`. The procedure follows
Section 6 of the paper:

1. **Prepare the target.** Build the target kernel with KASAN/KCOV and the
   manifest-declared ftrace/kprobe observers, produce a clean QEMU snapshot, and
   freeze `A_K` (id, `sourceHash`, `configHash`, `baseline`, `environment`,
   `capabilities`) into a target attestation.
2. **Attest the cohort.** Store original report evidence under `data/raw/` and
   the preflight target registry under `data/private/targets.json`, then build
   the formal ledger:

   ```bash
   python3 tools/build-dataset.py \
     --cohort data/dataset.jsonl \
     --targets data/private/targets.json \
     --out data/samples.jsonl
   ```

3. **Freeze the protocol.** Copy `config/protocol.template.json` to
   `config/local.protocol.json`, fill the source window, inclusion criteria,
   oracle policy, hardware, budgets, seeds, `(q, n_c)` and configurations, and
   set `status` to `frozen`.
4. **Run the pipeline.** For each subject × configuration × seed cell, invoke
   the pipeline with the real runtime and LLM client; record terminal outcome,
   budgets, `F1`–`F5` blockers, rounds, `clean_resets` and `joint_hits`. Keep
   seed-free trials patch/PoC-blind; each trial restores the clean baseline.
5. **Adjudicate independently.** Freeze outputs before opening the
   evaluation-only oracle (negative fixed-build differential, or two agreeing
   experts).
6. **Process records.**

   ```bash
   python3 -m triad digest config/local.protocol.json
   python3 -m triad validate \
     --protocol config/local.protocol.json \
     --samples data/samples.jsonl --runs data/runs.jsonl
   python3 -m triad report \
     --protocol config/local.protocol.json \
     --samples data/samples.jsonl --runs data/runs.jsonl \
     --output results/reviewed-run-001
   ```

   Outputs are `primary.csv`, `patch-assisted.csv`, `strata.csv`,
   `stability.csv` and `provenance.json`.

## Dataset

`data/dataset.jsonl` is the evaluation cohort: 26 real Linux kernel
memory-safety and concurrency defects collected from public CVE records and a
public syzbot report. Each line records `id`, `source`, `identifier`, `url`,
`title`, `subsystem`, `bug_class`, `cwe`, `kernel_version`, `reported_on`, and
the `analysis_available`/`seed_available`/`fix_available` routing tags.

`data/dataset.csv` summarizes the four route strata (the paper's
`tab:dataset-plan`). The cohort is the input to evaluation; measured
reproduction rates, costs and stability are produced only by running the
experiment steps above and are never pre-filled.

## Verification

```bash
bash scripts/validate-ubuntu.sh
```

This runs, in order: `doctor`, the unit-test suite (34 tests), the offline
M1–M4 dry-run, and the allowlisted release export. It is exercised on Ubuntu
22.04 and 24.04 by the CI workflow; the offline dry-run validates pipeline logic
only and is not a kernel reproduction.

Prepare an anonymous archive with:

```bash
python3 -m triad export --output dist/TRIAD-artifact-support.tar.gz
```

The export includes only the `config/release-files.json` allowlist (the vendored
`fuzzer/` tree is included as a directory entry), adds a `MANIFEST.json` with
file digests, and excludes credentials and private evidence. Automated scanning
cannot certify anonymity; review the archive before publication and do not ZIP
the whole working tree.

## Maintenance Notes

- **Source index.** M2's grounding uses an in-memory reference index; a
  production run must produce the versioned symbol/call/object-flow index from
  the target kernel source.
- **Catalog.** New syscalls or devices require syscall descriptions in
  `fuzzer/sys/linux/`, operation semantics in `triad/m3.py`, and re-validation
  with `syz-check`.
- **Instrumentation.** KASAN/KCOV and the manifest-declared ftrace/kprobe
  observers must be present in the target kernel for `L1`–`L3` feedback.
- **Confirmation.** `(q, N_c)` and the clean-baseline snapshot must be frozen
  before runs; a single trigger is never treated as stable reproduction.

## Cleanup Notes

This directory is a cleaned copy. Local build outputs (`fuzzer/bin/`,
`fuzzer/sys/gen/`), `workdir/`, `results/`, `dist/`, `data/raw/`,
`data/private/`, `config/local.*`, `.env`, `__pycache__` and `*.pyc` are removed
or ignored. `config/*.example.json` contain placeholders; replace them before
running on another host. The vendored `fuzzer/` tree is the upstream Linux
fuzzing infrastructure (Apache-2.0) with its license and attribution retained.
A license for the new TRIAD contributions has not yet been selected; select one
before redistribution.
