# R023–R027 SEM filter

Sources for the SEM filter continuation from exact R022. User guide:
[docs/sem-filter.md](../../docs/sem-filter.md). Release:
[releases/r027.json](../../releases/r027.json).

| Build | Section | Source |
| --- | --- | --- |
| R023 | ColdFire MAIN | `tree/scripts/build_dn2_sem_filter_r023.py`, `r023_sem_filter.py`: filter ID 6, controls, menu entry |
| R023–R025 | DSP | `tree/scripts/build_dn2_sem_kernel.py` and `tree/src/sem_filter/`: Faust-derived kernel compiled with pinned selache |
| R024 | DSP | `tree/scripts/build_dn2_sem_dsp.py`: SHARC adapter, dispatch tables, register contract (`sem_register_contract.py`) |
| R025 | DSP | `tree/scripts/build_dn2_right_gate.py`: right effects chain only for sampler voices |
| R024, R025 | ColdFire MAIN | `build_dn2_sem_efficiency_r024.py`, `build_dn2_right_gate_r025.py`: build identity only |
| R026 | ColdFire MAIN | `build_dn2_sem_graph_r026.py`, `r026_sem_graph.py`, `sem_graph_reference.py`: response graph |
| R027 | ColdFire MAIN | `build_dn2_sem_type_r027.py`, `r027_sem_type.py`: TYPE widget icons |

`tree/scripts/build_dn2_recovery_tail.py` is the recovery-tail helper with R023–R027
registered. `tree/scripts/check_sem_filter_host.py` compares the C kernel with the
unchanged Faust-generated reference on the host.

The DSP chain was rebuilt from these sources on 2026-11-11: kernel
`b55266440e4e…`, R024 DSP `b5ba74131db8…` and R025 DSP `1b858714c2ef…`, all equal
to the shipped images. These scripts use the same workspace layout and shared
helpers as `port/dsp` and `port/sampler-fixes`; `build.py` does not run them yet.
The browser recipe reproduces the exact R027 output from the two official OS files.

Firmware-derived data tables and graphics stay out of the recipe: the SEM
adapter's two replayed native instructions and the dispatch-table pointers are
copied from the user's DSP; the R026 graph's log-cutoff table and the R027 TYPE
icon planes are computed from the user's DN2 OS during the build. The sources do
contain factual interface data (addresses, stock filter IDs and their menu order)
and short authored instruction sequences that repeat native calling sequences and
frames, as earlier revisions in this repository do; R027's comments mark its repeated frames.

Workspace notes: `sem_graph_reference.py` reads the R025 DSP that
`build_dn2_right_gate.py` writes to `output/dn2-research/r025-right-gate-20261109/dsp/`
in the build workspace. Some docstrings and `src/sem_filter/README.md` cite internal
design notes and emulator checkers (`docs/DN2-R02x-*`, `check_dn2_sem_*.py`) that are
not part of this repository.

Licences: the kernel adapts Faust `vaeffects.lib` `oberheim` (Eric Tarr) and cubic
soft clipping (Julius O. Smith III) under the MIT-style STK-4.3 licence, kept in
`tree/src/sem_filter/LICENSE-STK-4.3.md`. The generated reference keeps its
notice in `tree/src/sem_filter/reference/`. Everything else follows this
repository's licence.
