# Source attribution

The firmware-port research and build glue are distributed under
AGPL-3.0-or-later; see [LICENSE](LICENSE). Preserve the component notices below.
No licence to Elektron's firmware or private sample audio is granted by this
repository. Those inputs and generated firmware remain outside the public tree.

* [angellinares/dn2_firmware_explore](https://github.com/angellinares/dn2_firmware_explore):
  AGPL-3.0-or-later. The vendored `port/tools/dnfw` snapshot includes research
  additions; its source manifest distinguishes the comparison revision from
  added or modified modules. USB probe assembly retains its irpina/digihealth
  attribution and GPL-2.0-or-later notice.
* [mischa85/elektron-firmware-tool](https://github.com/mischa85/elektron-firmware-tool):
  MIT, copyright 2026 Marcel Bierling. Source, licence and the local ELE3
  section-alignment patch are in `port/tools/elektron-firmware-tool`.
* [m-dwyer/digikit](https://github.com/m-dwyer/digikit): GPL-2.0-or-later;
  fetched at the pinned revision, not bundled.
* [js216/selache](https://github.com/js216/selache): GPL-3.0-only, with MIT
  `libsel`; fetched at the pinned revision, not bundled.
* [grame-cncm/faustlibraries](https://github.com/grame-cncm/faustlibraries/blob/b0e363a602a48eaced21e3838ba3f742dfd54c94/vaeffects.lib):
  `oberheim` by Eric Tarr and cubic soft clipping by Julius O. Smith III, MIT-style
  STK-4.3 licence. The adapted SEM kernel and the full STK notice are in
  `port/sem-filter/tree/src/sem_filter`.
* [SpotlightKid/faustfilters](https://github.com/SpotlightKid/faustfilters/tree/00cb332796b57487e5e0f384cb624345ca938561):
  generated `Oberheim.cpp`/`.hpp` by Christopher Arndt, used unchanged as a host
  comparison reference. Their headers declare the MIT-style STK-4.3 licence; the
  repository's ISC notice is retained in
  `port/sem-filter/tree/src/sem_filter/reference/LICENSE`. The compiled SEM kernel
  served in the browser recipe carries `sem-kernel-LICENSE.txt` on the site.
* GNU binutils: GPL-3.0-or-later and component notices; fetched from GNU and
  verified by archive hash, not bundled.
* [naturarum/dn2-cfw](https://github.com/naturarum/dn2-cfw): GPL-2.0-or-later.
  The experimental source-store audit adapts its store-tracing method; recovery
  check categories also credit its brick-check research. Notices, pinned source
  revision and GPL text are retained under `research/audits`.
* [complex-ping/digitone-2-modding-skill](https://github.com/complex-ping/digitone-2-modding-skill):
  MIT, copyright 2026 Julian Kominiak. Its SHARC-rule research informed the
  experimental instruction checker; the pinned revision and full MIT notice
  remain in `research/audits/dn2_sharc_rules.py`.

Exact revisions and provenance manifests are under `port/tools`. Compatibility
addresses, hashes and instruction-boundary metadata accompany extraction
recipes; actual donor instructions and assets come from local private inputs.
