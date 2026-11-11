# SEM filter

R027 adds **SEM** as a seventh filter type on the Digitone II, next to the stock
filters. It is available on every Machine: FM TONE, WAVETONE, FM DRUM, SWARMER and the
six sample Machines.

SEM follows the Oberheim SEM-style state-variable filter from
[Faust's `vaeffects.lib`](https://github.com/grame-cncm/faustlibraries/blob/b0e363a602a48eaced21e3838ba3f742dfd54c94/vaeffects.lib)
(`oberheim`, by Eric Tarr), with cubic soft clipping in its integrators. It is a
SEM-family virtual-analog model, not a measured copy of a particular instrument.

## Playing it

Choose **SEM** in the track's FILTER selection menu, where the stock filter types
are listed. The usual controls drive it:

| Control | SEM behaviour |
| --- | --- |
| **FREQ** | Cutoff, through the DN2's own cutoff curve, including keytracking, filter envelope and modulation |
| **RESO** | Resonance, Q 0.5 to 10 |
| **TYPE** | Response; see below |
| Filter envelope, keytracking, LFOs, parameter locks | As on the stock filters |

| TYPE | Response |
| --- | --- |
| 0 | Low-pass |
| 1–62 | Low-pass blending toward notch |
| 63 | Notch |
| 64–125 | Notch blending toward high-pass |
| 126 | High-pass |
| 127 | Band-pass |

Every voice keeps its own left and right filter state. Changing the filter type
or reinitializing the engine clears that state; parameter changes and note
retriggers keep it, as the stock filters do.

## What the screen shows

- **Response graph (R026).** The FILTER page draws SEM's computed magnitude
  response for the current FREQ, RESO and TYPE (3 dB per pixel row), instead of
  a fixed schematic. In the emulator the firmware draws exactly its integer
  model (11,520 settings), and that model stays within one pixel row of a
  floating-point reference across 92,416 settings, except that the marked
  notch or cutoff column can move by one.
- **TYPE control (R027).** For TYPE 0–126 the TYPE control shows
  **LP · NOTCH · HP** icons over the stock slider and marker. At TYPE 127 it
  shows the band-pass icon alone. Other filters keep the stock LP · BP · HP
  icons. The SEM icons appear on the FILTER page only.

## Status

R027 is an **owner-tested candidate**, not an instrumented release. R012
remains the stable target.

- R023 and R024, the first SEM builds, overloaded the DSP on hardware (audio
  breakup with many SEM voices). They were never published.
- R024 made SEM's sample loop cheaper (a settled 32-sample block went from 5,390
  to 1,755 emulated instructions). R025 then ran the relocated right effects
  chain only for sampler voices, which the emulator identifies as the cause of
  the overload. The emulator predicts about 81.7% of the DSP block with SEM on
  16 voices; that model excludes interrupts, cache, DMA and USB. The owner
  reported R025 working after that change; no hardware timing capture has been
  taken yet.
- One known side effect of R025: when a sampler voice takes over a slot from an
  FM voice, the one block of leftover right-channel audio that R024 produced is
  gone.
- The owner reported the R026 graph and R027 TYPE icons matching their
  emulator previews.

### Known limits

- **USB audio is untested on R027.** It was reported broken on R023/R024 during
  the overload and has not been rechecked since. Stay on R012 if you rely on it.
- Heavy SEM use alongside many sampler voices, long sessions and full polyphony
  are not yet measured on hardware.
- Sounds and projects saved with SEM store its filter as ID 6. How firmware
  without SEM (the stock OS, R022 and earlier) handles that ID is untested;
  switch those tracks to a stock filter before going back.
- The port smooths the prewarped cutoff coefficient instead of recomputing it
  every sample. Steady settings match Faust's output (maximum error about
  3.7 × 10⁻⁶ over 144 compared settings); fast modulation follows a slightly
  different path than Faust's own wrapper.

- If Transfer stays on **SUCCESS! REBOOTING** after installing, switch the DN2
  off and on; it then boots the new OS.

## Building

The [browser patcher](https://armio.github.io/dn2-dt2-firmware-research/)
builds R027 from your official DN2 OS 1.11 and DT2 OS 1.16 files. Two small
tables are computed locally from your DN2 OS during that build: the graph's
log-cutoff table, from the DN2's own cutoff curve, and the TYPE icons, from the
stock TYPE icons. The published recipe contains only the formulas, not those
values.

Sources: [port/sem-filter](../port/sem-filter/README.md) (the SEM kernel, its
SHARC adapters and the R023–R027 revision builders). The command-line builder
does not build R023–R027 yet.

## Credits

- Eric Tarr, `oberheim` in Faust's `vaeffects.lib`; Julius O. Smith III, cubic
  soft clipping. MIT-style STK-4.3 licence, kept in
  `port/sem-filter/tree/src/sem_filter/LICENSE-STK-4.3.md`.
- Christopher Arndt, the generated `Oberheim.cpp` reference from
  [faustfilters](https://github.com/SpotlightKid/faustfilters/tree/00cb332796b57487e5e0f384cb624345ca938561),
  used only for host comparison; its notice is kept in `reference/`.
