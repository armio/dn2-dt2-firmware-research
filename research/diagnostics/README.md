# Bounded USB publication diagnostics

These host tools read the experimental R007 and R008 diagnostic publications.
They do not fix the USB fault. T1E2 remains the stable default; R008 is a
hardware-unvalidated diagnostic build.

R007 reads accepted/rejected publication counters and codec/handler context.
R008 adds immutable rejection/post-check journals and per-predicate counters.
Its decoder requires complete coverage, matching snapshot identity, consistent
duplicates, valid field masks and a matching checksum. Partial records remain
in the local capture but are not interpreted as identified faults. Counter
banks come from different snapshot times; they must not be combined into a
simultaneous histogram.

## Capture

Requires Python 3.12+, `mido` and `python-rtmidi`, plus an exact matching private
build tree. Decoder tests use only the standard library. The transport's
exclusive-process lock uses POSIX `fcntl` (macOS/Linux).

```sh
python3 -m pip install mido python-rtmidi
python3 research/diagnostics/capture_dn2_r008_diagnostic.py \
  --build-dir /private/path/to/R008-work \
  --out /private/path/to/new-r008-capture \
  --seconds 54
```

Use normal playing mode with Recorder closed. The tool does not start/stop
playback or open an audio device. Leave any desired USB audio stream running
in the host application. `--port` accepts the exact MIDI input/output name;
its default is `Elektron Digitone II`. Only one capture client should run.

`--build-dir` must contain `main/expanded/{build-receipt.json,main-os.bin,runtime.bin}`
and `dsp/{build-receipt.json,section_7.bin}`. Local hashes and receipt identity
are checked before opening MIDI. Live MAIN hook bytes are compared with that
build. The tools do **not** read or verify the entire live DSP image.

The output directory must be new and outside this source repository. Captures
contain device memory, timing and wire bytes; keep them private. Do not upload
raw capture files, recordings or private build trees to this repository.

Only HELLO and fixed allowlisted PEEK requests can be transmitted. No memory
writes, sample loads, notes, transport commands, screen requests or flashing
are implemented. Requests have deadlines and are never retried. R007 permits
6–30 seconds of observation, with a 40-second hard host deadline and 36 extra
phase reads. R008 permits 12–54 seconds, with a 60-second deadline, 550 extra
reads and 1,000 requests total. Neither tool enables continuous polling.

Diagnostic requests still consume device time. These bounds limit interference;
they do not prove that capture is timing-neutral. A rejection reason or a
post-check crossing identifies a failed predicate, not necessarily audible
corruption. Retained maxima describe the period since boot, not the current
capture alone.

For an existing matching R007 private build, replace `r008` with `r007` and use
its own `--build-dir`; the default observation interval is 24 seconds.

## Offline tests

```sh
python3 -B -m unittest discover -s tests -v
```

The R007/R008 tests use synthetic headers and snapshots. Transport tests verify
command/read allowlists, deadlines, no retries and reply validation without
opening hardware. No firmware bytes, audio or captured device data are test
fixtures. Source provenance records the original project helper files and
publication adaptations.
