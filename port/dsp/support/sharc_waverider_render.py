"""Build-only compatibility for original DSP generators; no device APIs."""
import os
import pathlib
import shlex
import subprocess
import sys

SELAS = os.environ.get('SELAS', 'selas')


def _wsl_path(path):
    return shlex.quote(str(path))


def _wsl(command, work):
    # Historical callers overwrite SELAS with workspace-specific paths.
    # Always use the explicitly selected executable, without a shell.
    args = shlex.split(command)
    if not args or '-proc' not in args or args[args.index('-proc') + 1] != 'ADSP-21569':
        raise ValueError('Only the pinned SHARC assembler is supported')
    args = [os.environ['DSP_RELEASE_SELAS'], *args[args.index('-proc'):]]
    return subprocess.run(args, cwd=work, capture_output=True, text=True, check=False)


class Digikit:
    """Decoder-only view of the explicitly supplied, pinned Digikit checkout."""

    def __init__(self, historical_path):
        path = pathlib.Path(os.environ['DIGIKIT'])
        sys.path.insert(0, str(path / 'tools'))
        import sharc_trace
        import sharcldr
        self.st, self.ldr = sharc_trace, sharcldr

    def walk(self, memory, start_sw, end_sw):
        out, pc = [], start_sw
        while pc < end_sw:
            insn = self.st.decode_at(memory, None, pc)
            out.append((pc, (insn.length_bytes or 0) // 2, insn.type_name, insn.kind))
            if not insn.length_bytes:
                break
            pc += insn.length_bytes // 2
        return out
