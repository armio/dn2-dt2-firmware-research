const $ = (id) => document.getElementById(id);
const selected = new Map();
const revisions = new Map();
let release, worker, outputURL, buildRevision = 0;
const hex = (buffer) => Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, '0')).join('');
const digest = async (buffer) => hex(await crypto.subtle.digest('SHA-256', buffer));

function clearOutput() {
  if (outputURL) URL.revokeObjectURL(outputURL);
  outputURL = null;
  $('download').removeAttribute('href');
  $('result').hidden = true;
}

function setError(message = '') {
  $('error').textContent = message;
  $('error').hidden = !message;
}

function updateReady() {
  $('build').disabled = !!worker || !release || selected.size !== 2;
}

async function selectFile(key) {
  const revision = (revisions.get(key) || 0) + 1;
  revisions.set(key, revision);
  selected.delete(key);
  clearOutput();
  setError();
  updateReady();
  $('progress').value = 0;
  $('build-status').textContent = 'Select both files to begin.';
  const file = $(key).files[0];
  const zone = $(`${key}-zone`), status = $(`${key}-status`);
  zone.classList.remove('valid', 'invalid');
  if (!file) { status.textContent = ''; return; }
  status.textContent = 'Checking file…';
  try {
    const expected = release.inputs[key];
    if (!file.name.toLowerCase().endsWith('.syx')) throw new Error('Choose the extracted .syx file, not a ZIP archive.');
    if (file.size !== expected.bytes) throw new Error('File size does not match the required official OS. Check the version and choose its original .syx file.');
    const actual = await digest(await file.arrayBuffer());
    if (revisions.get(key) !== revision) return;
    if (actual !== expected.sha256) throw new Error('This file does not match the required official OS. Use an unmodified copy of the version shown above.');
    selected.set(key, file);
    zone.classList.add('valid');
    status.textContent = `${file.name} — verified`;
  } catch (error) {
    if (revisions.get(key) !== revision) return;
    zone.classList.add('invalid');
    status.textContent = error.message;
  }
  if (selected.size === 2) $('build-status').textContent = 'Files verified. Ready.';
  updateReady();
}

function stopWorker() {
  worker?.terminate();
  worker = null;
  $('inputs').disabled = false;
  $('cancel').hidden = true;
  updateReady();
}

$('cancel').addEventListener('click', () => {
  buildRevision++;
  stopWorker();
  clearOutput();
  $('progress').value = 0;
  $('build-status').textContent = 'Cancelled. Ready to try again.';
});

$('build').addEventListener('click', async () => {
  if (worker || selected.size !== 2 || !release) return;
  const revision = ++buildRevision;
  clearOutput();
  setError();
  $('inputs').disabled = true;
  $('cancel').hidden = false;
  $('build-status').textContent = 'Preparing local build…';
  $('progress').value = 0;
  const fail = (message) => {
    if (revision !== buildRevision) return;
    stopWorker();
    clearOutput();
    setError(message);
    $('build-status').textContent = 'Build failed.';
  };
  try {
    worker = new Worker('./build-worker.js', {type: 'module'});
    updateReady();
    worker.onerror = (event) => { event.preventDefault(); fail('The local builder could not run. Reload the page and retry in a current browser.'); };
    worker.onmessage = async ({data}) => {
      if (revision !== buildRevision) return;
      if (data.type === 'progress') {
        $('build-status').textContent = String(data.message || 'Building…');
        if (Number.isFinite(data.progress)) $('progress').value = Math.max(0, Math.min(100, data.progress));
      } else if (data.type === 'error') {
        fail(String(data.message || 'The build failed its checks.'));
      } else if (data.type === 'complete') {
        try {
          $('build-status').textContent = 'Verifying the completed firmware…';
          if (!(data.buffer instanceof ArrayBuffer) || data.buffer.byteLength !== release.outputs.sysex_bytes) throw new Error('Output size verification failed. The firmware cannot be downloaded.');
          const actual = await digest(data.buffer);
          if (revision !== buildRevision) return;
          if (actual !== release.outputs.sysex_sha256) throw new Error('Output hash verification failed. The firmware cannot be downloaded.');
          stopWorker();
          outputURL = URL.createObjectURL(new Blob([data.buffer], {type: 'application/octet-stream'}));
          $('download').href = outputURL;
          $('download').download = `Digitone_II_OS1.11_DT2_SAMPLERS_${release.build}_PUBLIC.syx`;
          $('output-hash').textContent = actual;
          $('result-summary').textContent = `${release.build} · ${data.buffer.byteLength.toLocaleString()} bytes · Verified`;
          $('result').hidden = false;
          $('progress').value = 100;
          $('build-status').textContent = 'Verified. Ready to download.';
          $('download').focus();
        } catch (error) { fail(error.message); }
      }
    };
    const [dn2, dt2] = await Promise.all(['dn2', 'dt2'].map((key) => selected.get(key).arrayBuffer()));
    if (revision !== buildRevision) return;
    worker.postMessage({type: 'build', inputs: {dn2, dt2}}, [dn2, dt2]);
  } catch (error) { fail(error.message); }
});

for (const key of ['dn2', 'dt2']) $(key).addEventListener('change', () => selectFile(key));

try {
  if (!crypto.subtle) throw new Error('Open this page over HTTPS or localhost to enable file verification.');
  const response = await fetch('./release.json', {cache: 'no-cache'});
  if (!response.ok) throw new Error('The build manifest is unavailable. Reload the page before choosing files.');
  const candidate = await response.json();
  if (!/^R\d{3}$/.test(candidate.build) || !Number.isSafeInteger(candidate.outputs?.sysex_bytes) || candidate.outputs.sysex_bytes <= 0 || !/^[a-f0-9]{64}$/.test(candidate.outputs?.sysex_sha256)) throw new Error('The build manifest is incomplete. This release is not ready to build.');
  for (const key of ['dn2', 'dt2']) {
    const input = candidate.inputs?.[key];
    if (!Number.isSafeInteger(input?.bytes) || input.bytes <= 0 || !/^[a-f0-9]{64}$/.test(input?.sha256)) throw new Error('The input manifest failed validation.');
  }
  release = candidate;
  $('release-name').textContent = release.build;
  const stable = release.status === 'stable';
  const storageWarning = Boolean(release.first_install_warning);
  $('release-status').textContent = storageWarning ? `${release.build} · First-time storage setup missing. New users should wait.` : stable ? 'Stable release.' : `${release.build} candidate · Owner-tested; USB audio untested. R012 remains stable.`;
  $('release-status').classList.toggle('candidate', !stable || storageWarning);
  $('release-notes').href = `https://github.com/armio/dn2-dt2-firmware-research/blob/main/releases/${release.build.toLowerCase()}.json`;
  $('inputs').disabled = false;
} catch (error) {
  $('release-name').textContent = 'Build unavailable';
  $('release-status').textContent = error.message;
  setError(error.message);
}
