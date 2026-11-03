# Loading your own samples

## First-time installation warning

**2026-11-03: new users should wait for the sample-storage setup fix.** R012
mounts an existing sample filesystem but does not create it on a previously
unprepared DN2. Our owner testing used storage initialized during development;
it missed this first-install case.

Symptoms can include **0% Free / 0 bytes** in Transfer, an empty Samples root,
uploads stuck at zero speed, and **Connection failed**. These symptoms alone
do not establish whether storage is uninitialized, damaged, or occupied by
another mod. A zero-capacity display is not proof that the physical drive is full.

Do **not** use the stock **FORMAT +DRIVE**, EMPTY RESET or FACTORY RESET as a
workaround. They can erase projects or presets and do not provide the missing
sample-filesystem setup. If sample uploads already work, leave the storage intact.

An explicit on-device sample-storage formatter with erase confirmation is in
development. It has not yet passed hardware validation or been released. The
candidate will be tested on our DN2 before publication. No automatic formatting
is being added on a failed mount.

The loading instructions below require initialized, working sample storage.

These instructions apply to R012, R011 and T1E2 custom firmware. Use your own
mono or stereo samples; the Digitakt II factory library is not required for
playback. R012 also builds without a private sample bank, using only the two
[official OS inputs](../README.md#private-inputs).

## 1. Transfer samples to +Drive

1. Boot the DN2 into normal playing mode and connect it to the computer by USB.
2. In **SETTINGS → SYSTEM → USB CONFIG**, select **USB MIDI** or **USB AUDIO/MIDI**.
3. Open [Elektron Transfer](https://www.elektron.se/support-downloads/transfer).
   Select **Digitone II** for both MIDI IN and MIDI OUT, then connect.
4. Open **EXPLORE**. Choose **My Computer** on the left and **Samples** for the
   device on the right.
5. Drag your sample files or folders into the desired device folder. Using
   EXPLORE lets you choose their destination. Wait for the transfer to finish.

This stores files on +Drive. It does not automatically load them into the active
project or assign them to a track. Use ordinary audio files such as WAV.
Transfer handles its own audio-format
conversion; manually converting files first is not required for this workflow.

## 2. Load samples into the project

1. From a track page, press **VOICE** once for Voice Setup, then again for
   **Sample Manager**. Use plain VOICE; FUNC + VOICE remains the unison shortcut.
2. Select **+DRIVE**, press **YES**, and navigate to the folder used in Transfer.
3. Highlight a sample. **FUNC + YES** previews it through the active track;
   use an unmuted sample-Machine track for this check.
4. Press **YES** to mark the samples you want. Press **RIGHT** to open sample
   actions, choose **LOAD TO PROJECT**, then press **YES**.
5. Wait for loading to finish. The samples now occupy project sample slots.

## 3. Assign a sample to a track

1. Select the destination track. Use **FUNC + SYN** to choose a sample Machine,
   such as **ONESHOT**.
2. Open **SYN** and turn **SAMP** to open the project sample list.
3. Highlight the loaded sample and press **YES** to assign it.
4. For a first ONESHOT check, use **PLAY FWD**, **STRT 0**, **LEN 120** and an
   audible sample level. Trigger a note on the unmuted track.
5. Save the project after loading and assigning samples so its assignments are
   retained when you reload it.

The quick-assign route is also available: from the SYN SAMP list, press
**FUNC + YES** to browse +Drive, find a sample, then press **YES** to load it into
the project and assign it to the active track.

## If a sample is missing or silent

Save the project after loading and assigning samples. A successful transfer
alone does not save project assignments; retain the original files on +Drive.

- **Visible in Transfer, absent from SAMP:** check +Drive in Sample Manager and
  load the file into the project first.
- **Assignment missing after reload:** confirm the project was saved after
  loading and assigning the sample.
- **Transfer cannot see DN2:** check both MIDI port selections, USB mode and the
  data cable. Reconnect to a working computer USB port if necessary.
- **Loaded but silent:** check track mute, selected sample slot, sample level,
  AMP volume/envelope and filter settings. For loops, set BARS to the actual
  loop length before judging tempo synchronization.

Transfer's [official sample-pack instructions](https://support.elektron.se/support/solutions/articles/43000622449-how-to-install-and-load-sound-packs-to-your-elektron-device)
describe the computer-side EXPLORE workflow. The DN2 VOICE/SYN mapping above is
specific to this port; Elektron's DT2 manual uses SAMPLING/SRC for those pages.

## Do I need the DT2 factory samples?

No. R012 needs only the official DN2 and DT2 OS files to build. After installing,
upload your own samples using the steps above. A DT2 factory library is optional
playable content and is not a build input.

Older exact-build targets retain a private test-bank requirement. That bank was
created for this project; it cannot be obtained by exporting DT2 factory content.
Use R012 to avoid that historical dependency.
