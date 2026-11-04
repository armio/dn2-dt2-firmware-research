# Loading your own samples

## Sample-storage setup

**R013 adds SETTINGS → SYSTEM → FORMAT SAMPLES.** This explicitly prepares
sample storage on a DN2 that has not used these sample Machines before. R012
could mount existing storage but could not create it. If sample uploads already
work, **leave the storage intact; no format is needed**.

The DN2 already contains the physical flash capacity. Stock firmware does not
expose this area as sample storage. R013 initializes a sample filesystem there;
Elektron Transfer reported about **20 GB** available on the tested DN2.

Transfer showing **0% Free / 0 bytes**, an empty Samples root or uploads stuck
at zero speed can indicate unavailable storage. Those symptoms do not prove
the area is empty; it may contain samples or data from another mod.

**FORMAT SAMPLES erases the sample-storage area, including existing samples and
other mods' data in that area.** Back up your projects, Sounds and sample files
first, and retain the original audio files. Projects referencing erased samples
will need those files restored. This is separate from stock **FORMAT +DRIVE**;
do not use that command, EMPTY RESET or FACTORY RESET for sample setup.

1. Stop playback and transfers. Close Transfer on the computer.
2. On R013, open **SETTINGS → SYSTEM → FORMAT SAMPLES**.
3. Read **ERASE SAMPLE AREA? / INCL. OTHER MODS. Y/N**. **NO** cancels without
   formatting. Press **YES** only when you intend to erase this area.
4. Keep power connected while **FORMATTING SAMPLES** is displayed.
5. When **SAMPLES FORMATTED / SWITCH OFF / ON DN2** appears, switch the DN2 off
   and back on. Sample storage remains unavailable until this restart.
6. Reconnect Transfer and check that Samples reports nonzero capacity. Then
   upload your files and load them into the project using the steps below.

If **FORMAT NOT STARTED** appears, address the accompanying reason before
retrying. If **FORMAT INCOMPLETE** appears, restart and report the error; do not
assume your previous samples remain intact. There is no automatic formatting
at boot or after a failed mount.

R013 is a candidate. On-device confirmation/cancellation, formatting, cold-start
mounting, Transfer capacity and subsequent sample uploads have been tested on
one DN2. Broader endurance testing remains pending.

Use your own mono or stereo samples; the Digitakt II factory library is not
required for playback. R013 and R012 build using only the two
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

**Playing during bulk transfers:** audio may stutter, notes may be missed, or
playback may go quiet. Stop playback before large uploads or restores and wait
until they finish before playing again. After formatting, restore the sample
files required by existing projects, then reload the project. If the problem
continues after transfers finish, report it.

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

No. R013 needs only the official DN2 and DT2 OS files to build. After installing,
upload your own samples using the steps above. A DT2 factory library is optional
playable content and is not a build input.

Older exact-build targets retain a private test-bank requirement. That bank was
created for this project; it cannot be obtained by exporting DT2 factory content.
Use R013 to avoid that historical dependency.
