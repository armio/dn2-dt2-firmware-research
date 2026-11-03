# Loading your own samples

These instructions apply to an already installed R011 or T1E2 custom firmware. You can
use your own mono or stereo samples; the Digitakt II factory library is not
required for playback. This guide does not remove the [private build-input
requirement](../README.md#private-inputs).

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
project or assign them to a track. Use ordinary audio files such as WAV, not
the build's private `sample-bank.bin`. Transfer handles its own audio-format
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

R011 has a new report of a track-2 sample assignment not surviving project loads.
The cause and scope remain unconfirmed. Save the project after assigning a
sample, retain the original file on +Drive, and keep a backup while this is
investigated. A successful transfer alone does not save project assignments.

- **Visible in Transfer, absent from SAMP:** check +Drive in Sample Manager and
  load the file into the project first.
- **Transfer cannot see DN2:** check both MIDI port selections, USB mode and the
  data cable. Reconnect to a working computer USB port if necessary.
- **Loaded but silent:** check track mute, selected sample slot, sample level,
  AMP volume/envelope and filter settings. For loops, set BARS to the actual
  loop length before judging tempo synchronization.

Transfer's [official sample-pack instructions](https://support.elektron.se/support/solutions/articles/43000622449-how-to-install-and-load-sound-packs-to-your-elektron-device)
describe the computer-side EXPLORE workflow. The DN2 VOICE/SYN mapping above is
specific to this port; Elektron's DT2 manual uses SAMPLING/SRC for those pages.

## Does owning a DT2 supply the build's sample bank?

No. The required 47,104-byte bank is this project's private test asset, not the
DT2 factory library, a factory-content download or an export from a DT2.
Uploading your own samples after installation is independent of that build
dependency. The current exact-build recipes still require the original private
bank; there is no public substitute supported by the builder.
