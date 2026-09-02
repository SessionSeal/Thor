Sample files for testing the Music Provenance MVP web app (http://localhost:3000)

SEAL A TRACK (section 1):
  master.wav            -> "Master" field
  stem_bass.wav         \
  stem_chords.wav        > select all three in the "Stems" field
  stem_drums.wav        /
  TestSong.logicx.zip   -> "Project" field
  Expected: coherence VERIFIED with confidence ~0.99.

MISMATCHED STEMS (coherence should FAIL):
  Upload master.wav with alt_stem_*.wav as the stems instead.
  Expected: coherence NOT verified, confidence ~0.74.

VERIFY A COPY (section 2):
  streamed.mp3          -> an MP3 re-encode of master.wav, simulating what a
                           streaming platform serves. Upload it after sealing;
                           it should re-link to the record with ~0.99 confidence
                           even though every byte differs from the sealed WAV.

LOGIC PROJECT INSPECTOR (http://localhost:3000/logic):
  DemoProject.logicx      -> pick this folder with the page's folder picker
  DemoProject.logicx.zip  -> or upload the zip instead
  A synthetic Logic package with plists (incl. an NSKeyedArchiver archive),
  a QuickLook thumbnail, WAV with bext/iXML/INFO/cue chunks, AIFF, CAF, and
  ProjectData blobs salted with track/plugin names and file paths.
  TestSong.logicx.zip from the provenance flow works here too.
