psb - Extracts files from alldata.psb/alldata.bin. 
Usage: psb path/to/alldata.psb (or alldata.psb.m). 
Notes:
- Currently expects alldata.bin to be in the current working directory
- Currently does not have the ability to create any directories, including the outer `unpacked` directory it expects

m2decrypt - Deobfuscates a binary (typically has a .m extension)
Usage: m2decrypt path/to/some/file.m

mecd_decode - Translates MECD format image to ISO/BIN/CUE
Usage: mecd_decode path/to/some/file.mcd
Notes:
- Compressed data track is saved to data.bin, must be decompressed with a tool like unzstd
- Audio is decoded to raw 48 kHz audio in audio.bin, must be externally resmplaed to 44.1 kHz
- Table of contents written to image.cue
