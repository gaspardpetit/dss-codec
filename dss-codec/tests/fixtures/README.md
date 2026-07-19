# Test fixtures

These files exist solely for codec regression testing.

## Grundig DSS-SP

- `grundig_sample.dss`
- `grundig_sample_16k.wav`

These fixtures were contributed by Guillain-RDCDE in upstream pull request
[hirparak/dss-codec#12](https://github.com/hirparak/dss-codec/pull/12). The WAV
was produced by the genuine Grundig DigtaSoft reference decoder. The integration
test requires this project to reproduce it byte-for-byte.

## Encrypted Olympus DS2

- `encrypted_aes128.ds2`
- `encrypted_aes128_reference.wav`
- `encrypted_aes256.ds2`
- `encrypted_aes256_reference.wav`

The encoded files are the free DSS Pro samples published by Dictate Australia
on 13 June 2018:

<https://dictate.com.au/blogs/news/download-ds2-audio-file-samples-dss-pro>

With original filenames:

- `Sample_DS2_Audio_File_-_128bit_Encryption_-_Password_is_1234.ds2`
- `Sample_DS2_Audio_File_-_256bit_Encryption_-_Password_is_1234.ds2`

Both use the password `1234`, as documented on the source page.

The corresponding WAV files are reference wavs obtained using the vendor's DLLs.

## Grundig Digta 7 / DS2 QP7

- `grundig_digta7_qp7.ds2`

This format-7 sample was shared by Dominique Heer (`heer-gielisch`) in
[hirparak/dss-codec#13](https://github.com/hirparak/dss-codec/issues/13) after
being recorded with a Grundig Digta 7. Its original filename was
`broken_DICT0822.DS2`; “broken” refers to the decoder not supporting format 7
when the issue was opened.

The decoded audio was manually reviewed and confirmed to sound correct, but no
vendor-generated reference WAV is available. The regression test therefore
locks the detected format, native rate, sample count, and decoded PCM hash; it
does not claim vendor bit-exactness.

SHA-256: `e4287f81ae24d20ee34185e77c2f2e554e4c790c0ace18963c27cb54d1e3ee84`
