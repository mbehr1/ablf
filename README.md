# ablf - Rust automotive binlog files (Vector .blf) handling library / crate

This library is a clean-room implementation based on information from the header file of the

"Read Write BLF API 2018 Version 8" found e.g. here: https://forums.ni.com/t5/Example-Code/Read-and-Write-BLF-Files/ta-p/3549766

## FEATURES

Open/decode blf files
 - that are zlib/deflate compressed
 - iterate over all objects (outer ones and the first level of container ones)
 - decoding of CAN messages objects

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

The test files under tests/technica are from the repo https://github.com/Technica-Engineering/vector_blf/tree/master/src/Vector/BLF/tests/unittests/ and are licensed under GPLv3. They are only used as test/input data and thus the library itself is not a derived work in the copyright sense.

## Contribution

Any and all test, code or feedback contributions are welcome.
Open an [issue](https://github.com/mbehr1/ablf/issues) or create a pull request to make this library work better for everybody.

[![Donations](https://www.paypalobjects.com/en_US/DK/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=2ZNMJP5P43QQN&source=url) Donations are welcome!

[GitHub ♥︎ Sponsors are welcome!](https://github.com/sponsors/mbehr1)

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
