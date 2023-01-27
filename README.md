<!-- SPDX-FileCopyrightText: 2023 FC Stegerman <flx@obfusk.net> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

[![CI](https://github.com/obfusk/sigblock-code-poc/workflows/CI/badge.svg)](https://github.com/obfusk/sigblock-code-poc/actions?query=workflow%3ACI)
[![GPLv3+](https://img.shields.io/badge/license-GPLv3+-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)

# android apk signing block payload poc

PoC for an Android app that reads the APK Signing block of its own APK and
extracts a payload to alter its behaviour.

Whether the payload is present or not does not affect the validity of the
signature.

NB: uses the work-in-progress [`apksigtool`](https://github.com/obfusk/apksigtool)
to add the PoC block to the APK.

## Example

Generate a dummy keystore:

```bash
$ keytool -genkey -keystore dummy-ks -alias dummy -keyalg RSA \
    -keysize 4096 -sigalg SHA512withRSA -validity 10000 \
    -storepass dummy-password -dname CN=dummy
```

Build a release APK:

```bash
$ ./gradlew assembleRelease
```

Sign it with the dummy key:

```bash
$ cp app/build/outputs/apk/release/app-release-unsigned.apk poc.apk
$ apksigner sign -v --ks dummy-ks --ks-key-alias dummy poc.apk
```

Add the payload:

```bash
$ echo 'This is the payload' > payload
$ ./add_poc.py poc.apk payload
```

Install on phone:

```bash
$ adb install poc.apk
```

## License

[![GPLv3+](https://www.gnu.org/graphics/gplv3-127x51.png)](https://www.gnu.org/licenses/gpl-3.0.html)

<!-- vim: set tw=70 sw=2 sts=2 et fdm=marker : -->
