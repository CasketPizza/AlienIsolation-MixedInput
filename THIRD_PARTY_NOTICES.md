# Third-party notices

## Ultimate ASI Loader

Nexus release archives include the x86 build of
[Ultimate ASI Loader v9.0.0](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/tag/v9.0.0)
by ThirteenAG. Ultimate ASI Loader is a separate project and is not
incorporated into the Mixed Input source code.

Exact official asset:

<https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/v9.0.0/Ultimate-ASI-Loader.zip>

Verification:

```text
Official ZIP SHA-256:
915ef34e75177c434b7b41d9eae195af4d9f1ea1fab5d119d2104f5bd3263d05

Bundled loader SHA-256:
f8a9852c0a26e356b095661f6b85079f6f95098558f5c3453d9a96fc8cceb28e
```

The official x86 archive contains `dinput8.dll`. The Nexus package contains the
exact same binary bytes under the filename `xinput1_3.dll`, which is the proxy
name used for this Alien: Isolation installation. Only the filename differs;
the binary has not been modified.

MIT License

Copyright (c) 2023 ThirteenAG

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
