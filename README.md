# vita-ida-physdump

![Screenshot](https://i.imgur.com/FFntTpG.png)

## Installation

Copy **contents** of this directory into your `IDA 7.0/loaders` directory.

Place [db.yml](https://raw.githubusercontent.com/vitasdk/vita-headers/master/db.yml) into the directory with your physical dump.

## Usage

Obtain a physical memory dump from a Vita running 3.60 (other versions are not supported).

You should dump physical addresses in the [0x40200000; 0x5FD00000) range. ([wiki](https://wiki.henkaku.xyz/vita/Physical_Memory))

When opening a physical dump, this loader should be selected by default. You don't need to do anything, just click "OK".

## Features

1. Physical dump loading
2. Modules are found and detected with import/export parsing
3. `db.yml` from vitasdk used for NID resolving
4. A comment is added to every exported function so you can see if it's exported multiple times using different NIDs/libnids
5. System instructions like MRC/MCR are automatically commented
6. MOVT/MOVW pairs are detected and appropriate xrefs are added

## Caveats, known bugs, etc

If you load a binary, go to an imported function and decompile it BEFORE decompiling any function that calls into it, it will break its return and arglist detection. Don't do that - there's no reason to.

MOVT/MOVW xrefs detection is not ideal, it does not follow branches.

The list of NORETURN functions is not complete, sometimes IDA will merge two functions into one.

Sometimes, it will create a huge function if module exports end and another module begins. I haven't investigated what causes it.

## License

MIT license, check LICENSE.

System instruction highlighting uses [gdelugre/ida-arm-system-highlight](https://github.com/gdelugre/ida-arm-system-highlight), licensed under MIT.
