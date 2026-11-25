# WineGdbStub

A GDB remote stub for 32-bit Windows programs running under Wine. It is built as a DLL that is loaded into the target
process, starts a TCP server on `127.0.0.1` (port `2345` by default), and speaks the GDB remote serial protocol. CLion,
Rider or the `gdb` command line can then debug the process with breakpoints, registers and memory, without `winedbg`
or ptrace permissions.

It was written to debug GWToolbox++ inside Guild Wars, and it's usable in any 32-bit Wine program.

## Build

The stub is built with llvm-mingw's i686 compiler. GWToolbox++ pins one in `.toolchain/llvm-mingw-linux`, so point
`LLVM_MINGW` at that folder:

```sh
export LLVM_MINGW=/path/to/GWToolboxpp2/.toolchain/llvm-mingw-linux
cmake -S . -B build -G Ninja -DCMAKE_TOOLCHAIN_FILE=cmake/llvm-mingw-i686.cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
```

The output is `build/bin/WineGdbStub.dll`. It only imports `WS2_32.dll`, `KERNEL32.dll` and `msvcrt.dll`, so it can be
injected into any process. A copy is kept in GWToolbox++ at `tools/debug/WineGdbStub.dll`.

## Use with a Guild Wars instance

1. Add the stub to a launcher account's mods, switched on, with the absolute path of the DLL. Start the account from GW
   Launcher. The stub starts listening when it loads. Check with `ss -ltn | grep 2345`.
2. Attach a debugger. From the command line:
   ```sh
   gdb -ex "target remote localhost:2345"
   ```
   Connecting stops the game, and `detach` resumes it. `monitor modules` lists the loaded modules and their base
   addresses.
3. For GWToolbox++ symbols, `tools/attach_symbols.py` defines an `attach_symbols` command. It finds GWToolbox's base
   address through `monitor modules` and loads its symbols. GDB can also apply the offset itself, because the stub reports
   it through `qOffsets`, so the helper is only needed for the command-line flow. `tools/clion_init.gdb` runs the whole
   sequence. It has the absolute path of `attach_symbols.py` in this checkout, so edit that path for yours.
4. For CLion, create a Remote Debug configuration: target `localhost:2345`, and the debug build's `.debug` file as the
   symbol file.

## Protocol

| Packet | Support |
|---|---|
| `?`, `qSupported`, `qAttached`, `qC`, `qfThreadInfo`, `qsThreadInfo`, `H` | yes |
| `g` (i386 registers) | read only |
| `m` (memory) | read only, readable pages (unmapped addresses return `E14`) |
| `Z0` / `z0` (software breakpoints) | yes |
| `c`, `s` | yes |
| `qOffsets` | yes, reports the configured module's move from its preferred base |
| `qGetTIBAddr` | yes, for the stopped thread |
| `qRcmd` (`monitor modules`) | yes |
| `M`, `G`, `vCont`, hardware breakpoints | no |

On connect the stub stops the process, so GDB can read state immediately. Other threads are suspended while the process is
stopped, and resumed on continue, step or detach. Detach removes all breakpoints.

## Configuration

* `GWSTUB_PORT`: the TCP port, read when the DLL loads. Default `2345`.
* `GWSTUB_MODULE`: the module whose offset `qOffsets` reports. Default `GWToolboxdll.dll`.

## Tests

`tests/run_test.py` loads `StubTarget.exe` under Wine and runs the protocol against it: breakpoints, registers, memory,
single-step, step-over, the TIB, module listing, offsets and detach. Run it with `WINEPREFIX` set. Set `GWSTUB_PORT` if
another debugger holds port 2345.

## Limits

* One debugger at a time. A second connection waits until the first one closes.
* Each breakpoint hit stops every thread in the process, so a breakpoint in code that runs every frame pauses the game
  briefly each frame.
* Interrupting a running process isn't supported.
* A debugger that disconnects abruptly while the process is stopped can leave the stub stuck until the process restarts.
