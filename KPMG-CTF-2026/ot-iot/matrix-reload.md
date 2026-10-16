# Challenge Name: Matrix Reload
**Category:** OT/IoT (binary exploitation / RE-style)
**Points:** 30
**Difficulty:** Hard

### Description
Hidden functionality exists beyond the available menu options, and tools like `strings`, `nm`, or `gdb` can help you find it. The bug lies in how the program handles a user after deletion. Follow the sequence create → delete → create data → access user and observe how heap memory is reused. After locating the target function in the debugger, try supplying its hexadecimal address when creating data and see what happens when the stale user object is accessed.

Provided: `CTF_File.zip` containing a single ELF binary, `matrix`.

### Approach
1. Unzipped the archive and confirmed the binary type:
   ```bash
   file matrix
   # ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
   ```
   Not stripped — symbol names were intact, which made analysis much faster.
2. Searched strings and symbols for anything interesting:
   ```bash
   strings matrix | grep -iE "flag|secret|admin|backdoor|hidden"
   nm matrix | grep -v " U "
   ```
   Found a `reveal_flag` function at offset `0x1213` and a `Flag: %s` format string — a function never called from the normal program flow.
3. Disassembled `main` to confirm the menu: `1=create_user`, `2=delete_user`, `3=show_user`, `4=create_data`, `5=exit`. `reveal_flag` is not reachable from any menu option.
4. Disassembled each function with `objdump -d -M intel`:
   - `create_user`: `malloc(0x28)` for a struct `[username: 0x20 bytes][function_pointer: 0x8 bytes]`, with the pointer initialized to `print_username`.
   - `delete_user`: calls `free(g_user)` but **never sets `g_user = NULL`** — a classic dangling-pointer / Use-After-Free bug.
   - `create_data`: `malloc(0x28)` for a *separate* global pointer, `g_data` — the same chunk size as the user struct, meaning glibc's allocator (tcache) is very likely to reuse the just-freed user chunk. After writing a data string, it also reads a hex value via `scanf("%lx", ...)` and writes it to offset `+0x20` of the new chunk — the exact same offset as the user struct's function pointer.
   - `show_user`: calls through `g_user`'s function pointer field (`g_user+0x20`), passing `g_user` as the first argument.

### Solution
The exploit chain:
1. `create_user` → allocate the user struct (function pointer defaults to `print_username`).
2. `delete_user` → `free()`s the chunk, but the pointer is left dangling.
3. `create_data` → allocates a same-size chunk which reuses the just-freed memory; when prompted for the hex "handler address," supply `reveal_flag`'s **runtime** address.
4. `show_user` → calls through the now-hijacked function pointer, which now points to `reveal_flag` instead of `print_username`.

Because the binary is PIE, the static offset `0x1213` isn't the real runtime address — it needs the load base added. With ASLR disabled, I confirmed the base via `/proc/<pid>/maps`:
```bash
rm -f infifo && mkfifo infifo
setarch x86_64 -R ./matrix < infifo &
PID=$!
sleep 0.3; exec 3>infifo; sleep 0.3
cat /proc/$PID/maps | grep matrix
# base = 0x555555554000
```
Runtime address of `reveal_flag` = `0x555555554000 + 0x1213 = 0x555555555213`.

Exploit input sequence:
```
1              # create_user
testuser       # username
2              # delete_user (UAF created here)
4              # create_data (reuses freed chunk)
dummydata      # data content
555555555213   # hex address of reveal_flag, overwrites the function pointer
3              # show_user -> triggers reveal_flag instead of print_username
5              # exit
```
```bash
setarch x86_64 -R ./matrix < exploit_input.txt
```

Running this printed the flag directly, since `reveal_flag` internally XOR-decoded an embedded byte string and printed it with `Flag: %s`.

**Static alternative (faster, no exploit execution needed):** since the flag bytes are hardcoded in `reveal_flag`'s disassembly XOR'd with a single byte key (`0x5A`), the flag could also be recovered purely statically:
```python
data = bytes.fromhex("...")  # bytes extracted from the disassembly
flag = bytes(b ^ 0x5a for b in data)
print(flag.decode())
```
Both methods produced the same flag, confirming the result.

### Flag
"[REDACTED]"

### What I learned
- Classic **Use-After-Free**: freeing a pointer without nullifying it leaves a dangling reference; if a same-size object is allocated afterward, the allocator (glibc tcache) will likely hand back the exact same memory, letting an attacker overwrite fields (like function pointers) that the original object's remaining code still trusts.
- PIE binaries randomize their base address at load time — any hardcoded offset found via static analysis (`nm`, `objdump`) must be added to the real runtime base, which can be leaked via `/proc/<pid>/maps`, an info-leak primitive in the binary itself, or inferred if ASLR is disabled.
- When a target function's data is itself embedded and statically recoverable (e.g. XOR-encoded strings sitting in the disassembly), it's often faster to decode statically with a short Python script than to fully weaponize the memory corruption bug — useful to recognize when a CTF only needs the *data*, not actual code execution.
- Unstripped binaries with meaningful symbol names make the "find hidden/unreachable functionality" pattern almost trivial via `nm`/`strings` — always check that first before reaching for a disassembler.
