# Fuzzing uhub's ADC parser

`adc_msg_parse()` (in `src/adc/message.c`) is the hub's most exposed code:
it runs against raw, attacker-controlled bytes *before* a connection is
authenticated. It has a documented history of out-of-bounds reads and
OOM-state leaks, so it is continuously fuzzed.

The harness lives in `src/tools/fuzz_message.c` and is built as the
`fuzz_message` target when CMake is configured with `-DFUZZING=ON`.
It requires **clang** (libFuzzer) and instruments the whole parse path with
AddressSanitizer + UndefinedBehaviorSanitizer.

## Build

```sh
CC=clang cmake -B build-fuzz -DFUZZING=ON -DSSL_SUPPORT=OFF -DRELEASE=ON .
cmake --build build-fuzz --target fuzz_message -j
```

## Run

```sh
# Explore, seeded from the checked-in corpus + dictionary
./build-fuzz/fuzz_message -dict=autotest/fuzz/adc.dict autotest/fuzz/corpus

# Time-boxed regression run (what CI does on every PR)
./build-fuzz/fuzz_message -dict=autotest/fuzz/adc.dict \
    -max_total_time=120 -print_final_stats=1 autotest/fuzz/corpus
```

A crash writes a `crash-<hash>` reproducer to the working directory. Replay it
with:

```sh
./build-fuzz/fuzz_message crash-<hash>
```

## Corpus

`corpus/` holds a handful of valid ADC messages (one per file) covering the
`B`/`E`/`D`/`F`/`I`/`H` message prefixes and the feature-cast path. New
interesting inputs that libFuzzer discovers can be committed back here to speed
up future runs. When you fix a parser bug, add the crashing reproducer to
`corpus/` so it becomes a permanent regression seed.
