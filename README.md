# LibAFL QuickJS Fuzzing Example

An example fuzzer about how to fuzz a JS engine combining Nautilus with Token-level fuzzing.

## Prepare

Make sure to have Rust nigthly installed and call the bash script to build everything.

```
bash ./build.sh
```

You ready-to-use fuzzer is now `fuzz_eval`.

## Run

To run the fuzzer, you must at least choose a TCP port for the broker and the cores in which you want to spawn the instances (you can list them individually like 0,1,2,3 or specify a range like 0-3).

```
./fuzz_eval --cores 0-12 --broker-port 1337
```

## Reproduce

If you find crashes or you want to print an item of the corpus, use the `--repro` command line option of the fuzzer.

