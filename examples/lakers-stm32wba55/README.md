# lakers on STM32WBA55

On-board tests of the lakers crypto backend on the STM32WBA55, using the chip's hardware
accelerators (HASH, AES, PKA, RNG) through the [`embedded-cal`](https://github.com/lake-rs/embedded-cal)
backend (the `lakers-crypto/stm32wba55` dispatch feature).

## Prerequisites

- install `probe-rs`
- an STM32WBA55 board (e.g. NUCLEO-WBA55CG) connected via a debug probe

## How to use

From this directory (its `rust-toolchain.toml` adds the target and its `.cargo/config.toml` sets
the target + probe-rs runner):

    cargo test --release

Results are printed over RTT/defmt; the run ends with `all tests passed!`.
