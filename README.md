# azuresim

A standalone local Azure emulator for the lmctl-ai family, built on
[Floci-AZ](https://github.com/floci-io/floci-az) 0.15.0 (MIT).

Implementation is in progress. The distribution will compile the pinned upstream
commit `8b439a8ddf90df92315dfdbe95b0498e81384cc0` with a small azuresim CLI entrypoint.
This repository is a build integration, not a fork mirror. Upstream publishes
container images but no native release assets, so building its source avoids a
Docker requirement for Blob and Queue Storage.

Target contract: `azuresim --version`, `azuresim serve` (alias `start`),
loopback HTTP on port 4577, real REST round-trip tests, and tagged native releases.
