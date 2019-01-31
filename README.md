# CAIDA Stats

This repository contains an implementation of a system for measuring the volumes and proportions of a handful of protocols in the 2018 CAIDA Anonymized Internet Traces dataset.
Specifically, I try to infer the presence of TCP, UDP and QUIC packets.
So as not to consume terrabytes worth of data, this is done by piping the asynchronously streamed HTTP body into a (multi-)GZIP decoder, piped again into a Pcap decoder.

## Usage
This software has been tested on Linux and Windows using rustc 1.32.0.
The program may be run via:
```sh
cargo run --release
```
whereupon access credentials will be requested.
Note that attempting to download the CAIDA traces outside of an academic network significantly reduces the maximum download rate and/or request rate-limit.