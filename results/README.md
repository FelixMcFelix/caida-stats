# Format
The CSV package for Rust is a little picky when it comes to printing headers for nested structs: the row format is displayed here.

| Field | Datatype |
| --- | --- |
| Month (range) | string |
| UDP (Non-Quic) Count | u64 |
| UDP (Non-Quic) Volume | u64 |
| UDP (Unknown) Count | u64 |
| UDP (Unknown) Volume | u64 |
| UDP (Quic) Count | u64 |
| UDP (Quic) Volume | u64 |
| TCP Count | u64 |
| TCP Volume | u64 |
| Other Count | u64 |
| Other Volume | u64 |
| Congestion-aware Protocol Percentage (Packets) | f64 |
| Congestion-aware Protocol Percentage (Bytes) | f64 |
| TCP Percentage (Packets) | f64 |
| TCP Percentage (Bytes) | f64 |
| UDP Percentage (Packets) | f64 |
| UDP Percentage (Bytes) | f64 |
| Other Percentage (Packets) | f64 |
| Other Percentage (Bytes) | f64 |
| Quic Percentage (Packets) | f64 |
| Quic Percentage (Bytes) | f64 |
| Total Packets | u64 |
| Total Bytes | u64 |
