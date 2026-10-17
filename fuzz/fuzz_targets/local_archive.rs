#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| crabinet::fuzzing::local_archive(data));
