# sig_recovery_check

Recovers and compares secp256k1 public keys from two ECDSA signature objects in a JSON file.  
Takes one argument: the path to a JSON file containing `old_res`, `new_res`, and `msg_hash`.  
Run with `cargo run -- path/to/file.json`.

This tool can be useful for checking wether the derived public key is preserved across contract updates.
