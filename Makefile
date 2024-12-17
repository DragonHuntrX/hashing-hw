main: hashing

hashing: src/main.rs
	cargo build --release
	cp target/release/hashing .