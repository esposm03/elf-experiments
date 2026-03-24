.PHONY: all

all: target/a target/b target/static

target/a: target/a.o target/b.o
	ld.lld $^ -o $@

target/b: target/a.o target/b.o
	cargo run -- $^

target/static: target/static.o
	cargo run -- $^

target/%.o: elfs/%.c
	@mkdir -p target/
	clang -target x86_64-unknown-linux-gnu -c $< -o $@

target/%.o: elfs/%.s
	@mkdir -p target/
	clang -target x86_64-unknown-linux-gnu -c $< -o $@
