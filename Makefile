.PHONY: all

all: target/a.o target/b.o
	ld.lld $^ -o target/a.out
	cargo run -- $^

target/%.o: elfs/%.c
	@mkdir -p target/
	clang -target x86_64-unknown-linux-gnu -c $< -o $@
