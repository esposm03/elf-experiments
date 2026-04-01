.PHONY: all
all: target/a target/b target/static target/rodata

target/debug/elf-experiments: $(shell find src -type f)
	cargo build

target/a: target/a.o target/b.o
	ld.lld $^ -o $@

target/b: target/a.o target/b.o target/debug/elf-experiments
	target/debug/elf-experiments target/a.o target/b.o

target/static: target/static.o target/debug/elf-experiments
	target/debug/elf-experiments target/static.o

target/rodata: target/rodata.o target/debug/elf-experiments
	target/debug/elf-experiments target/rodata.o

target/%.o: elfs/%.c
	@mkdir -p target/
	clang -target x86_64-unknown-linux-gnu -c $< -o $@

target/%.o: elfs/%.s
	@mkdir -p target/
	clang -target x86_64-unknown-linux-gnu -c $< -o $@
