build:
	zig build-exe -OReleaseSmall --name kit main.zig
install: build
	rm ~/bin/kit && mv kit ~/bin
