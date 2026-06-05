.PHONY: check build serve dev clean

# Проверка без WASM (быстро)
check:
	cd crates/parser && cargo check

# Нативный билд для тестов
test:
	cd crates/parser && cargo test

# WASM билд
build:
	wasm-pack build crates/parser --target web --out-dir ../../web/pkg

# Dev сервер
serve:
	python3 -m http.server 8888 --directory web

# Полный цикл
dev: build serve

clean:
	cd crates/parser && cargo clean
	rm -rf web/pkg
