.PHONY: docs docs-open

docs:
	RUSTDOCFLAGS="--cfg __docsrs" cargo +nightly doc --no-deps

docs-test:
	RUSTDOCFLAGS="--cfg __docsrs" cargo +nightly test --doc

docs-open:
	RUSTDOCFLAGS="--cfg __docsrs" cargo +nightly doc --no-deps --open
