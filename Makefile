.PHONY: docs docs-open

docs:
	RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --no-deps

docs-test:
	RUSTDOCFLAGS="--cfg docsrs" cargo +nightly test --doc

docs-open:
	RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --no-deps --open
