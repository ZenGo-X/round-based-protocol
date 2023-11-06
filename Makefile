.PHONY: docs docs-open

docs:
	RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --no-deps --all-features

docs-test:
	RUSTDOCFLAGS="--cfg docsrs" cargo +nightly test --doc --all-features

docs-open:
	RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --no-deps --all-features --open
