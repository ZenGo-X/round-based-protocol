## v0.1.7
- Add methods to access the state machine from `AsyncProtocol` [#9]
  Adds methods `AsyncProtocol::state_machine_ref` and `AsyncProtocol::into_state_machine`

[#7]: https://github.com/ZenGo-X/round-based-protocol/pull/9

## v0.1.6
- Update documentation of StateMachine

## v0.1.5
- Simulation can be configured to enable/disable tracing state changes [#6] \
  Simulation uses [`log`] crate to produce tracing messages, so logging can be configured at application level via logging
  implementation crates like [`env_logger`]

[#6]: https://github.com/ZenGo-X/round-based-protocol/pull/6
[`log`]: https://docs.rs/log/
[`env_logger`]: https://docs.rs/env_logger/

## v0.1.4

- Improved Simulation
  
  It got smarter, now should be able to carry out any valid StateMachine implementation
