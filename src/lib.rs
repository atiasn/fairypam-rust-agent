pub mod agent_runtime;
pub mod capture;
pub mod config;
pub mod core_facade;
pub mod environment_check;
pub mod input;
pub mod launch_to_ready;
pub mod mihoyo_discovery;
pub mod process;
pub mod protocol;
pub mod runtime_controller;
pub mod system;
pub mod target_operation;
pub mod window;
pub mod ws_client;

#[cfg(test)]
mod runtime_contract_tests {
    use crate::runtime_controller::RuntimeRunner;

    #[test]
    fn shared_in_process_runner_is_exported() {
        let _runner: RuntimeRunner = crate::agent_runtime::in_process_runtime_runner;
    }
}
