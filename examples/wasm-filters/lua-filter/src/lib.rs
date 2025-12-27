//! Custom Lua Interpreter Proxy-Wasm Filter
//!
//! A complete Lua 5.x subset interpreter implemented in pure Rust.
//! No external Lua libraries used - fully custom implementation.
//!
//! ## Features
//! - Lexer, Parser, AST, Interpreter from scratch
//! - Variables, functions, control flow, tables
//! - String library (sub, upper, lower, find, etc.)
//! - Proxy-WASM bindings via `veil` table
//!
//! ## Usage
//!
//! Configuration JSON:
//! ```json
//! {
//!   "script": "function on_request() veil.set_request_header('X-Lua', 'true') return 'continue' end"
//! }
//! ```
//!
//! ## Lua API (veil table)
//!
//! - `veil.log(level, message)` - Log message
//! - `veil.get_request_header(name)` - Get request header
//! - `veil.set_request_header(name, value)` - Set request header
//! - `veil.get_response_header(name)` - Get response header
//! - `veil.set_response_header(name, value)` - Set response header
//! - `veil.get_path()` - Get request path
//! - `veil.get_method()` - Get request method
//! - `veil.send_local_response(status, body)` - Send local response
//! - `veil.get_headers()` - Get all request headers as table

pub mod lua;

use lua::interpreter::{Interpreter, SharedState};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use std::cell::RefCell;
use std::rc::Rc;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(LuaFilterRoot::new())
    });
}}

/// Configuration for the Lua filter
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LuaConfig {
    /// Lua script source code
    #[serde(default)]
    pub script: String,

    /// Enable debug logging
    #[serde(default)]
    pub debug: bool,
}

struct LuaFilterRoot {
    config: LuaConfig,
}

impl LuaFilterRoot {
    fn new() -> Self {
        Self {
            config: LuaConfig::default(),
        }
    }
}

impl Context for LuaFilterRoot {}

impl RootContext for LuaFilterRoot {
    fn on_configure(&mut self, plugin_configuration_size: usize) -> bool {
        if plugin_configuration_size == 0 {
            log::warn!("[lua] No script configured");
            return true;
        }

        if let Some(config_bytes) = self.get_plugin_configuration() {
            match serde_json::from_slice::<LuaConfig>(&config_bytes) {
                Ok(config) => {
                    if config.script.is_empty() {
                        log::warn!("[lua] Empty script in configuration");
                    } else {
                        log::info!("[lua] Script loaded ({} bytes)", config.script.len());

                        // Validate script by parsing
                        match lua::lexer::tokenize(&config.script) {
                            Ok(tokens) => match lua::parser::parse(&tokens) {
                                Ok(_) => {
                                    log::info!("[lua] Script parsed successfully");
                                }
                                Err(e) => {
                                    log::error!("[lua] Script parse error: {}", e);
                                    return false;
                                }
                            },
                            Err(e) => {
                                log::error!("[lua] Script tokenize error: {}", e);
                                return false;
                            }
                        }
                    }
                    self.config = config;
                }
                Err(e) => {
                    log::error!("[lua] Failed to parse configuration: {}", e);
                    return false;
                }
            }
        }
        true
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(LuaFilter::new(context_id, self.config.clone())))
    }
}

struct LuaFilter {
    context_id: u32,
    config: LuaConfig,
    state: Rc<RefCell<SharedState>>,
    interpreter: Option<Interpreter>,
}

impl LuaFilter {
    fn new(context_id: u32, config: LuaConfig) -> Self {
        let state = Rc::new(RefCell::new(SharedState::default()));
        let interpreter = Some(Interpreter::with_state(state.clone()));

        Self {
            context_id,
            config,
            state,
            interpreter,
        }
    }

    fn execute_lua(&mut self, func_name: &str) -> Result<String, String> {
        if self.config.script.is_empty() {
            return Ok("continue".to_string());
        }

        let interpreter = match &mut self.interpreter {
            Some(i) => i,
            None => return Err("No interpreter".to_string()),
        };

        // Build script that calls the function
        let full_script = format!("{}\nreturn {}()", self.config.script, func_name);

        // Parse
        let tokens = lua::lexer::tokenize(&full_script)?;
        let program = lua::parser::parse(&tokens)?;

        // Execute
        let result = interpreter.execute(&program)?;

        // Process log messages
        {
            let state = self.state.borrow();
            for (level, msg) in &state.log_messages {
                match level.as_str() {
                    "debug" => log::debug!("[lua-script:{}] {}", self.context_id, msg),
                    "info" => log::info!("[lua-script:{}] {}", self.context_id, msg),
                    "warn" | "warning" => log::warn!("[lua-script:{}] {}", self.context_id, msg),
                    "error" => log::error!("[lua-script:{}] {}", self.context_id, msg),
                    _ => log::info!("[lua-script:{}] {}", self.context_id, msg),
                }
            }
        }

        Ok(result.to_lua_string())
    }

    fn apply_request_modifications(&self) {
        let state = self.state.borrow();
        for (key, value) in &state.request_headers_to_set {
            self.add_http_request_header(key, value);
        }
    }

    fn apply_response_modifications(&self) {
        let state = self.state.borrow();
        for (key, value) in &state.response_headers_to_set {
            self.add_http_response_header(key, value);
        }
    }
}

impl Context for LuaFilter {}

impl HttpContext for LuaFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // Populate state with current headers
        {
            let mut state = self.state.borrow_mut();
            state.reset();

            let headers = self.get_http_request_headers();
            state.current_request_headers = headers;

            if let Some(path) = self.get_http_request_header(":path") {
                state.current_path = path;
            }
            if let Some(method) = self.get_http_request_header(":method") {
                state.current_method = method;
            }
        }

        // Execute Lua on_request function
        match self.execute_lua("on_request") {
            Ok(result) => {
                if self.config.debug {
                    log::debug!(
                        "[lua:{}] on_request returned: {}",
                        self.context_id,
                        result
                    );
                }
            }
            Err(e) => {
                log::error!("[lua:{}] Error in on_request: {}", self.context_id, e);
            }
        }

        // Check for local response
        {
            let state = self.state.borrow();
            if let Some((status, body)) = &state.local_response {
                self.send_http_response(
                    *status as u32,
                    vec![("content-type", "text/plain")],
                    Some(body.as_bytes()),
                );
                return Action::Pause;
            }
        }

        // Apply header modifications
        self.apply_request_modifications();

        Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // Populate state with current headers
        {
            let mut state = self.state.borrow_mut();
            state.reset();

            let headers = self.get_http_response_headers();
            state.current_response_headers = headers;
        }

        // Execute Lua on_response function
        match self.execute_lua("on_response") {
            Ok(result) => {
                if self.config.debug {
                    log::debug!(
                        "[lua:{}] on_response returned: {}",
                        self.context_id,
                        result
                    );
                }
            }
            Err(e) => {
                // on_response might not be defined, that's OK
                if self.config.debug {
                    log::debug!("[lua:{}] on_response: {}", self.context_id, e);
                }
            }
        }

        // Apply header modifications
        self.apply_response_modifications();

        Action::Continue
    }

    fn on_log(&mut self) {
        if self.config.debug {
            log::debug!("[lua:{}] Request completed", self.context_id);
        }
    }
}
