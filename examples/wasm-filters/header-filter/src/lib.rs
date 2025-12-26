//! Sample Proxy-Wasm Header Filter
//!
//! This filter adds custom headers to both request and response.

use proxy_wasm::traits::*;
use proxy_wasm::types::*;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Debug);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(HeaderFilterRoot)
    });
}}

struct HeaderFilterRoot;

impl Context for HeaderFilterRoot {}

impl RootContext for HeaderFilterRoot {
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(HeaderFilter { context_id }))
    }
}

struct HeaderFilter {
    context_id: u32,
}

impl Context for HeaderFilter {}

impl HttpContext for HeaderFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // Add custom header to request
        self.add_http_request_header("X-Veil-Proxy-Filter", "header-filter-v1");
        self.add_http_request_header("X-Veil-Request-Id", &format!("req-{}", self.context_id));

        log::info!("Added request headers for context {}", self.context_id);

        Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // Add custom headers to response
        self.add_http_response_header("X-Veil-Processed", "true");
        self.add_http_response_header("X-Veil-Filter-Version", "1.0.0");
        self.add_http_response_header("X-Veil-Context-Id", &format!("{}", self.context_id));

        log::info!("Added response headers for context {}", self.context_id);

        Action::Continue
    }

    fn on_log(&mut self) {
        log::info!("Request {} completed", self.context_id);
    }
}
