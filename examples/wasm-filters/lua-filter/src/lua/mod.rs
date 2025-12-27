//! Custom Lua Interpreter Module
//!
//! A minimal Lua 5.x subset interpreter implemented in pure Rust.
//! No external Lua libraries used.

mod ast;
pub mod interpreter;
pub mod lexer;
pub mod parser;
pub mod pattern;
pub mod value;

pub use interpreter::Interpreter;
pub use value::LuaValue;

/// Parse and execute Lua code
///
/// This function provides a convenient way to parse and execute Lua source code.
/// It tokenizes the source, parses it into an AST, and executes it using the provided interpreter.
///
/// # Arguments
/// * `source` - The Lua source code to execute
/// * `interpreter` - The interpreter instance to use for execution
///
/// # Returns
/// * `Ok(LuaValue)` - The result of executing the code
/// * `Err(String)` - An error message if parsing or execution fails
#[allow(dead_code)] // Public API for future use
pub fn execute(source: &str, interpreter: &mut Interpreter) -> Result<LuaValue, String> {
    // Tokenize
    let tokens = lexer::tokenize(source)?;

    // Parse
    let ast = parser::parse(&tokens)?;

    // Execute
    interpreter.execute(&ast)
}
