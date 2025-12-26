//! Custom Lua Interpreter Module
//!
//! A minimal Lua 5.x subset interpreter implemented in pure Rust.
//! No external Lua libraries used.

mod ast;
pub mod interpreter;
pub mod lexer;
pub mod parser;
mod stdlib;
pub mod value;

pub use interpreter::Interpreter;
pub use value::LuaValue;

/// Parse and execute Lua code
pub fn execute(source: &str, interpreter: &mut Interpreter) -> Result<LuaValue, String> {
    // Tokenize
    let tokens = lexer::tokenize(source)?;

    // Parse
    let ast = parser::parse(&tokens)?;

    // Execute
    interpreter.execute(&ast)
}
