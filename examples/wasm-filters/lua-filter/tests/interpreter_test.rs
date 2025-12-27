//! Integration tests for Lua interpreter

use lua_filter::lua::interpreter::{Interpreter, SharedState};
use lua_filter::lua::{lexer, parser};
use std::cell::RefCell;
use std::rc::Rc;

fn create_interpreter() -> Interpreter {
    let state = Rc::new(RefCell::new(SharedState::default()));
    Interpreter::with_state(state)
}

#[test]
fn test_basic_arithmetic() {
    let mut interpreter = create_interpreter();
    let tokens = lexer::tokenize("return 1 + 2").unwrap();
    let program = parser::parse(&tokens).unwrap();
    let result = interpreter.execute(&program).unwrap();
    assert_eq!(result.to_number(), Some(3.0));
}

#[test]
fn test_variable_assignment() {
    let mut interpreter = create_interpreter();
    let tokens = lexer::tokenize("local x = 42; return x").unwrap();
    let program = parser::parse(&tokens).unwrap();
    let result = interpreter.execute(&program).unwrap();
    assert_eq!(result.to_number(), Some(42.0));
}

#[test]
fn test_function_call() {
    let mut interpreter = create_interpreter();
    let tokens = lexer::tokenize(
        "function add(a, b) return a + b end; return add(10, 20)"
    ).unwrap();
    let program = parser::parse(&tokens).unwrap();
    let result = interpreter.execute(&program).unwrap();
    assert_eq!(result.to_number(), Some(30.0));
}

#[test]
fn test_multiple_return_values() {
    let mut interpreter = create_interpreter();
    let tokens = lexer::tokenize(
        "function f() return 1, 2, 3 end; local a, b, c = f(); return a + b + c"
    ).unwrap();
    let program = parser::parse(&tokens).unwrap();
    let result = interpreter.execute(&program).unwrap();
    assert_eq!(result.to_number(), Some(6.0));
}

#[test]
fn test_pcall_success() {
    let mut interpreter = create_interpreter();
    let tokens = lexer::tokenize(
        "function f() return 42 end; local ok, result = pcall(f); return ok and result"
    ).unwrap();
    let program = parser::parse(&tokens).unwrap();
    let result = interpreter.execute(&program).unwrap();
    assert_eq!(result.to_number(), Some(42.0));
}

#[test]
fn test_pcall_error() {
    let mut interpreter = create_interpreter();
    let tokens = lexer::tokenize(
        "function f() error('test error') end; local ok, err = pcall(f); return ok"
    ).unwrap();
    let program = parser::parse(&tokens).unwrap();
    let result = interpreter.execute(&program).unwrap();
    assert_eq!(result.is_truthy(), false);
}

#[test]
fn test_table_operations() {
    let mut interpreter = create_interpreter();
    let tokens = lexer::tokenize(
        "local t = {}; t.key = 'value'; return t.key"
    ).unwrap();
    let program = parser::parse(&tokens).unwrap();
    let result = interpreter.execute(&program).unwrap();
    assert_eq!(result.to_lua_string(), "value");
}

#[test]
fn test_metatable_index() {
    let mut interpreter = create_interpreter();
    let tokens = lexer::tokenize(
        "local t = {}; local mt = {__index = {default = 'default'}}; setmetatable(t, mt); return t.default"
    ).unwrap();
    let program = parser::parse(&tokens).unwrap();
    let result = interpreter.execute(&program).unwrap();
    assert_eq!(result.to_lua_string(), "default");
}

#[test]
fn test_string_operations() {
    let mut interpreter = create_interpreter();
    let tokens = lexer::tokenize(
        "return string.upper('hello')"
    ).unwrap();
    let program = parser::parse(&tokens).unwrap();
    let result = interpreter.execute(&program).unwrap();
    assert_eq!(result.to_lua_string(), "HELLO");
}

#[test]
fn test_math_operations() {
    let mut interpreter = create_interpreter();
    let tokens = lexer::tokenize(
        "return math.abs(-42)"
    ).unwrap();
    let program = parser::parse(&tokens).unwrap();
    let result = interpreter.execute(&program).unwrap();
    assert_eq!(result.to_number(), Some(42.0));
}

#[test]
fn test_math_ult() {
    let mut interpreter = create_interpreter();
    let tokens = lexer::tokenize(
        "return math.ult(1, 2)"
    ).unwrap();
    let program = parser::parse(&tokens).unwrap();
    let result = interpreter.execute(&program).unwrap();
    assert_eq!(result.is_truthy(), true);
}

#[test]
fn test_math_tointeger() {
    let mut interpreter = create_interpreter();
    let tokens = lexer::tokenize(
        "return math.tointeger(42.0)"
    ).unwrap();
    let program = parser::parse(&tokens).unwrap();
    let result = interpreter.execute(&program).unwrap();
    assert_eq!(result.to_number(), Some(42.0));
}

#[test]
fn test_table_move() {
    let mut interpreter = create_interpreter();
    let tokens = lexer::tokenize(
        "local t1 = {10, 20, 30}; local t2 = {}; table.move(t1, 1, 3, 1, t2); return t2[1] + t2[2] + t2[3]"
    ).unwrap();
    let program = parser::parse(&tokens).unwrap();
    let result = interpreter.execute(&program).unwrap();
    assert_eq!(result.to_number(), Some(60.0));
}

#[test]
fn test_goto_label() {
    let mut interpreter = create_interpreter();
    let tokens = lexer::tokenize(
        "local x = 0; ::start:: x = x + 1; if x < 3 then goto start end; return x"
    ).unwrap();
    let program = parser::parse(&tokens).unwrap();
    let result = interpreter.execute(&program).unwrap();
    assert_eq!(result.to_number(), Some(3.0));
}

