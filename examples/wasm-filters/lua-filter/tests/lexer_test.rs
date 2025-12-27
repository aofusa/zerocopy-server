//! Unit tests for Lua lexer

use lua_filter::lua::lexer;

#[test]
fn test_tokenize_basic() {
    let tokens = lexer::tokenize("local x = 1").unwrap();
    assert_eq!(tokens.len(), 5);
}

#[test]
fn test_tokenize_string() {
    let tokens = lexer::tokenize(r#"local s = "hello""#).unwrap();
    assert_eq!(tokens.len(), 5);
}

#[test]
fn test_tokenize_number() {
    let tokens = lexer::tokenize("return 42.5").unwrap();
    assert_eq!(tokens.len(), 3);
}

#[test]
fn test_tokenize_operators() {
    let tokens = lexer::tokenize("x = a + b * c").unwrap();
    assert!(tokens.len() >= 7);
}

#[test]
fn test_tokenize_keywords() {
    let tokens = lexer::tokenize("if then else end").unwrap();
    assert_eq!(tokens.len(), 5);
}

#[test]
fn test_tokenize_invalid() {
    let result = lexer::tokenize("local x = 'unclosed string");
    assert!(result.is_err());
}

