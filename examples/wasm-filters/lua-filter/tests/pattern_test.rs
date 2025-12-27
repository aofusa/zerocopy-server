//! Unit tests for pattern matching

use lua_filter::lua::pattern;

#[test]
fn test_simple_pattern() {
    let result = pattern::match_pattern("hello", "hello");
    assert!(result.is_ok());
    assert!(result.unwrap().is_some());
}

#[test]
fn test_character_class() {
    let result = pattern::match_pattern("abc123", "%d+");
    assert!(result.is_ok());
    let m = result.unwrap();
    assert!(m.is_some());
    assert_eq!(m.unwrap().matched, "123");
}

#[test]
fn test_capture() {
    let result = pattern::match_pattern("hello world", "(%w+)");
    assert!(result.is_ok());
    let m = result.unwrap();
    assert!(m.is_some());
    let match_result = m.unwrap();
    assert_eq!(match_result.matched, "hello");
    assert!(!match_result.captures.is_empty());
}

#[test]
fn test_anchor() {
    let result = pattern::match_pattern("hello", "^hello$");
    assert!(result.is_ok());
    assert!(result.unwrap().is_some());
}

#[test]
fn test_gsub() {
    let result = pattern::gsub("hello world", "world", "lua", None);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().0, "hello lua");
}

#[test]
fn test_match_all() {
    let result = pattern::match_all("a1 b2 c3", "%d+");
    assert!(result.is_ok());
    let matches = result.unwrap();
    assert_eq!(matches.len(), 3);
}

