//! Lua Standard Library

use crate::lua::value::LuaValue;
use std::collections::HashMap;

/// Call a standard library function
pub fn call_stdlib(
    name: &str,
    args: &[LuaValue],
    log_fn: &dyn Fn(&str, &str),
) -> Result<LuaValue, String> {
    match name {
        "print" => {
            let output: Vec<String> = args.iter().map(|v| v.to_lua_string()).collect();
            log_fn("info", &output.join("\t"));
            Ok(LuaValue::Nil)
        }

        "tostring" => Ok(LuaValue::String(
            args.first()
                .map(|v| v.to_lua_string())
                .unwrap_or_else(|| "nil".to_string()),
        )),

        "tonumber" => {
            let result = args.first().and_then(|v| v.to_number());
            Ok(result.map(LuaValue::Number).unwrap_or(LuaValue::Nil))
        }

        "type" => Ok(LuaValue::String(
            args.first().map(|v| v.type_name()).unwrap_or("nil").to_string(),
        )),

        "error" => {
            let msg = args
                .first()
                .map(|v| v.to_lua_string())
                .unwrap_or_else(|| "error".to_string());
            Err(msg)
        }

        "assert" => {
            if args.first().map(|v| v.is_truthy()).unwrap_or(false) {
                Ok(args.first().cloned().unwrap_or(LuaValue::Nil))
            } else {
                let msg = args
                    .get(1)
                    .map(|v| v.to_lua_string())
                    .unwrap_or_else(|| "assertion failed!".to_string());
                Err(msg)
            }
        }

        "pcall" => {
            // Simplified pcall - just returns success
            Ok(LuaValue::Boolean(true))
        }

        _ => Err(format!("Unknown function: {}", name)),
    }
}

/// Call a string library function
pub fn call_string_lib(method: &str, args: &[LuaValue]) -> Result<LuaValue, String> {
    match method {
        "len" => {
            let s = args
                .first()
                .map(|v| v.to_lua_string())
                .unwrap_or_default();
            Ok(LuaValue::Number(s.len() as f64))
        }

        "sub" => {
            let s = args
                .first()
                .map(|v| v.to_lua_string())
                .unwrap_or_default();

            let start = args
                .get(1)
                .and_then(|v| v.to_number())
                .map(|n| n as i64)
                .unwrap_or(1);

            let end = args
                .get(2)
                .and_then(|v| v.to_number())
                .map(|n| n as i64)
                .unwrap_or(-1);

            let len = s.len() as i64;

            // Lua uses 1-based indexing with negative wraparound
            let start_idx = if start < 0 {
                (len + start + 1).max(0) as usize
            } else {
                (start - 1).max(0) as usize
            };

            let end_idx = if end < 0 {
                (len + end + 1).max(0) as usize
            } else {
                end.min(len) as usize
            };

            if start_idx >= s.len() || end_idx <= start_idx {
                Ok(LuaValue::String(String::new()))
            } else {
                Ok(LuaValue::String(s[start_idx..end_idx].to_string()))
            }
        }

        "upper" => {
            let s = args
                .first()
                .map(|v| v.to_lua_string())
                .unwrap_or_default();
            Ok(LuaValue::String(s.to_uppercase()))
        }

        "lower" => {
            let s = args
                .first()
                .map(|v| v.to_lua_string())
                .unwrap_or_default();
            Ok(LuaValue::String(s.to_lowercase()))
        }

        "find" => {
            let s = args
                .first()
                .map(|v| v.to_lua_string())
                .unwrap_or_default();
            let pattern = args
                .get(1)
                .map(|v| v.to_lua_string())
                .unwrap_or_default();

            match s.find(&pattern) {
                Some(pos) => Ok(LuaValue::Number((pos + 1) as f64)), // 1-based
                None => Ok(LuaValue::Nil),
            }
        }

        "match" => {
            // Simple substring match (not full pattern matching)
            let s = args
                .first()
                .map(|v| v.to_lua_string())
                .unwrap_or_default();
            let pattern = args
                .get(1)
                .map(|v| v.to_lua_string())
                .unwrap_or_default();

            if s.contains(&pattern) {
                Ok(LuaValue::String(pattern))
            } else {
                Ok(LuaValue::Nil)
            }
        }

        "format" => {
            let format = args
                .first()
                .map(|v| v.to_lua_string())
                .unwrap_or_default();

            // Simple format: replace %s, %d with arguments
            let mut result = format;
            for (i, arg) in args.iter().skip(1).enumerate() {
                let placeholder_s = format!("%s");
                let placeholder_d = format!("%d");

                if result.contains(&placeholder_s) {
                    result = result.replacen(&placeholder_s, &arg.to_lua_string(), 1);
                } else if result.contains(&placeholder_d) {
                    let num_str = arg
                        .to_number()
                        .map(|n| {
                            if n.fract() == 0.0 {
                                format!("{}", n as i64)
                            } else {
                                n.to_string()
                            }
                        })
                        .unwrap_or_else(|| arg.to_lua_string());
                    result = result.replacen(&placeholder_d, &num_str, 1);
                }
            }

            Ok(LuaValue::String(result))
        }

        "rep" => {
            let s = args
                .first()
                .map(|v| v.to_lua_string())
                .unwrap_or_default();
            let n = args
                .get(1)
                .and_then(|v| v.to_number())
                .map(|n| n as usize)
                .unwrap_or(1);
            Ok(LuaValue::String(s.repeat(n)))
        }

        "reverse" => {
            let s = args
                .first()
                .map(|v| v.to_lua_string())
                .unwrap_or_default();
            Ok(LuaValue::String(s.chars().rev().collect()))
        }

        "byte" => {
            let s = args
                .first()
                .map(|v| v.to_lua_string())
                .unwrap_or_default();
            let pos = args
                .get(1)
                .and_then(|v| v.to_number())
                .map(|n| (n as usize).saturating_sub(1))
                .unwrap_or(0);

            s.chars()
                .nth(pos)
                .map(|c| LuaValue::Number(c as u32 as f64))
                .ok_or_else(|| "index out of range".to_string())
        }

        "char" => {
            let chars: String = args
                .iter()
                .filter_map(|v| v.to_number())
                .filter_map(|n| char::from_u32(n as u32))
                .collect();
            Ok(LuaValue::String(chars))
        }

        _ => Err(format!("Unknown string method: {}", method)),
    }
}

/// Create the string table
pub fn create_string_table() -> HashMap<String, LuaValue> {
    let mut table = HashMap::new();

    // Register string functions as native functions
    for method in &[
        "len", "sub", "upper", "lower", "find", "match", "format", "rep", "reverse", "byte", "char",
    ] {
        table.insert(
            method.to_string(),
            LuaValue::NativeFunction(format!("string.{}", method)),
        );
    }

    table
}
