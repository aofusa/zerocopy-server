//! Lua Value Types

use std::collections::HashMap;
use std::fmt;

/// Lua value types
#[derive(Clone, Debug)]
pub enum LuaValue {
    Nil,
    Boolean(bool),
    Number(f64),
    String(String),
    Table(HashMap<String, LuaValue>),
    Function(String), // Function name reference
    NativeFunction(String), // Built-in function name
}

impl Default for LuaValue {
    fn default() -> Self {
        LuaValue::Nil
    }
}

impl LuaValue {
    pub fn is_truthy(&self) -> bool {
        match self {
            LuaValue::Nil => false,
            LuaValue::Boolean(b) => *b,
            _ => true,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            LuaValue::Nil => "nil",
            LuaValue::Boolean(_) => "boolean",
            LuaValue::Number(_) => "number",
            LuaValue::String(_) => "string",
            LuaValue::Table(_) => "table",
            LuaValue::Function(_) | LuaValue::NativeFunction(_) => "function",
        }
    }

    pub fn to_number(&self) -> Option<f64> {
        match self {
            LuaValue::Number(n) => Some(*n),
            LuaValue::String(s) => s.parse().ok(),
            _ => None,
        }
    }

    pub fn to_lua_string(&self) -> String {
        match self {
            LuaValue::Nil => "nil".to_string(),
            LuaValue::Boolean(b) => b.to_string(),
            LuaValue::Number(n) => {
                if n.fract() == 0.0 {
                    format!("{}", *n as i64)
                } else {
                    n.to_string()
                }
            }
            LuaValue::String(s) => s.clone(),
            LuaValue::Table(_) => "table".to_string(),
            LuaValue::Function(name) => format!("function: {}", name),
            LuaValue::NativeFunction(name) => format!("function: {}", name),
        }
    }
}

impl fmt::Display for LuaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_lua_string())
    }
}

impl PartialEq for LuaValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (LuaValue::Nil, LuaValue::Nil) => true,
            (LuaValue::Boolean(a), LuaValue::Boolean(b)) => a == b,
            (LuaValue::Number(a), LuaValue::Number(b)) => (a - b).abs() < f64::EPSILON,
            (LuaValue::String(a), LuaValue::String(b)) => a == b,
            _ => false,
        }
    }
}
