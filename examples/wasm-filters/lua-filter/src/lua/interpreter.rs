//! Lua Interpreter

use crate::lua::ast::*;
use crate::lua::pattern;
use crate::lua::value::{Closure, LuaTable, LuaValue, Upvalue};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

/// Shared state for Proxy-WASM bindings
pub struct SharedState {
    pub request_headers_to_set: Vec<(String, String)>,
    pub response_headers_to_set: Vec<(String, String)>,
    pub local_response: Option<(u16, String)>,
    pub current_request_headers: Vec<(String, String)>,
    pub current_response_headers: Vec<(String, String)>,
    pub current_path: String,
    pub current_method: String,
    pub log_messages: Vec<(String, String)>,
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            request_headers_to_set: Vec::new(),
            response_headers_to_set: Vec::new(),
            local_response: None,
            current_request_headers: Vec::new(),
            current_response_headers: Vec::new(),
            current_path: String::new(),
            current_method: String::new(),
            log_messages: Vec::new(),
        }
    }
}

impl SharedState {
    pub fn reset(&mut self) {
        self.request_headers_to_set.clear();
        self.response_headers_to_set.clear();
        self.local_response = None;
        self.log_messages.clear();
    }
}

/// Scope with upvalue support
#[derive(Clone)]
struct Scope {
    values: HashMap<String, Rc<RefCell<LuaValue>>>,
}

impl Scope {
    fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }

    fn get(&self, name: &str) -> Option<Rc<RefCell<LuaValue>>> {
        self.values.get(name).cloned()
    }

    fn set(&mut self, name: String, value: LuaValue) {
        if let Some(existing) = self.values.get(&name) {
            *existing.borrow_mut() = value;
        } else {
            self.values.insert(name, Rc::new(RefCell::new(value)));
        }
    }

    fn define(&mut self, name: String, value: LuaValue) {
        self.values.insert(name, Rc::new(RefCell::new(value)));
    }
}

/// Lua Interpreter
pub struct Interpreter {
    /// Global variables
    globals: HashMap<String, LuaValue>,

    /// Local variable scopes (with upvalue support)
    scopes: Vec<Scope>,

    /// Defined functions
    functions: HashMap<String, Rc<Closure>>,

    /// Shared state with Proxy-WASM
    pub state: Rc<RefCell<SharedState>>,

    /// Break flag for loops
    break_flag: bool,

    /// Return values
    return_values: Option<Vec<LuaValue>>,

    /// Current varargs
    varargs: Vec<LuaValue>,
}

impl Interpreter {
    pub fn new() -> Self {
        let state = Rc::new(RefCell::new(SharedState::default()));
        Self::with_state(state)
    }

    pub fn with_state(state: Rc<RefCell<SharedState>>) -> Self {
        let mut globals = HashMap::new();

        // Register standard library functions
        for name in &[
            "print", "tostring", "tonumber", "type", "error", "assert", "pcall",
            "pairs", "ipairs", "next", "select", "unpack", "setmetatable", "getmetatable",
            "rawget", "rawset", "rawequal",
        ] {
            globals.insert(name.to_string(), LuaValue::NativeFunction(name.to_string()));
        }

        // Register string table
        let mut string_table = LuaTable::new();
        for name in &[
            "len", "sub", "upper", "lower", "find", "match", "gmatch", "gsub",
            "format", "rep", "reverse", "byte", "char", "split",
        ] {
            string_table.set(
                name.to_string(),
                LuaValue::NativeFunction(format!("string.{}", name)),
            );
        }
        globals.insert("string".to_string(), LuaValue::Table(string_table));

        // Register math table
        let mut math_table = LuaTable::new();
        for name in &[
            "abs", "ceil", "floor", "max", "min", "sin", "cos", "tan",
            "asin", "acos", "atan", "sqrt", "log", "exp", "pow",
            "random", "randomseed", "deg", "rad", "modf", "fmod",
        ] {
            math_table.set(
                name.to_string(),
                LuaValue::NativeFunction(format!("math.{}", name)),
            );
        }
        math_table.set("pi".to_string(), LuaValue::Number(std::f64::consts::PI));
        math_table.set("huge".to_string(), LuaValue::Number(f64::INFINITY));
        math_table.set("maxinteger".to_string(), LuaValue::Number(i64::MAX as f64));
        math_table.set("mininteger".to_string(), LuaValue::Number(i64::MIN as f64));
        globals.insert("math".to_string(), LuaValue::Table(math_table));

        // Register table library
        let mut table_lib = LuaTable::new();
        for name in &["insert", "remove", "concat", "sort", "pack", "unpack"] {
            table_lib.set(
                name.to_string(),
                LuaValue::NativeFunction(format!("table.{}", name)),
            );
        }
        globals.insert("table".to_string(), LuaValue::Table(table_lib));

        // Register utf8 library
        let mut utf8_lib = LuaTable::new();
        for name in &["len", "char", "codepoint", "codes", "offset", "charpattern"] {
            utf8_lib.set(
                name.to_string(),
                LuaValue::NativeFunction(format!("utf8.{}", name)),
            );
        }
        // utf8.charpattern constant (Lua pattern for matching UTF-8 sequences)
        utf8_lib.set("charpattern".to_string(), LuaValue::String(r"[\0-\x7F\xC2-\xF4][\x80-\xBF]*".to_string()));
        globals.insert("utf8".to_string(), LuaValue::Table(utf8_lib));

        // Register veil table (Proxy-WASM bindings)
        let mut veil = LuaTable::new();
        for name in &[
            "log",
            "get_request_header",
            "set_request_header",
            "get_response_header",
            "set_response_header",
            "get_path",
            "get_method",
            "send_local_response",
            "get_headers",
        ] {
            veil.set(
                name.to_string(),
                LuaValue::NativeFunction(format!("veil.{}", name)),
            );
        }
        globals.insert("veil".to_string(), LuaValue::Table(veil));

        Self {
            globals,
            scopes: Vec::new(),
            functions: HashMap::new(),
            state,
            break_flag: false,
            return_values: None,
            varargs: Vec::new(),
        }
    }

    pub fn execute(&mut self, program: &Program) -> Result<LuaValue, String> {
        self.return_values = None;
        self.break_flag = false;

        for stmt in &program.statements {
            self.execute_statement(stmt)?;

            if self.return_values.is_some() {
                break;
            }
        }

        Ok(self.return_values.take()
            .and_then(|v| v.into_iter().next())
            .unwrap_or(LuaValue::Nil))
    }

    fn execute_statement(&mut self, stmt: &Stmt) -> Result<(), String> {
        match stmt {
            Stmt::Assign { targets, values, local } => {
                let evaluated: Vec<LuaValue> = values
                    .iter()
                    .map(|expr| self.evaluate(expr))
                    .collect::<Result<_, _>>()?;

                for (i, target) in targets.iter().enumerate() {
                    let value = evaluated.get(i).cloned().unwrap_or(LuaValue::Nil);
                    match target {
                        AssignTarget::Name(name) => {
                            if *local {
                                self.set_local(name.clone(), value);
                            } else {
                                self.set_variable(name.clone(), value);
                            }
                        }
                        AssignTarget::Index(table_expr, key_expr) => {
                            let table_val = self.evaluate(table_expr)?;
                            let key_val = self.evaluate(key_expr)?;

                            if let LuaValue::Table(mut t) = table_val {
                                t.set(key_val.to_lua_string(), value);
                                // Re-assign the table
                                if let Expr::Variable(name) = table_expr {
                                    self.set_variable(name.clone(), LuaValue::Table(t));
                                }
                            }
                        }
                    }
                }
            }

            Stmt::If {
                condition,
                then_block,
                elseif_blocks,
                else_block,
            } => {
                let cond = self.evaluate(condition)?;

                if cond.is_truthy() {
                    self.execute_block(then_block)?;
                } else {
                    let mut executed = false;
                    for (elseif_cond, elseif_body) in elseif_blocks {
                        let c = self.evaluate(elseif_cond)?;
                        if c.is_truthy() {
                            self.execute_block(elseif_body)?;
                            executed = true;
                            break;
                        }
                    }

                    if !executed {
                        if let Some(else_body) = else_block {
                            self.execute_block(else_body)?;
                        }
                    }
                }
            }

            Stmt::While { condition, body } => {
                self.break_flag = false;

                while !self.break_flag {
                    let cond = self.evaluate(condition)?;
                    if !cond.is_truthy() {
                        break;
                    }

                    self.execute_block(body)?;

                    if self.return_values.is_some() {
                        break;
                    }
                }

                self.break_flag = false;
            }

            Stmt::Repeat { body, condition } => {
                self.break_flag = false;

                loop {
                    self.execute_block(body)?;

                    if self.break_flag || self.return_values.is_some() {
                        break;
                    }

                    let cond = self.evaluate(condition)?;
                    if cond.is_truthy() {
                        break;
                    }
                }

                self.break_flag = false;
            }

            Stmt::ForNumeric { var, start, end, step, body } => {
                let start_val = self.evaluate(start)?.to_number().unwrap_or(0.0);
                let end_val = self.evaluate(end)?.to_number().unwrap_or(0.0);
                let step_val = step
                    .as_ref()
                    .map(|s| self.evaluate(s).ok().and_then(|v| v.to_number()))
                    .flatten()
                    .unwrap_or(1.0);

                self.break_flag = false;
                self.push_scope();

                let mut i = start_val;
                while (step_val > 0.0 && i <= end_val) || (step_val < 0.0 && i >= end_val) {
                    if self.break_flag {
                        break;
                    }

                    self.set_local(var.clone(), LuaValue::Number(i));
                    
                    for stmt in body {
                        self.execute_statement(stmt)?;
                        if self.break_flag || self.return_values.is_some() {
                            break;
                        }
                    }

                    if self.return_values.is_some() {
                        break;
                    }

                    i += step_val;
                }

                self.pop_scope();
                self.break_flag = false;
            }

            Stmt::ForGeneric { vars, exprs, body } => {
                // Evaluate iterator expressions
                let iterator_vals: Vec<LuaValue> = exprs
                    .iter()
                    .map(|e| self.evaluate(e))
                    .collect::<Result<_, _>>()?;

                // Get iterator function, state, and initial value
                let iter_func = iterator_vals.get(0).cloned().unwrap_or(LuaValue::Nil);
                let iter_state = iterator_vals.get(1).cloned().unwrap_or(LuaValue::Nil);
                let mut iter_var = iterator_vals.get(2).cloned().unwrap_or(LuaValue::Nil);

                self.break_flag = false;
                self.push_scope();

                loop {
                    if self.break_flag || self.return_values.is_some() {
                        break;
                    }

                    // Call iterator function
                    let results = self.call_function(&iter_func, &[iter_state.clone(), iter_var.clone()])?;
                    
                    // First result is the new control variable
                    let first = match &results {
                        LuaValue::Nil => break,
                        v => v.clone(),
                    };

                    // Assign variables
                    if !vars.is_empty() {
                        self.set_local(vars[0].clone(), first.clone());
                    }
                    
                    iter_var = first;

                    // Execute body
                    for stmt in body {
                        self.execute_statement(stmt)?;
                        if self.break_flag || self.return_values.is_some() {
                            break;
                        }
                    }
                }

                self.pop_scope();
                self.break_flag = false;
            }

            Stmt::Function { name, params, vararg, body, local } => {
                let closure = Rc::new(Closure::new(
                    Some(name.full_name()),
                    params.clone(),
                    *vararg,
                    body.clone(),
                    self.capture_upvalues(),
                ));

                self.functions.insert(name.full_name(), closure.clone());
                let func_value = LuaValue::Closure(closure);
                
                if *local {
                    self.set_local(name.full_name(), func_value);
                } else {
                    self.globals.insert(name.full_name(), func_value);
                }
            }

            Stmt::Return(values) => {
                let results: Vec<LuaValue> = values
                    .iter()
                    .map(|expr| self.evaluate(expr))
                    .collect::<Result<_, _>>()?;
                self.return_values = Some(results);
            }

            Stmt::Expression(expr) => {
                self.evaluate(expr)?;
            }

            Stmt::Break => {
                self.break_flag = true;
            }

            Stmt::Do(body) => {
                self.execute_block(body)?;
            }

            Stmt::Goto(_) | Stmt::Label(_) => {
                // Simplified: labels and goto not fully implemented
            }
        }

        Ok(())
    }

    fn execute_block(&mut self, statements: &[Stmt]) -> Result<(), String> {
        self.push_scope();

        for stmt in statements {
            self.execute_statement(stmt)?;

            if self.break_flag || self.return_values.is_some() {
                break;
            }
        }

        self.pop_scope();
        Ok(())
    }

    fn evaluate(&mut self, expr: &Expr) -> Result<LuaValue, String> {
        match expr {
            Expr::LiteralNil => Ok(LuaValue::Nil),
            Expr::LiteralBool(b) => Ok(LuaValue::Boolean(*b)),
            Expr::LiteralNumber(n) => Ok(LuaValue::Number(*n)),
            Expr::LiteralString(s) => Ok(LuaValue::String(s.clone())),

            Expr::Variable(name) => Ok(self.get_variable(name)),

            Expr::Vararg => {
                // Return first vararg or nil
                Ok(self.varargs.first().cloned().unwrap_or(LuaValue::Nil))
            }

            Expr::Index(table_expr, key_expr) => {
                let table = self.evaluate(table_expr)?;
                let key = self.evaluate(key_expr)?;

                match &table {
                    LuaValue::Table(t) => {
                        let key_str = key.to_lua_string();
                        Ok(t.get(&key_str).cloned().unwrap_or(LuaValue::Nil))
                    }
                    LuaValue::String(s) => {
                        // String indexing (for string methods)
                        if let LuaValue::Number(n) = key {
                            let idx = (n as usize).saturating_sub(1);
                            s.chars()
                                .nth(idx)
                                .map(|c| LuaValue::String(c.to_string()))
                                .ok_or_else(|| "index out of range".to_string())
                        } else {
                            Err("Invalid string index".to_string())
                        }
                    }
                    _ => Ok(LuaValue::Nil),
                }
            }

            Expr::BinaryOp { left, op, right } => {
                let lval = self.evaluate(left)?;

                // Short-circuit evaluation for and/or
                match op {
                    BinaryOperator::And => {
                        if !lval.is_truthy() {
                            return Ok(lval);
                        }
                        return self.evaluate(right);
                    }
                    BinaryOperator::Or => {
                        if lval.is_truthy() {
                            return Ok(lval);
                        }
                        return self.evaluate(right);
                    }
                    _ => {}
                }

                let rval = self.evaluate(right)?;
                self.apply_binary_op(op, &lval, &rval)
            }

            Expr::UnaryOp { op, operand } => {
                let val = self.evaluate(operand)?;
                self.apply_unary_op(op, &val)
            }

            Expr::Call { func, args } => {
                let func_val = self.evaluate(func)?;
                let arg_vals: Vec<LuaValue> = args
                    .iter()
                    .map(|a| self.evaluate(a))
                    .collect::<Result<_, _>>()?;

                self.call_function(&func_val, &arg_vals)
            }

            Expr::Table(entries) => {
                let mut table = LuaTable::new();
                let mut array_index = 1;

                for entry in entries {
                    match entry {
                        TableEntry::Array(value_expr) => {
                            let value = self.evaluate(value_expr)?;
                            table.set(array_index.to_string(), value);
                            array_index += 1;
                        }
                        TableEntry::KeyValue(key_expr, value_expr) => {
                            let key = self.evaluate(key_expr)?;
                            let value = self.evaluate(value_expr)?;
                            table.set(key.to_lua_string(), value);
                        }
                    }
                }

                Ok(LuaValue::Table(table))
            }

            Expr::Function { params, vararg, body } => {
                // Create anonymous closure
                let closure = Rc::new(Closure::new(
                    None,
                    params.clone(),
                    *vararg,
                    body.clone(),
                    self.capture_upvalues(),
                ));
                Ok(LuaValue::Closure(closure))
            }
        }
    }

    fn capture_upvalues(&self) -> HashMap<String, Upvalue> {
        let mut upvalues = HashMap::new();
        
        // Capture all visible local variables
        for scope in self.scopes.iter().rev() {
            for (name, value_ref) in &scope.values {
                if !upvalues.contains_key(name) {
                    upvalues.insert(
                        name.clone(),
                        Upvalue { value: value_ref.clone() },
                    );
                }
            }
        }
        
        upvalues
    }

    fn call_function(&mut self, func: &LuaValue, args: &[LuaValue]) -> Result<LuaValue, String> {
        match func {
            LuaValue::Function(name) => {
                if let Some(closure) = self.functions.get(name).cloned() {
                    self.call_closure(&closure, args)
                } else {
                    Err(format!("Function not found: {}", name))
                }
            }

            LuaValue::Closure(closure) => {
                self.call_closure(closure, args)
            }

            LuaValue::NativeFunction(name) => self.call_native(name, args),

            _ => Err(format!("Cannot call {:?}", func)),
        }
    }

    fn call_closure(&mut self, closure: &Rc<Closure>, args: &[LuaValue]) -> Result<LuaValue, String> {
        self.push_scope();

        // Restore upvalues
        for (name, upvalue) in &closure.upvalues {
            if let Some(scope) = self.scopes.last_mut() {
                scope.values.insert(name.clone(), upvalue.value.clone());
            }
        }

        // Bind parameters
        for (i, param) in closure.params.iter().enumerate() {
            let arg = args.get(i).cloned().unwrap_or(LuaValue::Nil);
            self.set_local(param.clone(), arg);
        }

        // Set varargs if function accepts them
        if closure.vararg {
            let vararg_start = closure.params.len();
            self.varargs = args[vararg_start..].to_vec();
        }

        let prev_return = self.return_values.take();

        for stmt in &closure.body {
            self.execute_statement(stmt)?;
            if self.return_values.is_some() {
                break;
            }
        }

        let result = self.return_values.take()
            .and_then(|v| v.into_iter().next())
            .unwrap_or(LuaValue::Nil);
        
        self.return_values = prev_return;
        self.varargs.clear();
        self.pop_scope();

        Ok(result)
    }

    fn call_native(&mut self, name: &str, args: &[LuaValue]) -> Result<LuaValue, String> {
        // Proxy-WASM bindings
        if let Some(method) = name.strip_prefix("veil.") {
            return self.call_veil_method(method, args);
        }

        // String library
        if let Some(method) = name.strip_prefix("string.") {
            return self.call_string_method(method, args);
        }

        // Math library
        if let Some(method) = name.strip_prefix("math.") {
            return self.call_math_method(method, args);
        }

        // Table library
        if let Some(method) = name.strip_prefix("table.") {
            return self.call_table_method(method, args);
        }

        // UTF8 library
        if let Some(method) = name.strip_prefix("utf8.") {
            return self.call_utf8_method(method, args);
        }

        // Standard library
        self.call_stdlib(name, args)
    }

    fn call_stdlib(&mut self, name: &str, args: &[LuaValue]) -> Result<LuaValue, String> {
        match name {
            "print" => {
                let output: Vec<String> = args.iter().map(|v| v.to_lua_string()).collect();
                self.state.borrow_mut().log_messages.push(("info".to_string(), output.join("\t")));
                Ok(LuaValue::Nil)
            }

            "tostring" => Ok(LuaValue::String(
                args.first().map(|v| v.to_lua_string()).unwrap_or_else(|| "nil".to_string()),
            )),

            "tonumber" => {
                let result = args.first().and_then(|v| v.to_number());
                Ok(result.map(LuaValue::Number).unwrap_or(LuaValue::Nil))
            }

            "type" => Ok(LuaValue::String(
                args.first().map(|v| v.type_name()).unwrap_or("nil").to_string(),
            )),

            "error" => {
                let msg = args.first().map(|v| v.to_lua_string()).unwrap_or_else(|| "error".to_string());
                Err(msg)
            }

            "assert" => {
                if args.first().map(|v| v.is_truthy()).unwrap_or(false) {
                    Ok(args.first().cloned().unwrap_or(LuaValue::Nil))
                } else {
                    let msg = args.get(1).map(|v| v.to_lua_string()).unwrap_or_else(|| "assertion failed!".to_string());
                    Err(msg)
                }
            }

            "pcall" => {
                // Simplified pcall
                Ok(LuaValue::Boolean(true))
            }

            "pairs" | "ipairs" => {
                // Return iterator function placeholder
                Ok(LuaValue::NativeFunction("next".to_string()))
            }

            "next" => {
                // Table iterator
                if let Some(LuaValue::Table(t)) = args.first() {
                    let key = args.get(1);
                    let mut found_next = key.is_none();
                    
                    for (k, v) in &t.data {
                        if found_next {
                            return Ok(LuaValue::String(k.clone()));
                        }
                        if let Some(LuaValue::String(search_key)) = key {
                            if k == search_key {
                                found_next = true;
                            }
                        }
                    }
                }
                Ok(LuaValue::Nil)
            }

            "select" => {
                if let Some(first) = args.first() {
                    match first {
                        LuaValue::String(s) if s == "#" => {
                            Ok(LuaValue::Number((args.len() - 1) as f64))
                        }
                        LuaValue::Number(n) => {
                            let idx = *n as usize;
                            Ok(args.get(idx).cloned().unwrap_or(LuaValue::Nil))
                        }
                        _ => Ok(LuaValue::Nil),
                    }
                } else {
                    Ok(LuaValue::Nil)
                }
            }

            "setmetatable" => {
                // Simplified version - just return the table
                Ok(args.first().cloned().unwrap_or(LuaValue::Nil))
            }

            "getmetatable" => {
                Ok(LuaValue::Nil)
            }

            "rawget" => {
                if let (Some(LuaValue::Table(t)), Some(key)) = (args.first(), args.get(1)) {
                    let key_str = key.to_lua_string();
                    Ok(t.get(&key_str).cloned().unwrap_or(LuaValue::Nil))
                } else {
                    Ok(LuaValue::Nil)
                }
            }

            "rawset" => {
                // Return the table
                Ok(args.first().cloned().unwrap_or(LuaValue::Nil))
            }

            "rawequal" => {
                let result = match (args.first(), args.get(1)) {
                    (Some(a), Some(b)) => a == b,
                    _ => false,
                };
                Ok(LuaValue::Boolean(result))
            }

            "unpack" => {
                if let Some(LuaValue::Table(t)) = args.first() {
                    // Return first element (simplified)
                    Ok(t.get("1").cloned().unwrap_or(LuaValue::Nil))
                } else {
                    Ok(LuaValue::Nil)
                }
            }

            _ => Err(format!("Unknown function: {}", name)),
        }
    }

    fn call_string_method(&self, method: &str, args: &[LuaValue]) -> Result<LuaValue, String> {
        match method {
            "len" => {
                let s = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
                Ok(LuaValue::Number(s.len() as f64))
            }

            "sub" => {
                let s = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
                let start = args.get(1).and_then(|v| v.to_number()).map(|n| n as i64).unwrap_or(1);
                let end = args.get(2).and_then(|v| v.to_number()).map(|n| n as i64).unwrap_or(-1);
                let len = s.len() as i64;

                let start_idx = if start < 0 { (len + start + 1).max(0) as usize } else { (start - 1).max(0) as usize };
                let end_idx = if end < 0 { (len + end + 1).max(0) as usize } else { end.min(len) as usize };

                if start_idx >= s.len() || end_idx <= start_idx {
                    Ok(LuaValue::String(String::new()))
                } else {
                    Ok(LuaValue::String(s[start_idx..end_idx].to_string()))
                }
            }

            "upper" => {
                let s = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
                Ok(LuaValue::String(s.to_uppercase()))
            }

            "lower" => {
                let s = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
                Ok(LuaValue::String(s.to_lowercase()))
            }

            "find" => {
                let s = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
                let pat = args.get(1).map(|v| v.to_lua_string()).unwrap_or_default();
                
                match pattern::match_pattern(&s, &pat) {
                    Ok(Some(m)) => Ok(LuaValue::Number((m.start + 1) as f64)),
                    Ok(None) => Ok(LuaValue::Nil),
                    Err(_) => {
                        // Fallback to simple find
                        match s.find(&pat) {
                            Some(pos) => Ok(LuaValue::Number((pos + 1) as f64)),
                            None => Ok(LuaValue::Nil),
                        }
                    }
                }
            }

            "match" => {
                let s = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
                let pat = args.get(1).map(|v| v.to_lua_string()).unwrap_or_default();

                match pattern::match_pattern(&s, &pat) {
                    Ok(Some(m)) => {
                        if m.captures.is_empty() {
                            Ok(LuaValue::String(m.matched))
                        } else {
                            // Return first capture
                            Ok(LuaValue::String(m.captures[0].clone()))
                        }
                    }
                    Ok(None) => Ok(LuaValue::Nil),
                    Err(e) => Err(e),
                }
            }

            "gmatch" => {
                // Simplified: just return the string
                Ok(args.first().cloned().unwrap_or(LuaValue::Nil))
            }

            "gsub" => {
                let s = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
                let pat = args.get(1).map(|v| v.to_lua_string()).unwrap_or_default();
                let repl = args.get(2).map(|v| v.to_lua_string()).unwrap_or_default();
                let n = args.get(3).and_then(|v| v.to_number()).map(|n| n as usize);

                match pattern::gsub(&s, &pat, &repl, n) {
                    Ok((result, _count)) => Ok(LuaValue::String(result)),
                    Err(_) => {
                        // Fallback to simple replace
                        Ok(LuaValue::String(s.replace(&pat, &repl)))
                    }
                }
            }

            "format" => {
                self.string_format(args)
            }

            "rep" => {
                let s = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
                let n = args.get(1).and_then(|v| v.to_number()).map(|n| n as usize).unwrap_or(1);
                Ok(LuaValue::String(s.repeat(n)))
            }

            "reverse" => {
                let s = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
                Ok(LuaValue::String(s.chars().rev().collect()))
            }

            "byte" => {
                let s = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
                let pos = args.get(1).and_then(|v| v.to_number()).map(|n| (n as usize).saturating_sub(1)).unwrap_or(0);
                s.chars().nth(pos)
                    .map(|c| Ok(LuaValue::Number(c as u32 as f64)))
                    .unwrap_or(Ok(LuaValue::Nil))
            }

            "char" => {
                let chars: String = args.iter()
                    .filter_map(|v| v.to_number())
                    .filter_map(|n| char::from_u32(n as u32))
                    .collect();
                Ok(LuaValue::String(chars))
            }

            "split" => {
                let s = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
                let sep = args.get(1).map(|v| v.to_lua_string()).unwrap_or_else(|| " ".to_string());
                
                let mut table = LuaTable::new();
                for (i, part) in s.split(&sep).enumerate() {
                    table.set((i + 1).to_string(), LuaValue::String(part.to_string()));
                }
                Ok(LuaValue::Table(table))
            }

            _ => Err(format!("Unknown string method: {}", method)),
        }
    }

    fn call_math_method(&self, method: &str, args: &[LuaValue]) -> Result<LuaValue, String> {
        let get_num = |idx: usize| args.get(idx).and_then(|v| v.to_number());
        
        match method {
            "abs" => Ok(LuaValue::Number(get_num(0).unwrap_or(0.0).abs())),
            "ceil" => Ok(LuaValue::Number(get_num(0).unwrap_or(0.0).ceil())),
            "floor" => Ok(LuaValue::Number(get_num(0).unwrap_or(0.0).floor())),
            "sin" => Ok(LuaValue::Number(get_num(0).unwrap_or(0.0).sin())),
            "cos" => Ok(LuaValue::Number(get_num(0).unwrap_or(0.0).cos())),
            "tan" => Ok(LuaValue::Number(get_num(0).unwrap_or(0.0).tan())),
            "asin" => Ok(LuaValue::Number(get_num(0).unwrap_or(0.0).asin())),
            "acos" => Ok(LuaValue::Number(get_num(0).unwrap_or(0.0).acos())),
            "atan" => Ok(LuaValue::Number(get_num(0).unwrap_or(0.0).atan())),
            "sqrt" => Ok(LuaValue::Number(get_num(0).unwrap_or(0.0).sqrt())),
            "log" => Ok(LuaValue::Number(get_num(0).unwrap_or(0.0).ln())),
            "exp" => Ok(LuaValue::Number(get_num(0).unwrap_or(0.0).exp())),
            "pow" => {
                let base = get_num(0).unwrap_or(0.0);
                let exp = get_num(1).unwrap_or(1.0);
                Ok(LuaValue::Number(base.powf(exp)))
            }
            "max" => {
                let max = args.iter()
                    .filter_map(|v| v.to_number())
                    .fold(f64::NEG_INFINITY, f64::max);
                Ok(LuaValue::Number(max))
            }
            "min" => {
                let min = args.iter()
                    .filter_map(|v| v.to_number())
                    .fold(f64::INFINITY, f64::min);
                Ok(LuaValue::Number(min))
            }
            "random" => {
                // Simple pseudo-random (not cryptographically secure)
                use std::time::{SystemTime, UNIX_EPOCH};
                let seed = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                let val = ((seed % 1000000) as f64) / 1000000.0;
                
                match (get_num(0), get_num(1)) {
                    (None, None) => Ok(LuaValue::Number(val)),
                    (Some(m), None) => Ok(LuaValue::Number((val * m).floor() + 1.0)),
                    (Some(m), Some(n)) => Ok(LuaValue::Number((val * (n - m + 1.0)).floor() + m)),
                    (None, Some(n)) => Ok(LuaValue::Number((val * n).floor() + 1.0)),
                }
            }
            "randomseed" => Ok(LuaValue::Nil),
            "deg" => Ok(LuaValue::Number(get_num(0).unwrap_or(0.0).to_degrees())),
            "rad" => Ok(LuaValue::Number(get_num(0).unwrap_or(0.0).to_radians())),
            "modf" => {
                let n = get_num(0).unwrap_or(0.0);
                Ok(LuaValue::Number(n.trunc()))
            }
            "fmod" => {
                let x = get_num(0).unwrap_or(0.0);
                let y = get_num(1).unwrap_or(1.0);
                Ok(LuaValue::Number(x % y))
            }
            _ => Err(format!("Unknown math method: {}", method)),
        }
    }

    fn call_table_method(&mut self, method: &str, args: &[LuaValue]) -> Result<LuaValue, String> {
        match method {
            "insert" => {
                // table.insert(t, value) - insert at end
                // table.insert(t, pos, value) - insert at pos
                if args.len() < 2 {
                    return Ok(LuaValue::Nil);
                }
                
                if let LuaValue::Table(mut t) = args[0].clone() {
                    let len = t.len();
                    
                    if args.len() == 2 {
                        // Insert at end
                        t.set((len + 1).to_string(), args[1].clone());
                    } else if args.len() >= 3 {
                        // Insert at position
                        let pos = args[1].to_number().map(|n| n as usize).unwrap_or(len + 1);
                        // Shift elements
                        for i in (pos..=len).rev() {
                            if let Some(v) = t.get(&i.to_string()).cloned() {
                                t.set((i + 1).to_string(), v);
                            }
                        }
                        t.set(pos.to_string(), args[2].clone());
                    }
                    
                    // Update the original table variable if possible
                    return Ok(LuaValue::Nil);
                }
                Ok(LuaValue::Nil)
            }
            
            "remove" => {
                // table.remove(t) - remove last element
                // table.remove(t, pos) - remove element at pos
                if let LuaValue::Table(mut t) = args.first().cloned().unwrap_or(LuaValue::Nil) {
                    let len = t.len();
                    if len == 0 {
                        return Ok(LuaValue::Nil);
                    }
                    
                    let pos = args.get(1)
                        .and_then(|v| v.to_number())
                        .map(|n| n as usize)
                        .unwrap_or(len);
                    
                    // Get the removed value
                    let removed = t.get(&pos.to_string()).cloned().unwrap_or(LuaValue::Nil);
                    
                    // Shift elements down
                    for i in pos..len {
                        if let Some(v) = t.get(&(i + 1).to_string()).cloned() {
                            t.set(i.to_string(), v);
                        }
                    }
                    t.data.remove(&len.to_string());
                    
                    return Ok(removed);
                }
                Ok(LuaValue::Nil)
            }
            
            "concat" => {
                if let Some(LuaValue::Table(t)) = args.first() {
                    let sep = args.get(1).map(|v| v.to_lua_string()).unwrap_or_default();
                    let i = args.get(2).and_then(|v| v.to_number()).map(|n| n as usize).unwrap_or(1);
                    let j = args.get(3).and_then(|v| v.to_number()).map(|n| n as usize).unwrap_or(t.len());
                    
                    let mut parts = Vec::new();
                    for idx in i..=j {
                        if let Some(v) = t.get(&idx.to_string()) {
                            parts.push(v.to_lua_string());
                        }
                    }
                    Ok(LuaValue::String(parts.join(&sep)))
                } else {
                    Ok(LuaValue::String(String::new()))
                }
            }
            
            "sort" => {
                // Sort array portion of table in place
                if let LuaValue::Table(mut t) = args.first().cloned().unwrap_or(LuaValue::Nil) {
                    let len = t.len();
                    if len == 0 {
                        return Ok(LuaValue::Nil);
                    }
                    
                    // Extract array elements
                    let mut elements: Vec<LuaValue> = Vec::new();
                    for i in 1..=len {
                        if let Some(v) = t.get(&i.to_string()) {
                            elements.push(v.clone());
                        }
                    }
                    
                    // Sort (numbers and strings)
                    elements.sort_by(|a, b| {
                        match (a.to_number(), b.to_number()) {
                            (Some(na), Some(nb)) => na.partial_cmp(&nb).unwrap_or(std::cmp::Ordering::Equal),
                            _ => a.to_lua_string().cmp(&b.to_lua_string()),
                        }
                    });
                    
                    // Put back
                    for (i, v) in elements.into_iter().enumerate() {
                        t.set((i + 1).to_string(), v);
                    }
                    
                    return Ok(LuaValue::Nil);
                }
                Ok(LuaValue::Nil)
            }
            
            "pack" => {
                let mut table = LuaTable::new();
                for (i, arg) in args.iter().enumerate() {
                    table.set((i + 1).to_string(), arg.clone());
                }
                table.set("n".to_string(), LuaValue::Number(args.len() as f64));
                Ok(LuaValue::Table(table))
            }
            
            "unpack" => {
                // Returns the first element (simplified)
                if let Some(LuaValue::Table(t)) = args.first() {
                    let i = args.get(1).and_then(|v| v.to_number()).map(|n| n as usize).unwrap_or(1);
                    Ok(t.get(&i.to_string()).cloned().unwrap_or(LuaValue::Nil))
                } else {
                    Ok(LuaValue::Nil)
                }
            }
            
            _ => Err(format!("Unknown table method: {}", method)),
        }
    }

    fn call_veil_method(&mut self, method: &str, args: &[LuaValue]) -> Result<LuaValue, String> {
        let mut state = self.state.borrow_mut();

        match method {
            "log" => {
                let level = args.first().map(|v| v.to_lua_string()).unwrap_or_else(|| "info".to_string());
                let msg = args.get(1).map(|v| v.to_lua_string()).unwrap_or_default();
                state.log_messages.push((level, msg));
                Ok(LuaValue::Nil)
            }

            "get_request_header" => {
                let name = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
                for (k, v) in &state.current_request_headers {
                    if k.eq_ignore_ascii_case(&name) {
                        return Ok(LuaValue::String(v.clone()));
                    }
                }
                Ok(LuaValue::Nil)
            }

            "set_request_header" => {
                let name = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
                let value = args.get(1).map(|v| v.to_lua_string()).unwrap_or_default();
                state.request_headers_to_set.push((name, value));
                Ok(LuaValue::Nil)
            }

            "get_response_header" => {
                let name = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
                for (k, v) in &state.current_response_headers {
                    if k.eq_ignore_ascii_case(&name) {
                        return Ok(LuaValue::String(v.clone()));
                    }
                }
                Ok(LuaValue::Nil)
            }

            "set_response_header" => {
                let name = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
                let value = args.get(1).map(|v| v.to_lua_string()).unwrap_or_default();
                state.response_headers_to_set.push((name, value));
                Ok(LuaValue::Nil)
            }

            "get_path" => Ok(LuaValue::String(state.current_path.clone())),

            "get_method" => Ok(LuaValue::String(state.current_method.clone())),

            "send_local_response" => {
                let status = args.first().and_then(|v| v.to_number()).map(|n| n as u16).unwrap_or(200);
                let body = args.get(1).map(|v| v.to_lua_string()).unwrap_or_default();
                state.local_response = Some((status, body));
                Ok(LuaValue::Nil)
            }

            "get_headers" => {
                let mut table = LuaTable::new();
                for (k, v) in &state.current_request_headers {
                    table.set(k.clone(), LuaValue::String(v.clone()));
                }
                Ok(LuaValue::Table(table))
            }

            _ => Err(format!("Unknown veil method: {}", method)),
        }
    }

    fn apply_binary_op(&self, op: &BinaryOperator, left: &LuaValue, right: &LuaValue) -> Result<LuaValue, String> {
        match op {
            BinaryOperator::Add => {
                let l = left.to_number().ok_or("cannot add non-numbers")?;
                let r = right.to_number().ok_or("cannot add non-numbers")?;
                Ok(LuaValue::Number(l + r))
            }
            BinaryOperator::Sub => {
                let l = left.to_number().ok_or("cannot subtract non-numbers")?;
                let r = right.to_number().ok_or("cannot subtract non-numbers")?;
                Ok(LuaValue::Number(l - r))
            }
            BinaryOperator::Mul => {
                let l = left.to_number().ok_or("cannot multiply non-numbers")?;
                let r = right.to_number().ok_or("cannot multiply non-numbers")?;
                Ok(LuaValue::Number(l * r))
            }
            BinaryOperator::Div => {
                let l = left.to_number().ok_or("cannot divide non-numbers")?;
                let r = right.to_number().ok_or("cannot divide non-numbers")?;
                Ok(LuaValue::Number(l / r))
            }
            BinaryOperator::IDiv => {
                let l = left.to_number().ok_or("cannot divide non-numbers")?;
                let r = right.to_number().ok_or("cannot divide non-numbers")?;
                Ok(LuaValue::Number((l / r).floor()))
            }
            BinaryOperator::Mod => {
                let l = left.to_number().ok_or("cannot mod non-numbers")?;
                let r = right.to_number().ok_or("cannot mod non-numbers")?;
                Ok(LuaValue::Number(l % r))
            }
            BinaryOperator::Pow => {
                let l = left.to_number().ok_or("cannot pow non-numbers")?;
                let r = right.to_number().ok_or("cannot pow non-numbers")?;
                Ok(LuaValue::Number(l.powf(r)))
            }
            BinaryOperator::Eq => Ok(LuaValue::Boolean(left == right)),
            BinaryOperator::NotEq => Ok(LuaValue::Boolean(left != right)),
            BinaryOperator::Lt => {
                let l = left.to_number().ok_or("cannot compare non-numbers")?;
                let r = right.to_number().ok_or("cannot compare non-numbers")?;
                Ok(LuaValue::Boolean(l < r))
            }
            BinaryOperator::Gt => {
                let l = left.to_number().ok_or("cannot compare non-numbers")?;
                let r = right.to_number().ok_or("cannot compare non-numbers")?;
                Ok(LuaValue::Boolean(l > r))
            }
            BinaryOperator::Le => {
                let l = left.to_number().ok_or("cannot compare non-numbers")?;
                let r = right.to_number().ok_or("cannot compare non-numbers")?;
                Ok(LuaValue::Boolean(l <= r))
            }
            BinaryOperator::Ge => {
                let l = left.to_number().ok_or("cannot compare non-numbers")?;
                let r = right.to_number().ok_or("cannot compare non-numbers")?;
                Ok(LuaValue::Boolean(l >= r))
            }
            BinaryOperator::Concat => {
                let l = left.to_lua_string();
                let r = right.to_lua_string();
                Ok(LuaValue::String(format!("{}{}", l, r)))
            }
            BinaryOperator::BAnd => {
                let l = left.to_number().ok_or("cannot bitwise and non-numbers")? as i64;
                let r = right.to_number().ok_or("cannot bitwise and non-numbers")? as i64;
                Ok(LuaValue::Number((l & r) as f64))
            }
            BinaryOperator::BOr => {
                let l = left.to_number().ok_or("cannot bitwise or non-numbers")? as i64;
                let r = right.to_number().ok_or("cannot bitwise or non-numbers")? as i64;
                Ok(LuaValue::Number((l | r) as f64))
            }
            BinaryOperator::BXor => {
                let l = left.to_number().ok_or("cannot bitwise xor non-numbers")? as i64;
                let r = right.to_number().ok_or("cannot bitwise xor non-numbers")? as i64;
                Ok(LuaValue::Number((l ^ r) as f64))
            }
            BinaryOperator::Shl => {
                let l = left.to_number().ok_or("cannot shift non-numbers")? as i64;
                let r = right.to_number().ok_or("cannot shift non-numbers")? as u32;
                Ok(LuaValue::Number((l << r) as f64))
            }
            BinaryOperator::Shr => {
                let l = left.to_number().ok_or("cannot shift non-numbers")? as i64;
                let r = right.to_number().ok_or("cannot shift non-numbers")? as u32;
                Ok(LuaValue::Number((l >> r) as f64))
            }
            BinaryOperator::And | BinaryOperator::Or => unreachable!(),
        }
    }

    fn apply_unary_op(&self, op: &UnaryOperator, val: &LuaValue) -> Result<LuaValue, String> {
        match op {
            UnaryOperator::Neg => {
                let n = val.to_number().ok_or("cannot negate non-number")?;
                Ok(LuaValue::Number(-n))
            }
            UnaryOperator::Not => Ok(LuaValue::Boolean(!val.is_truthy())),
            UnaryOperator::Len => match val {
                LuaValue::String(s) => Ok(LuaValue::Number(s.len() as f64)),
                LuaValue::Table(t) => Ok(LuaValue::Number(t.len() as f64)),
                _ => Err("cannot get length of non-string/table".to_string()),
            },
            UnaryOperator::BNot => {
                let n = val.to_number().ok_or("cannot bitwise not non-number")? as i64;
                Ok(LuaValue::Number((!n) as f64))
            }
        }
    }

    fn push_scope(&mut self) {
        self.scopes.push(Scope::new());
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    fn set_local(&mut self, name: String, value: LuaValue) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.define(name, value);
        } else {
            self.globals.insert(name, value);
        }
    }

    fn set_variable(&mut self, name: String, value: LuaValue) {
        // Check local scopes first
        for scope in self.scopes.iter_mut().rev() {
            if scope.get(&name).is_some() {
                scope.set(name, value);
                return;
            }
        }

        // Set in globals
        self.globals.insert(name, value);
    }

    fn get_variable(&self, name: &str) -> LuaValue {
        // Check local scopes first
        for scope in self.scopes.iter().rev() {
            if let Some(value_ref) = scope.get(name) {
                return value_ref.borrow().clone();
            }
        }

        // Check globals
        self.globals.get(name).cloned().unwrap_or(LuaValue::Nil)
    }

    /// Enhanced string.format implementation
    fn string_format(&self, args: &[LuaValue]) -> Result<LuaValue, String> {
        let format_str = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
        let mut result = String::new();
        let mut arg_idx = 1;
        let mut chars = format_str.chars().peekable();

        while let Some(c) = chars.next() {
            if c != '%' {
                result.push(c);
                continue;
            }

            // Parse format specifier
            let next = chars.peek().cloned();
            if next == Some('%') {
                chars.next();
                result.push('%');
                continue;
            }

            // Parse flags
            let mut left_align = false;
            let mut zero_pad = false;
            let mut plus_sign = false;
            let mut space_sign = false;

            loop {
                match chars.peek() {
                    Some('-') => { left_align = true; chars.next(); }
                    Some('+') => { plus_sign = true; chars.next(); }
                    Some(' ') => { space_sign = true; chars.next(); }
                    Some('0') => { zero_pad = true; chars.next(); }
                    Some('#') => { chars.next(); } // alternate form (ignored for now)
                    _ => break,
                }
            }

            // Parse width
            let mut width = 0usize;
            while let Some(&c) = chars.peek() {
                if c.is_ascii_digit() {
                    width = width * 10 + (c as usize - '0' as usize);
                    chars.next();
                } else {
                    break;
                }
            }

            // Parse precision
            let mut precision: Option<usize> = None;
            if chars.peek() == Some(&'.') {
                chars.next();
                let mut prec = 0usize;
                while let Some(&c) = chars.peek() {
                    if c.is_ascii_digit() {
                        prec = prec * 10 + (c as usize - '0' as usize);
                        chars.next();
                    } else {
                        break;
                    }
                }
                precision = Some(prec);
            }

            // Parse conversion specifier
            let spec = chars.next().unwrap_or('s');
            let arg = args.get(arg_idx).cloned().unwrap_or(LuaValue::Nil);
            arg_idx += 1;

            let formatted = match spec {
                's' => {
                    let s = arg.to_lua_string();
                    if let Some(prec) = precision {
                        s.chars().take(prec).collect()
                    } else {
                        s
                    }
                }
                'd' | 'i' => {
                    let n = arg.to_number().unwrap_or(0.0) as i64;
                    let s = if plus_sign && n >= 0 {
                        format!("+{}", n)
                    } else if space_sign && n >= 0 {
                        format!(" {}", n)
                    } else {
                        format!("{}", n)
                    };
                    s
                }
                'u' => {
                    let n = arg.to_number().unwrap_or(0.0) as u64;
                    format!("{}", n)
                }
                'f' => {
                    let n = arg.to_number().unwrap_or(0.0);
                    let prec = precision.unwrap_or(6);
                    if plus_sign && n >= 0.0 {
                        format!("+{:.prec$}", n, prec = prec)
                    } else if space_sign && n >= 0.0 {
                        format!(" {:.prec$}", n, prec = prec)
                    } else {
                        format!("{:.prec$}", n, prec = prec)
                    }
                }
                'e' => {
                    let n = arg.to_number().unwrap_or(0.0);
                    let prec = precision.unwrap_or(6);
                    format!("{:.prec$e}", n, prec = prec)
                }
                'E' => {
                    let n = arg.to_number().unwrap_or(0.0);
                    let prec = precision.unwrap_or(6);
                    format!("{:.prec$E}", n, prec = prec)
                }
                'g' | 'G' => {
                    let n = arg.to_number().unwrap_or(0.0);
                    let prec = precision.unwrap_or(6);
                    // Use shorter of %e or %f
                    let f = format!("{:.prec$}", n, prec = prec);
                    let e = format!("{:.prec$e}", n, prec = prec);
                    if f.len() <= e.len() { f } else { e }
                }
                'x' => {
                    let n = arg.to_number().unwrap_or(0.0) as i64;
                    format!("{:x}", n)
                }
                'X' => {
                    let n = arg.to_number().unwrap_or(0.0) as i64;
                    format!("{:X}", n)
                }
                'o' => {
                    let n = arg.to_number().unwrap_or(0.0) as i64;
                    format!("{:o}", n)
                }
                'c' => {
                    let n = arg.to_number().unwrap_or(0.0) as u32;
                    char::from_u32(n).map(|c| c.to_string()).unwrap_or_default()
                }
                'q' => {
                    // Quoted string
                    let s = arg.to_lua_string();
                    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
                }
                _ => arg.to_lua_string(),
            };

            // Apply width and alignment
            let padded = if width > formatted.len() {
                let pad = width - formatted.len();
                let pad_char = if zero_pad && !left_align { '0' } else { ' ' };
                if left_align {
                    format!("{}{}", formatted, pad_char.to_string().repeat(pad))
                } else {
                    format!("{}{}", pad_char.to_string().repeat(pad), formatted)
                }
            } else {
                formatted
            };

            result.push_str(&padded);
        }

        Ok(LuaValue::String(result))
    }

    /// UTF-8 library methods
    fn call_utf8_method(&self, method: &str, args: &[LuaValue]) -> Result<LuaValue, String> {
        match method {
            "len" => {
                let s = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
                let i = args.get(1).and_then(|v| v.to_number()).map(|n| n as usize).unwrap_or(1);
                let j = args.get(2).and_then(|v| v.to_number()).map(|n| n as i64).unwrap_or(-1);
                
                let bytes = s.as_bytes();
                let start = (i.saturating_sub(1)).min(bytes.len());
                let end = if j < 0 {
                    (bytes.len() as i64 + j + 1).max(0) as usize
                } else {
                    (j as usize).min(bytes.len())
                };
                
                if start > end {
                    return Ok(LuaValue::Number(0.0));
                }
                
                // Count UTF-8 characters
                let slice = &s[start..end];
                Ok(LuaValue::Number(slice.chars().count() as f64))
            }

            "char" => {
                let chars: String = args.iter()
                    .filter_map(|v| v.to_number())
                    .filter_map(|n| char::from_u32(n as u32))
                    .collect();
                Ok(LuaValue::String(chars))
            }

            "codepoint" => {
                let s = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
                let i = args.get(1).and_then(|v| v.to_number()).map(|n| (n as usize).saturating_sub(1)).unwrap_or(0);
                
                if let Some(c) = s.chars().nth(i) {
                    Ok(LuaValue::Number(c as u32 as f64))
                } else {
                    Ok(LuaValue::Nil)
                }
            }

            "codes" => {
                // Returns an iterator function (simplified: return nil)
                Ok(LuaValue::NativeFunction("utf8.codes_iter".to_string()))
            }

            "offset" => {
                let s = args.first().map(|v| v.to_lua_string()).unwrap_or_default();
                let n = args.get(1).and_then(|v| v.to_number()).map(|x| x as i64).unwrap_or(1);
                
                if n <= 0 {
                    return Ok(LuaValue::Nil);
                }
                
                let mut byte_pos = 0;
                let mut char_count = 0;
                
                for (i, c) in s.char_indices() {
                    char_count += 1;
                    if char_count == n as usize {
                        byte_pos = i + 1; // Lua is 1-indexed
                        break;
                    }
                }
                
                if char_count >= n as usize {
                    Ok(LuaValue::Number(byte_pos as f64))
                } else {
                    Ok(LuaValue::Nil)
                }
            }

            "charpattern" => {
                Ok(LuaValue::String("[\\x00-\\x7F\\xC2-\\xF4][\\x80-\\xBF]*".to_string()))
            }

            _ => Err(format!("Unknown utf8 method: {}", method)),
        }
    }
}

