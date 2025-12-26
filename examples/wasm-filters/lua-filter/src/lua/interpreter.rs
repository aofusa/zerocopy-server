//! Lua Interpreter

use crate::lua::ast::*;
use crate::lua::stdlib;
use crate::lua::value::LuaValue;
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

/// Lua Interpreter
pub struct Interpreter {
    /// Global variables
    globals: HashMap<String, LuaValue>,

    /// Local variable scopes
    scopes: Vec<HashMap<String, LuaValue>>,

    /// Defined functions
    functions: HashMap<String, (Vec<String>, Vec<Stmt>)>,

    /// Shared state with Proxy-WASM
    pub state: Rc<RefCell<SharedState>>,

    /// Break flag for loops
    break_flag: bool,

    /// Return value
    return_value: Option<LuaValue>,
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
        ] {
            globals.insert(name.to_string(), LuaValue::NativeFunction(name.to_string()));
        }

        // Register string table
        globals.insert(
            "string".to_string(),
            LuaValue::Table(stdlib::create_string_table()),
        );

        // Register veil table (Proxy-WASM bindings)
        let mut veil = HashMap::new();
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
            veil.insert(
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
            return_value: None,
        }
    }

    pub fn execute(&mut self, program: &Program) -> Result<LuaValue, String> {
        self.return_value = None;
        self.break_flag = false;

        for stmt in &program.statements {
            self.execute_statement(stmt)?;

            if self.return_value.is_some() {
                break;
            }
        }

        Ok(self.return_value.take().unwrap_or(LuaValue::Nil))
    }

    fn execute_statement(&mut self, stmt: &Stmt) -> Result<(), String> {
        match stmt {
            Stmt::Assign {
                targets,
                values,
                local,
            } => {
                let evaluated: Vec<LuaValue> = values
                    .iter()
                    .map(|expr| self.evaluate(expr))
                    .collect::<Result<_, _>>()?;

                for (i, target) in targets.iter().enumerate() {
                    let value = evaluated.get(i).cloned().unwrap_or(LuaValue::Nil);
                    if *local {
                        self.set_local(target.clone(), value);
                    } else {
                        self.set_variable(target.clone(), value);
                    }
                }
            }

            Stmt::TableAssign { table, key, value } => {
                let table_val = self.evaluate(table)?;
                let key_val = self.evaluate(key)?;
                let val = self.evaluate(value)?;

                if let LuaValue::Table(mut t) = table_val {
                    t.insert(key_val.to_lua_string(), val);
                    // Re-assign the table
                    if let Expr::Variable(name) = table {
                        self.set_variable(name.clone(), LuaValue::Table(t));
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

                    if self.return_value.is_some() {
                        break;
                    }
                }

                self.break_flag = false;
            }

            Stmt::ForNumeric {
                var,
                start,
                end,
                step,
                body,
            } => {
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
                    self.execute_block(body)?;

                    if self.return_value.is_some() {
                        break;
                    }

                    i += step_val;
                }

                self.pop_scope();
                self.break_flag = false;
            }

            Stmt::Function { name, params, body } => {
                self.functions
                    .insert(name.clone(), (params.clone(), body.clone()));
                self.globals
                    .insert(name.clone(), LuaValue::Function(name.clone()));
            }

            Stmt::Return(values) => {
                let result = if values.is_empty() {
                    LuaValue::Nil
                } else {
                    self.evaluate(&values[0])?
                };
                self.return_value = Some(result);
            }

            Stmt::Expression(expr) => {
                self.evaluate(expr)?;
            }

            Stmt::Break => {
                self.break_flag = true;
            }
        }

        Ok(())
    }

    fn execute_block(&mut self, statements: &[Stmt]) -> Result<(), String> {
        self.push_scope();

        for stmt in statements {
            self.execute_statement(stmt)?;

            if self.break_flag || self.return_value.is_some() {
                break;
            }
        }

        self.pop_scope();
        Ok(())
    }

    fn evaluate(&mut self, expr: &Expr) -> Result<LuaValue, String> {
        match expr {
            Expr::Literal(value) => Ok(value.clone()),

            Expr::Variable(name) => Ok(self.get_variable(name)),

            Expr::Index(table_expr, key_expr) => {
                let table = self.evaluate(table_expr)?;
                let key = self.evaluate(key_expr)?;

                match table {
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
                let mut table = HashMap::new();
                let mut array_index = 1;

                for (key_opt, value_expr) in entries {
                    let value = self.evaluate(value_expr)?;

                    if let Some(key_expr) = key_opt {
                        let key = self.evaluate(key_expr)?;
                        table.insert(key.to_lua_string(), value);
                    } else {
                        table.insert(array_index.to_string(), value);
                        array_index += 1;
                    }
                }

                Ok(LuaValue::Table(table))
            }
        }
    }

    fn call_function(
        &mut self,
        func: &LuaValue,
        args: &[LuaValue],
    ) -> Result<LuaValue, String> {
        match func {
            LuaValue::Function(name) => {
                if let Some((params, body)) = self.functions.get(name).cloned() {
                    self.push_scope();

                    for (i, param) in params.iter().enumerate() {
                        let arg = args.get(i).cloned().unwrap_or(LuaValue::Nil);
                        self.set_local(param.clone(), arg);
                    }

                    let prev_return = self.return_value.take();

                    for stmt in &body {
                        self.execute_statement(stmt)?;
                        if self.return_value.is_some() {
                            break;
                        }
                    }

                    let result = self.return_value.take().unwrap_or(LuaValue::Nil);
                    self.return_value = prev_return;
                    self.pop_scope();

                    Ok(result)
                } else {
                    Err(format!("Function not found: {}", name))
                }
            }

            LuaValue::NativeFunction(name) => self.call_native(name, args),

            _ => Err(format!("Cannot call {:?}", func)),
        }
    }

    fn call_native(&mut self, name: &str, args: &[LuaValue]) -> Result<LuaValue, String> {
        // Proxy-WASM bindings
        if name.starts_with("veil.") {
            let method = &name[5..];
            return self.call_veil_method(method, args);
        }

        // String library
        if name.starts_with("string.") {
            let method = &name[7..];
            return stdlib::call_string_lib(method, args);
        }

        // Standard library
        let log_fn = |level: &str, msg: &str| {
            self.state
                .borrow_mut()
                .log_messages
                .push((level.to_string(), msg.to_string()));
        };

        stdlib::call_stdlib(name, args, &log_fn)
    }

    fn call_veil_method(&mut self, method: &str, args: &[LuaValue]) -> Result<LuaValue, String> {
        let mut state = self.state.borrow_mut();

        match method {
            "log" => {
                let level = args
                    .first()
                    .map(|v| v.to_lua_string())
                    .unwrap_or_else(|| "info".to_string());
                let msg = args
                    .get(1)
                    .map(|v| v.to_lua_string())
                    .unwrap_or_default();
                state.log_messages.push((level, msg));
                Ok(LuaValue::Nil)
            }

            "get_request_header" => {
                let name = args
                    .first()
                    .map(|v| v.to_lua_string())
                    .unwrap_or_default();
                for (k, v) in &state.current_request_headers {
                    if k.eq_ignore_ascii_case(&name) {
                        return Ok(LuaValue::String(v.clone()));
                    }
                }
                Ok(LuaValue::Nil)
            }

            "set_request_header" => {
                let name = args
                    .first()
                    .map(|v| v.to_lua_string())
                    .unwrap_or_default();
                let value = args
                    .get(1)
                    .map(|v| v.to_lua_string())
                    .unwrap_or_default();
                state.request_headers_to_set.push((name, value));
                Ok(LuaValue::Nil)
            }

            "get_response_header" => {
                let name = args
                    .first()
                    .map(|v| v.to_lua_string())
                    .unwrap_or_default();
                for (k, v) in &state.current_response_headers {
                    if k.eq_ignore_ascii_case(&name) {
                        return Ok(LuaValue::String(v.clone()));
                    }
                }
                Ok(LuaValue::Nil)
            }

            "set_response_header" => {
                let name = args
                    .first()
                    .map(|v| v.to_lua_string())
                    .unwrap_or_default();
                let value = args
                    .get(1)
                    .map(|v| v.to_lua_string())
                    .unwrap_or_default();
                state.response_headers_to_set.push((name, value));
                Ok(LuaValue::Nil)
            }

            "get_path" => Ok(LuaValue::String(state.current_path.clone())),

            "get_method" => Ok(LuaValue::String(state.current_method.clone())),

            "send_local_response" => {
                let status = args
                    .first()
                    .and_then(|v| v.to_number())
                    .map(|n| n as u16)
                    .unwrap_or(200);
                let body = args
                    .get(1)
                    .map(|v| v.to_lua_string())
                    .unwrap_or_default();
                state.local_response = Some((status, body));
                Ok(LuaValue::Nil)
            }

            "get_headers" => {
                let mut table = HashMap::new();
                for (k, v) in &state.current_request_headers {
                    table.insert(k.clone(), LuaValue::String(v.clone()));
                }
                Ok(LuaValue::Table(table))
            }

            _ => Err(format!("Unknown veil method: {}", method)),
        }
    }

    fn apply_binary_op(
        &self,
        op: &BinaryOperator,
        left: &LuaValue,
        right: &LuaValue,
    ) -> Result<LuaValue, String> {
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
                if r == 0.0 {
                    Ok(LuaValue::Number(f64::INFINITY))
                } else {
                    Ok(LuaValue::Number(l / r))
                }
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
            BinaryOperator::And | BinaryOperator::Or => {
                // Should be handled by short-circuit in evaluate()
                unreachable!()
            }
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
                LuaValue::Table(t) => {
                    // Array length (highest consecutive integer key)
                    let mut len = 0;
                    loop {
                        if t.contains_key(&(len + 1).to_string()) {
                            len += 1;
                        } else {
                            break;
                        }
                    }
                    Ok(LuaValue::Number(len as f64))
                }
                _ => Err("cannot get length of non-string/table".to_string()),
            },
        }
    }

    fn push_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    fn set_local(&mut self, name: String, value: LuaValue) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name, value);
        } else {
            self.globals.insert(name, value);
        }
    }

    fn set_variable(&mut self, name: String, value: LuaValue) {
        // Check local scopes first
        for scope in self.scopes.iter_mut().rev() {
            if scope.contains_key(&name) {
                scope.insert(name, value);
                return;
            }
        }

        // Set in globals
        self.globals.insert(name, value);
    }

    fn get_variable(&self, name: &str) -> LuaValue {
        // Check local scopes first
        for scope in self.scopes.iter().rev() {
            if let Some(value) = scope.get(name) {
                return value.clone();
            }
        }

        // Check globals
        self.globals.get(name).cloned().unwrap_or(LuaValue::Nil)
    }
}
