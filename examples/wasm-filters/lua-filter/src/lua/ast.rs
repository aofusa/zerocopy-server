//! Lua Abstract Syntax Tree

/// Expression types
#[derive(Debug, Clone)]
pub enum Expr {
    /// Literal value - use LiteralValue to avoid circular dependency
    LiteralNil,
    LiteralBool(bool),
    LiteralNumber(f64),
    LiteralString(String),

    /// Variable reference
    Variable(String),

    /// Varargs (...)
    Vararg,

    /// Table field access: table.field or table["field"]
    Index(Box<Expr>, Box<Expr>),

    /// Binary operation
    BinaryOp {
        left: Box<Expr>,
        op: BinaryOperator,
        right: Box<Expr>,
    },

    /// Unary operation
    UnaryOp {
        op: UnaryOperator,
        operand: Box<Expr>,
    },

    /// Function call
    Call {
        func: Box<Expr>,
        args: Vec<Expr>,
    },

    /// Table constructor
    Table(Vec<TableEntry>),

    /// Anonymous function (closure)
    Function {
        params: Vec<String>,
        vararg: bool,
        body: Vec<Stmt>,
    },
}

/// Table constructor entry
#[derive(Debug, Clone)]
pub enum TableEntry {
    /// Array-style: value
    Array(Expr),
    /// Key-value: key = value or [key] = value
    KeyValue(Expr, Expr),
}

/// Binary operators
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BinaryOperator {
    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    IDiv, // //

    // Comparison
    Eq,
    NotEq,
    Lt,
    Gt,
    Le,
    Ge,

    // Logical
    And,
    Or,

    // String
    Concat,

    // Bitwise (Lua 5.3+)
    BAnd,
    BOr,
    BXor,
    Shl,
    Shr,
}

/// Unary operators
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnaryOperator {
    Neg,
    Not,
    Len,
    BNot, // Bitwise not ~
}

/// Statement types
#[derive(Debug, Clone)]
pub enum Stmt {
    /// Assignment: x = expr or local x = expr
    Assign {
        targets: Vec<AssignTarget>,
        values: Vec<Expr>,
        local: bool,
    },

    /// If statement
    If {
        condition: Expr,
        then_block: Vec<Stmt>,
        elseif_blocks: Vec<(Expr, Vec<Stmt>)>,
        else_block: Option<Vec<Stmt>>,
    },

    /// While loop
    While {
        condition: Expr,
        body: Vec<Stmt>,
    },

    /// Repeat-until loop
    Repeat {
        body: Vec<Stmt>,
        condition: Expr,
    },

    /// Numeric for loop
    ForNumeric {
        var: String,
        start: Expr,
        end: Expr,
        step: Option<Expr>,
        body: Vec<Stmt>,
    },

    /// Generic for loop
    ForGeneric {
        vars: Vec<String>,
        exprs: Vec<Expr>,
        body: Vec<Stmt>,
    },

    /// Function definition
    Function {
        name: FunctionName,
        params: Vec<String>,
        vararg: bool,
        body: Vec<Stmt>,
        local: bool,
    },

    /// Return statement
    Return(Vec<Expr>),

    /// Expression statement (function call)
    Expression(Expr),

    /// Break statement
    Break,

    /// Do block
    Do(Vec<Stmt>),

    /// Goto statement (Lua 5.2+)
    Goto(String),

    /// Label (::name::)
    Label(String),
}

/// Assignment target
#[derive(Debug, Clone)]
pub enum AssignTarget {
    /// Simple variable
    Name(String),
    /// Table index: table[key] or table.field
    Index(Expr, Expr),
}

/// Function name (can be dotted or method)
#[derive(Debug, Clone)]
pub struct FunctionName {
    pub base: String,
    pub fields: Vec<String>,
    pub method: Option<String>,
}

impl FunctionName {
    pub fn simple(name: String) -> Self {
        Self {
            base: name,
            fields: Vec::new(),
            method: None,
        }
    }

    pub fn full_name(&self) -> String {
        let mut name = self.base.clone();
        for field in &self.fields {
            name.push('.');
            name.push_str(field);
        }
        if let Some(method) = &self.method {
            name.push(':');
            name.push_str(method);
        }
        name
    }
}

/// A complete Lua program
#[derive(Debug)]
pub struct Program {
    pub statements: Vec<Stmt>,
}
