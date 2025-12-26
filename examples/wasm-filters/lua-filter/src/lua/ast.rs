//! Lua Abstract Syntax Tree

use crate::lua::value::LuaValue;

/// Expression types
#[derive(Debug, Clone)]
pub enum Expr {
    /// Literal value
    Literal(LuaValue),

    /// Variable reference
    Variable(String),

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
    Table(Vec<(Option<Expr>, Expr)>),
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
}

/// Unary operators
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnaryOperator {
    Neg,
    Not,
    Len,
}

/// Statement types
#[derive(Debug, Clone)]
pub enum Stmt {
    /// Assignment: x = expr or local x = expr
    Assign {
        targets: Vec<String>,
        values: Vec<Expr>,
        local: bool,
    },

    /// Table field assignment: table.field = expr
    TableAssign {
        table: Expr,
        key: Expr,
        value: Expr,
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

    /// Numeric for loop
    ForNumeric {
        var: String,
        start: Expr,
        end: Expr,
        step: Option<Expr>,
        body: Vec<Stmt>,
    },

    /// Function definition
    Function {
        name: String,
        params: Vec<String>,
        body: Vec<Stmt>,
    },

    /// Return statement
    Return(Vec<Expr>),

    /// Expression statement (function call)
    Expression(Expr),

    /// Break statement
    Break,
}

/// A complete Lua program
#[derive(Debug)]
pub struct Program {
    pub statements: Vec<Stmt>,
}
