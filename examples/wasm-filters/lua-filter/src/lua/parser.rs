//! Lua Parser

use crate::lua::ast::*;
use crate::lua::lexer::Token;
use crate::lua::value::LuaValue;

/// Parse tokens into AST
pub fn parse(tokens: &[Token]) -> Result<Program, String> {
    let mut parser = Parser::new(tokens);
    parser.parse_program()
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        Self { tokens, pos: 0 }
    }

    fn current(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn peek(&self, offset: usize) -> &Token {
        self.tokens.get(self.pos + offset).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> Token {
        let token = self.current().clone();
        self.pos += 1;
        token
    }

    fn expect(&mut self, expected: Token) -> Result<(), String> {
        if self.current() == &expected {
            self.advance();
            Ok(())
        } else {
            Err(format!(
                "Expected {:?}, found {:?}",
                expected,
                self.current()
            ))
        }
    }

    fn parse_program(&mut self) -> Result<Program, String> {
        let mut statements = Vec::new();

        while self.current() != &Token::Eof {
            statements.push(self.parse_statement()?);
        }

        Ok(Program { statements })
    }

    fn parse_statement(&mut self) -> Result<Stmt, String> {
        match self.current() {
            Token::Local => self.parse_local(),
            Token::If => self.parse_if(),
            Token::While => self.parse_while(),
            Token::For => self.parse_for(),
            Token::Function => self.parse_function(),
            Token::Return => self.parse_return(),
            Token::Break => {
                self.advance();
                Ok(Stmt::Break)
            }
            Token::Identifier(_) => self.parse_assignment_or_call(),
            _ => Err(format!("Unexpected token: {:?}", self.current())),
        }
    }

    fn parse_local(&mut self) -> Result<Stmt, String> {
        self.expect(Token::Local)?;

        // Check for local function
        if self.current() == &Token::Function {
            self.advance();
            let name = self.parse_identifier()?;
            return self.parse_function_body(name, true);
        }

        // Variable declaration
        let mut targets = Vec::new();
        targets.push(self.parse_identifier()?);

        while self.current() == &Token::Comma {
            self.advance();
            targets.push(self.parse_identifier()?);
        }

        let mut values = Vec::new();
        if self.current() == &Token::Assign {
            self.advance();
            values.push(self.parse_expression()?);

            while self.current() == &Token::Comma {
                self.advance();
                values.push(self.parse_expression()?);
            }
        }

        Ok(Stmt::Assign {
            targets,
            values,
            local: true,
        })
    }

    fn parse_if(&mut self) -> Result<Stmt, String> {
        self.expect(Token::If)?;
        let condition = self.parse_expression()?;
        self.expect(Token::Then)?;

        let then_block = self.parse_block(&[Token::Elseif, Token::Else, Token::End])?;

        let mut elseif_blocks = Vec::new();
        while self.current() == &Token::Elseif {
            self.advance();
            let cond = self.parse_expression()?;
            self.expect(Token::Then)?;
            let block = self.parse_block(&[Token::Elseif, Token::Else, Token::End])?;
            elseif_blocks.push((cond, block));
        }

        let else_block = if self.current() == &Token::Else {
            self.advance();
            Some(self.parse_block(&[Token::End])?)
        } else {
            None
        };

        self.expect(Token::End)?;

        Ok(Stmt::If {
            condition,
            then_block,
            elseif_blocks,
            else_block,
        })
    }

    fn parse_while(&mut self) -> Result<Stmt, String> {
        self.expect(Token::While)?;
        let condition = self.parse_expression()?;
        self.expect(Token::Do)?;
        let body = self.parse_block(&[Token::End])?;
        self.expect(Token::End)?;

        Ok(Stmt::While { condition, body })
    }

    fn parse_for(&mut self) -> Result<Stmt, String> {
        self.expect(Token::For)?;
        let var = self.parse_identifier()?;

        if self.current() == &Token::Assign {
            // Numeric for
            self.advance();
            let start = self.parse_expression()?;
            self.expect(Token::Comma)?;
            let end = self.parse_expression()?;

            let step = if self.current() == &Token::Comma {
                self.advance();
                Some(self.parse_expression()?)
            } else {
                None
            };

            self.expect(Token::Do)?;
            let body = self.parse_block(&[Token::End])?;
            self.expect(Token::End)?;

            Ok(Stmt::ForNumeric {
                var,
                start,
                end,
                step,
                body,
            })
        } else {
            Err("Generic for not yet supported".to_string())
        }
    }

    fn parse_function(&mut self) -> Result<Stmt, String> {
        self.expect(Token::Function)?;
        let name = self.parse_identifier()?;
        self.parse_function_body(name, false)
    }

    fn parse_function_body(&mut self, name: String, _local: bool) -> Result<Stmt, String> {
        self.expect(Token::LParen)?;

        let mut params = Vec::new();
        if self.current() != &Token::RParen {
            params.push(self.parse_identifier()?);

            while self.current() == &Token::Comma {
                self.advance();
                params.push(self.parse_identifier()?);
            }
        }

        self.expect(Token::RParen)?;
        let body = self.parse_block(&[Token::End])?;
        self.expect(Token::End)?;

        Ok(Stmt::Function { name, params, body })
    }

    fn parse_return(&mut self) -> Result<Stmt, String> {
        self.expect(Token::Return)?;

        let mut values = Vec::new();

        // Check if there's a return value
        if !matches!(
            self.current(),
            Token::End | Token::Else | Token::Elseif | Token::Eof
        ) {
            values.push(self.parse_expression()?);

            while self.current() == &Token::Comma {
                self.advance();
                values.push(self.parse_expression()?);
            }
        }

        Ok(Stmt::Return(values))
    }

    fn parse_assignment_or_call(&mut self) -> Result<Stmt, String> {
        let expr = self.parse_primary_expression()?;

        // Check for assignment
        if self.current() == &Token::Assign {
            self.advance();
            let value = self.parse_expression()?;

            match expr {
                Expr::Variable(name) => Ok(Stmt::Assign {
                    targets: vec![name],
                    values: vec![value],
                    local: false,
                }),
                Expr::Index(table, key) => Ok(Stmt::TableAssign {
                    table: *table,
                    key: *key,
                    value,
                }),
                _ => Err("Invalid assignment target".to_string()),
            }
        } else {
            // Expression statement
            let full_expr = self.parse_expression_rest(expr)?;
            Ok(Stmt::Expression(full_expr))
        }
    }

    fn parse_block(&mut self, terminators: &[Token]) -> Result<Vec<Stmt>, String> {
        let mut statements = Vec::new();

        while !terminators.contains(self.current()) && self.current() != &Token::Eof {
            statements.push(self.parse_statement()?);
        }

        Ok(statements)
    }

    fn parse_identifier(&mut self) -> Result<String, String> {
        match self.current().clone() {
            Token::Identifier(name) => {
                self.advance();
                Ok(name)
            }
            _ => Err(format!("Expected identifier, found {:?}", self.current())),
        }
    }

    fn parse_expression(&mut self) -> Result<Expr, String> {
        self.parse_or_expression()
    }

    fn parse_or_expression(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_and_expression()?;

        while self.current() == &Token::Or {
            self.advance();
            let right = self.parse_and_expression()?;
            left = Expr::BinaryOp {
                left: Box::new(left),
                op: BinaryOperator::Or,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    fn parse_and_expression(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_comparison_expression()?;

        while self.current() == &Token::And {
            self.advance();
            let right = self.parse_comparison_expression()?;
            left = Expr::BinaryOp {
                left: Box::new(left),
                op: BinaryOperator::And,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    fn parse_comparison_expression(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_concat_expression()?;

        loop {
            let op = match self.current() {
                Token::Eq => BinaryOperator::Eq,
                Token::NotEq => BinaryOperator::NotEq,
                Token::Lt => BinaryOperator::Lt,
                Token::Gt => BinaryOperator::Gt,
                Token::Le => BinaryOperator::Le,
                Token::Ge => BinaryOperator::Ge,
                _ => break,
            };
            self.advance();
            let right = self.parse_concat_expression()?;
            left = Expr::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    fn parse_concat_expression(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_additive_expression()?;

        while self.current() == &Token::Concat {
            self.advance();
            let right = self.parse_additive_expression()?;
            left = Expr::BinaryOp {
                left: Box::new(left),
                op: BinaryOperator::Concat,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    fn parse_additive_expression(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_multiplicative_expression()?;

        loop {
            let op = match self.current() {
                Token::Plus => BinaryOperator::Add,
                Token::Minus => BinaryOperator::Sub,
                _ => break,
            };
            self.advance();
            let right = self.parse_multiplicative_expression()?;
            left = Expr::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    fn parse_multiplicative_expression(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_unary_expression()?;

        loop {
            let op = match self.current() {
                Token::Star => BinaryOperator::Mul,
                Token::Slash => BinaryOperator::Div,
                Token::Percent => BinaryOperator::Mod,
                _ => break,
            };
            self.advance();
            let right = self.parse_unary_expression()?;
            left = Expr::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    fn parse_unary_expression(&mut self) -> Result<Expr, String> {
        match self.current() {
            Token::Minus => {
                self.advance();
                let operand = self.parse_unary_expression()?;
                Ok(Expr::UnaryOp {
                    op: UnaryOperator::Neg,
                    operand: Box::new(operand),
                })
            }
            Token::Not => {
                self.advance();
                let operand = self.parse_unary_expression()?;
                Ok(Expr::UnaryOp {
                    op: UnaryOperator::Not,
                    operand: Box::new(operand),
                })
            }
            Token::Hash => {
                self.advance();
                let operand = self.parse_unary_expression()?;
                Ok(Expr::UnaryOp {
                    op: UnaryOperator::Len,
                    operand: Box::new(operand),
                })
            }
            _ => self.parse_power_expression(),
        }
    }

    fn parse_power_expression(&mut self) -> Result<Expr, String> {
        let left = self.parse_primary_expression()?;

        if self.current() == &Token::Caret {
            self.advance();
            let right = self.parse_unary_expression()?;
            Ok(Expr::BinaryOp {
                left: Box::new(left),
                op: BinaryOperator::Pow,
                right: Box::new(right),
            })
        } else {
            self.parse_expression_rest(left)
        }
    }

    fn parse_primary_expression(&mut self) -> Result<Expr, String> {
        match self.current().clone() {
            Token::Nil => {
                self.advance();
                Ok(Expr::Literal(LuaValue::Nil))
            }
            Token::True => {
                self.advance();
                Ok(Expr::Literal(LuaValue::Boolean(true)))
            }
            Token::False => {
                self.advance();
                Ok(Expr::Literal(LuaValue::Boolean(false)))
            }
            Token::Number(n) => {
                self.advance();
                Ok(Expr::Literal(LuaValue::Number(n)))
            }
            Token::String(s) => {
                self.advance();
                Ok(Expr::Literal(LuaValue::String(s)))
            }
            Token::Identifier(name) => {
                self.advance();
                Ok(Expr::Variable(name))
            }
            Token::LParen => {
                self.advance();
                let expr = self.parse_expression()?;
                self.expect(Token::RParen)?;
                Ok(expr)
            }
            Token::LBrace => self.parse_table_constructor(),
            _ => Err(format!("Unexpected token: {:?}", self.current())),
        }
    }

    fn parse_expression_rest(&mut self, mut expr: Expr) -> Result<Expr, String> {
        loop {
            match self.current() {
                Token::Dot => {
                    self.advance();
                    let field = self.parse_identifier()?;
                    expr = Expr::Index(
                        Box::new(expr),
                        Box::new(Expr::Literal(LuaValue::String(field))),
                    );
                }
                Token::LBracket => {
                    self.advance();
                    let index = self.parse_expression()?;
                    self.expect(Token::RBracket)?;
                    expr = Expr::Index(Box::new(expr), Box::new(index));
                }
                Token::LParen => {
                    self.advance();
                    let mut args = Vec::new();

                    if self.current() != &Token::RParen {
                        args.push(self.parse_expression()?);

                        while self.current() == &Token::Comma {
                            self.advance();
                            args.push(self.parse_expression()?);
                        }
                    }

                    self.expect(Token::RParen)?;
                    expr = Expr::Call {
                        func: Box::new(expr),
                        args,
                    };
                }
                Token::Colon => {
                    // Method call: obj:method(args)
                    self.advance();
                    let method = self.parse_identifier()?;
                    self.expect(Token::LParen)?;

                    let mut args = vec![expr.clone()]; // self as first arg

                    if self.current() != &Token::RParen {
                        args.push(self.parse_expression()?);

                        while self.current() == &Token::Comma {
                            self.advance();
                            args.push(self.parse_expression()?);
                        }
                    }

                    self.expect(Token::RParen)?;

                    let func = Expr::Index(
                        Box::new(expr),
                        Box::new(Expr::Literal(LuaValue::String(method))),
                    );

                    expr = Expr::Call {
                        func: Box::new(func),
                        args,
                    };
                }
                _ => break,
            }
        }

        Ok(expr)
    }

    fn parse_table_constructor(&mut self) -> Result<Expr, String> {
        self.expect(Token::LBrace)?;

        let mut entries = Vec::new();

        while self.current() != &Token::RBrace {
            // [key] = value
            if self.current() == &Token::LBracket {
                self.advance();
                let key = self.parse_expression()?;
                self.expect(Token::RBracket)?;
                self.expect(Token::Assign)?;
                let value = self.parse_expression()?;
                entries.push((Some(key), value));
            }
            // key = value
            else if let Token::Identifier(name) = self.current().clone() {
                if self.peek(1) == &Token::Assign {
                    self.advance();
                    self.advance();
                    let value = self.parse_expression()?;
                    entries.push((Some(Expr::Literal(LuaValue::String(name))), value));
                } else {
                    // array element
                    let value = self.parse_expression()?;
                    entries.push((None, value));
                }
            } else {
                // array element
                let value = self.parse_expression()?;
                entries.push((None, value));
            }

            // Optional separator
            if self.current() == &Token::Comma || self.current() == &Token::Semicolon {
                self.advance();
            } else {
                break;
            }
        }

        self.expect(Token::RBrace)?;

        Ok(Expr::Table(entries))
    }
}
