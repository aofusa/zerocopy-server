//! Lua Lexer (Tokenizer)

use std::iter::Peekable;
use std::str::Chars;

/// Token types
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Literals
    Nil,
    True,
    False,
    Number(f64),
    String(String),
    Identifier(String),

    // Keywords
    And,
    Break,
    Do,
    Else,
    Elseif,
    End,
    For,
    Function,
    Goto,
    If,
    In,
    Local,
    Not,
    Or,
    Repeat,
    Return,
    Then,
    Until,
    While,

    // Operators
    Plus,
    Minus,
    Star,
    Slash,
    DoubleSlash, // //
    Percent,
    Caret,
    Hash,
    Ampersand,   // &
    Pipe,        // |
    Tilde,       // ~
    Shl,         // <<
    Shr,         // >>
    Eq,
    NotEq,
    Lt,
    Gt,
    Le,
    Ge,
    Assign,
    Concat,
    Vararg,      // ...
    Dot,
    DoubleColon, // ::
    Colon,
    Comma,
    Semicolon,

    // Brackets
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,

    // End of file
    Eof,
}

/// Tokenize Lua source code
pub fn tokenize(source: &str) -> Result<Vec<Token>, String> {
    let mut lexer = Lexer::new(source);
    let mut tokens = Vec::new();

    loop {
        let token = lexer.next_token()?;
        let is_eof = token == Token::Eof;
        tokens.push(token);
        if is_eof {
            break;
        }
    }

    Ok(tokens)
}

struct Lexer<'a> {
    chars: Peekable<Chars<'a>>,
    line: usize,
    column: usize,
}

impl<'a> Lexer<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            chars: source.chars().peekable(),
            line: 1,
            column: 1,
        }
    }

    fn next_char(&mut self) -> Option<char> {
        let c = self.chars.next();
        if let Some(ch) = c {
            if ch == '\n' {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
        }
        c
    }

    fn peek_char(&mut self) -> Option<&char> {
        self.chars.peek()
    }

    fn skip_whitespace(&mut self) {
        while let Some(&c) = self.peek_char() {
            if c.is_whitespace() {
                self.next_char();
            } else if c == '-' {
                // Check for comment
                let mut chars_clone = self.chars.clone();
                chars_clone.next(); // consume '-'
                if chars_clone.peek() == Some(&'-') {
                    // Single-line comment
                    self.next_char(); // '-'
                    self.next_char(); // '-'
                    while let Some(&c) = self.peek_char() {
                        if c == '\n' {
                            break;
                        }
                        self.next_char();
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    fn read_number(&mut self, first: char) -> Result<Token, String> {
        let mut s = String::from(first);

        while let Some(&c) = self.peek_char() {
            if c.is_ascii_digit() || c == '.' || c == 'e' || c == 'E' {
                s.push(self.next_char().unwrap());
                // Handle exponent sign
                if (c == 'e' || c == 'E') && self.peek_char() == Some(&'-') {
                    s.push(self.next_char().unwrap());
                }
            } else {
                break;
            }
        }

        s.parse::<f64>()
            .map(Token::Number)
            .map_err(|_| format!("Invalid number: {}", s))
    }

    fn read_string(&mut self, quote: char) -> Result<Token, String> {
        let mut s = String::new();

        loop {
            match self.next_char() {
                Some(c) if c == quote => break,
                Some('\\') => {
                    // Escape sequence
                    match self.next_char() {
                        Some('n') => s.push('\n'),
                        Some('t') => s.push('\t'),
                        Some('r') => s.push('\r'),
                        Some('\\') => s.push('\\'),
                        Some('"') => s.push('"'),
                        Some('\'') => s.push('\''),
                        Some(c) => s.push(c),
                        None => return Err("Unterminated string".to_string()),
                    }
                }
                Some(c) => s.push(c),
                None => return Err("Unterminated string".to_string()),
            }
        }

        Ok(Token::String(s))
    }

    fn read_identifier(&mut self, first: char) -> Token {
        let mut s = String::from(first);

        while let Some(&c) = self.peek_char() {
            if c.is_alphanumeric() || c == '_' {
                s.push(self.next_char().unwrap());
            } else {
                break;
            }
        }

        // Check for keywords
        match s.as_str() {
            "and" => Token::And,
            "break" => Token::Break,
            "do" => Token::Do,
            "else" => Token::Else,
            "elseif" => Token::Elseif,
            "end" => Token::End,
            "false" => Token::False,
            "for" => Token::For,
            "function" => Token::Function,
            "goto" => Token::Goto,
            "if" => Token::If,
            "in" => Token::In,
            "local" => Token::Local,
            "nil" => Token::Nil,
            "not" => Token::Not,
            "or" => Token::Or,
            "repeat" => Token::Repeat,
            "return" => Token::Return,
            "then" => Token::Then,
            "true" => Token::True,
            "until" => Token::Until,
            "while" => Token::While,
            _ => Token::Identifier(s),
        }
    }

    fn next_token(&mut self) -> Result<Token, String> {
        self.skip_whitespace();

        let c = match self.next_char() {
            Some(c) => c,
            None => return Ok(Token::Eof),
        };

        match c {
            // Numbers
            '0'..='9' => self.read_number(c),

            // Strings
            '"' | '\'' => self.read_string(c),

            // Identifiers and keywords
            'a'..='z' | 'A'..='Z' | '_' => Ok(self.read_identifier(c)),

            // Operators and punctuation
            '+' => Ok(Token::Plus),
            '-' => Ok(Token::Minus),
            '*' => Ok(Token::Star),
            '%' => Ok(Token::Percent),
            '^' => Ok(Token::Caret),
            '#' => Ok(Token::Hash),
            '(' => Ok(Token::LParen),
            ')' => Ok(Token::RParen),
            '[' => Ok(Token::LBracket),
            ']' => Ok(Token::RBracket),
            '{' => Ok(Token::LBrace),
            '}' => Ok(Token::RBrace),
            ',' => Ok(Token::Comma),
            ';' => Ok(Token::Semicolon),

            '.' => {
                if self.peek_char() == Some(&'.') {
                    self.next_char();
                    if self.peek_char() == Some(&'.') {
                        self.next_char();
                        Ok(Token::Vararg)
                    } else {
                        Ok(Token::Concat)
                    }
                } else if self.peek_char().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                    // .5 style number
                    self.read_number(c)
                } else {
                    Ok(Token::Dot)
                }
            }

            '/' => {
                if self.peek_char() == Some(&'/') {
                    self.next_char();
                    Ok(Token::DoubleSlash)
                } else {
                    Ok(Token::Slash)
                }
            }

            ':' => {
                if self.peek_char() == Some(&':') {
                    self.next_char();
                    Ok(Token::DoubleColon)
                } else {
                    Ok(Token::Colon)
                }
            }

            '&' => Ok(Token::Ampersand),
            '|' => Ok(Token::Pipe),

            '=' => {
                if self.peek_char() == Some(&'=') {
                    self.next_char();
                    Ok(Token::Eq)
                } else {
                    Ok(Token::Assign)
                }
            }

            '~' => {
                if self.peek_char() == Some(&'=') {
                    self.next_char();
                    Ok(Token::NotEq)
                } else {
                    Ok(Token::Tilde)
                }
            }

            '<' => {
                if self.peek_char() == Some(&'=') {
                    self.next_char();
                    Ok(Token::Le)
                } else if self.peek_char() == Some(&'<') {
                    self.next_char();
                    Ok(Token::Shl)
                } else {
                    Ok(Token::Lt)
                }
            }

            '>' => {
                if self.peek_char() == Some(&'=') {
                    self.next_char();
                    Ok(Token::Ge)
                } else if self.peek_char() == Some(&'>') {
                    self.next_char();
                    Ok(Token::Shr)
                } else {
                    Ok(Token::Gt)
                }
            }

            _ => Err(format!("Unexpected character: {} at line {}", c, self.line)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize_basics() {
        let tokens = tokenize("local x = 42").unwrap();
        assert_eq!(tokens[0], Token::Local);
        assert_eq!(tokens[1], Token::Identifier("x".to_string()));
        assert_eq!(tokens[2], Token::Assign);
        assert_eq!(tokens[3], Token::Number(42.0));
    }

    #[test]
    fn test_tokenize_string() {
        let tokens = tokenize(r#""hello world""#).unwrap();
        assert_eq!(tokens[0], Token::String("hello world".to_string()));
    }

    #[test]
    fn test_tokenize_operators() {
        let tokens = tokenize("a + b - c * d / e").unwrap();
        assert_eq!(tokens[1], Token::Plus);
        assert_eq!(tokens[3], Token::Minus);
        assert_eq!(tokens[5], Token::Star);
        assert_eq!(tokens[7], Token::Slash);
    }
}
