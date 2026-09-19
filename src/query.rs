use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    MatchAll,
    Term {
        field: Option<String>,
        value: String,
        prefix: bool,
    },
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    Quoted(String),
    Colon,
    LParen,
    RParen,
    And,
    Or,
    Not,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryError {
    pub message: String,
    pub offset: usize,
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.message, self.offset)
    }
}

impl std::error::Error for QueryError {}

pub fn parse(input: &str) -> Result<Expr, QueryError> {
    if input.trim().is_empty() || input.trim() == "*" {
        return Ok(Expr::MatchAll);
    }
    let tokens = lex(input)?;
    let mut parser = Parser { tokens, cursor: 0 };
    let expr = parser.parse_or()?;
    if parser.cursor != parser.tokens.len() {
        return Err(QueryError {
            message: "unexpected token".into(),
            offset: parser.cursor,
        });
    }
    Ok(expr)
}

fn lex(input: &str) -> Result<Vec<Token>, QueryError> {
    let chars: Vec<char> = input.chars().collect();
    let mut out = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        match chars[index] {
            c if c.is_whitespace() => index += 1,
            ':' => {
                out.push(Token::Colon);
                index += 1;
            }
            '(' => {
                out.push(Token::LParen);
                index += 1;
            }
            ')' => {
                out.push(Token::RParen);
                index += 1;
            }
            '"' => {
                let start = index;
                index += 1;
                let mut value = String::new();
                let mut closed = false;
                while index < chars.len() {
                    if chars[index] == '"' {
                        closed = true;
                        index += 1;
                        break;
                    }
                    if chars[index] == '\\' && index + 1 < chars.len() {
                        index += 1;
                    }
                    value.push(chars[index]);
                    index += 1;
                }
                if !closed {
                    return Err(QueryError {
                        message: "unterminated quoted string".into(),
                        offset: start,
                    });
                }
                out.push(Token::Quoted(value));
            }
            _ => {
                let start = index;
                while index < chars.len()
                    && !chars[index].is_whitespace()
                    && !matches!(chars[index], ':' | '(' | ')')
                {
                    index += 1;
                }
                let value: String = chars[start..index].iter().collect();
                out.push(match value.to_ascii_uppercase().as_str() {
                    "AND" => Token::And,
                    "OR" => Token::Or,
                    "NOT" => Token::Not,
                    _ => Token::Word(value),
                });
            }
        }
    }
    Ok(out)
}

struct Parser {
    tokens: Vec<Token>,
    cursor: usize,
}

impl Parser {
    fn parse_or(&mut self) -> Result<Expr, QueryError> {
        let mut expr = self.parse_and()?;
        while self.take(&Token::Or) {
            expr = Expr::Or(Box::new(expr), Box::new(self.parse_and()?));
        }
        Ok(expr)
    }

    fn parse_and(&mut self) -> Result<Expr, QueryError> {
        let mut expr = self.parse_unary()?;
        while self.take(&Token::And) {
            expr = Expr::And(Box::new(expr), Box::new(self.parse_unary()?));
        }
        Ok(expr)
    }

    fn parse_unary(&mut self) -> Result<Expr, QueryError> {
        if self.take(&Token::Not) {
            return Ok(Expr::Not(Box::new(self.parse_unary()?)));
        }
        if self.take(&Token::LParen) {
            let nested = self.parse_or()?;
            if !self.take(&Token::RParen) {
                return Err(self.error("expected ')'"));
            }
            return Ok(nested);
        }
        self.parse_term()
    }

    fn parse_term(&mut self) -> Result<Expr, QueryError> {
        let first = self.value()?;
        let (field, mut value) = if self.take(&Token::Colon) {
            (Some(first), self.value()?)
        } else {
            (None, first)
        };
        let prefix = value.ends_with('*') && value.len() > 1;
        if prefix {
            value.pop();
        }
        Ok(Expr::Term {
            field,
            value: value.to_lowercase(),
            prefix,
        })
    }

    fn value(&mut self) -> Result<String, QueryError> {
        let token = self.tokens.get(self.cursor).cloned();
        match token {
            Some(Token::Word(value)) | Some(Token::Quoted(value)) => {
                self.cursor += 1;
                Ok(value)
            }
            _ => Err(self.error("expected search term")),
        }
    }

    fn take(&mut self, expected: &Token) -> bool {
        if self.tokens.get(self.cursor) == Some(expected) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn error(&self, message: &str) -> QueryError {
        QueryError {
            message: message.into(),
            offset: self.cursor,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_boolean_field_query() {
        let parsed = parse("event.id:4625 OR process.name:\"powershell.exe\"").unwrap();
        assert!(matches!(parsed, Expr::Or(_, _)));
    }

    #[test]
    fn not_binds_tighter_than_and_and_or() {
        let parsed = parse("alpha OR beta AND NOT gamma").unwrap();
        assert!(matches!(parsed, Expr::Or(_, right) if matches!(*right, Expr::And(_, _))));
    }

    #[test]
    fn rejects_unclosed_quotes() {
        assert!(parse("message:\"broken").is_err());
    }
}
