use std::fmt;

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct QueryLimits {
    pub max_bytes: usize,
    pub max_tokens: usize,
    pub max_depth: usize,
    pub max_nodes: usize,
}

impl Default for QueryLimits {
    fn default() -> Self {
        Self {
            max_bytes: 8192,
            max_tokens: 256,
            max_depth: 16,
            max_nodes: 64,
        }
    }
}

impl QueryLimits {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|name| match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} must be UTF-8")),
        })
    }

    fn from_lookup(
        mut lookup: impl FnMut(&str) -> Result<Option<String>, String>,
    ) -> Result<Self, String> {
        let mut limits = Self::default();
        for (name, value) in [
            ("REDTRACE_QUERY_MAX_BYTES", &mut limits.max_bytes),
            ("REDTRACE_QUERY_MAX_TOKENS", &mut limits.max_tokens),
            ("REDTRACE_QUERY_MAX_DEPTH", &mut limits.max_depth),
            ("REDTRACE_QUERY_MAX_NODES", &mut limits.max_nodes),
        ] {
            if let Some(raw) = lookup(name)? {
                *value = raw
                    .parse::<usize>()
                    .ok()
                    .filter(|parsed| (1..=*value).contains(parsed))
                    .ok_or_else(|| format!("{name} must be an integer between 1 and {value}"))?;
            }
        }
        Ok(limits)
    }

    fn validate(self) -> Result<(), QueryError> {
        let ceiling = Self::default();
        if self.max_bytes == 0
            || self.max_bytes > ceiling.max_bytes
            || self.max_tokens == 0
            || self.max_tokens > ceiling.max_tokens
            || self.max_depth == 0
            || self.max_depth > ceiling.max_depth
            || self.max_nodes == 0
            || self.max_nodes > ceiling.max_nodes
        {
            return Err(QueryError {
                message: "invalid query limits".into(),
                offset: 0,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    MatchAll,
    Value {
        field: Option<String>,
        value: String,
        exact: bool,
    },
    Exists(String),
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
    Equals,
    Contains,
    LParen,
    RParen,
    And,
    Or,
    Not,
}

struct SpannedToken {
    token: Token,
    offset: usize,
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
    parse_with_limits(input, QueryLimits::default())
}

pub fn parse_with_limits(input: &str, limits: QueryLimits) -> Result<Expr, QueryError> {
    limits.validate()?;
    if input.len() > limits.max_bytes {
        return Err(QueryError {
            message: "query exceeds byte limit".into(),
            offset: input
                .char_indices()
                .map(|(offset, _)| offset)
                .find(|offset| *offset >= limits.max_bytes)
                .unwrap_or(input.len()),
        });
    }
    if input.trim().is_empty() || input.trim() == "*" {
        return Ok(Expr::MatchAll);
    }
    let tokens = lex(input, limits.max_tokens)?;
    let mut parser = Parser {
        tokens,
        cursor: 0,
        input_bytes: input.len(),
        limits,
        nodes: 0,
    };
    let expr = parser.parse_or(0)?;
    if parser.cursor != parser.tokens.len() {
        return Err(parser.error("unexpected token"));
    }
    Ok(expr)
}

pub fn complexity(expression: &Expr) -> usize {
    match expression {
        Expr::MatchAll | Expr::Term { .. } | Expr::Value { .. } | Expr::Exists(_) => 1,
        Expr::Not(inner) => 1 + complexity(inner),
        Expr::And(left, right) | Expr::Or(left, right) => 1 + complexity(left) + complexity(right),
    }
}

fn lex(input: &str, max_tokens: usize) -> Result<Vec<SpannedToken>, QueryError> {
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let mut out = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let (offset, character) = chars[index];
        if character.is_whitespace() {
            index += 1;
            continue;
        }
        if out.len() == max_tokens {
            return Err(QueryError {
                message: "query exceeds token limit".into(),
                offset,
            });
        }
        let token = match character {
            ':' => {
                index += 1;
                Token::Colon
            }
            '=' => {
                index += 1;
                Token::Equals
            }
            '~' => {
                index += 1;
                Token::Contains
            }
            '(' => {
                index += 1;
                Token::LParen
            }
            ')' => {
                index += 1;
                Token::RParen
            }
            '"' => {
                index += 1;
                let mut value = String::new();
                let mut closed = false;
                while index < chars.len() {
                    if chars[index].1 == '"' {
                        closed = true;
                        index += 1;
                        break;
                    }
                    if chars[index].1 == '\\' && index + 1 < chars.len() {
                        index += 1;
                    }
                    value.push(chars[index].1);
                    index += 1;
                }
                if !closed {
                    return Err(QueryError {
                        message: "unterminated quoted string".into(),
                        offset,
                    });
                }
                Token::Quoted(value)
            }
            _ => {
                let start = index;
                while index < chars.len()
                    && !chars[index].1.is_whitespace()
                    && !matches!(chars[index].1, ':' | '=' | '~' | '(' | ')')
                {
                    index += 1;
                }
                let value: String = chars[start..index].iter().map(|(_, c)| c).collect();
                match value.to_ascii_uppercase().as_str() {
                    "AND" => Token::And,
                    "OR" => Token::Or,
                    "NOT" => Token::Not,
                    _ => Token::Word(value),
                }
            }
        };
        out.push(SpannedToken { token, offset });
    }
    Ok(out)
}

struct Parser {
    tokens: Vec<SpannedToken>,
    cursor: usize,
    input_bytes: usize,
    limits: QueryLimits,
    nodes: usize,
}

impl Parser {
    fn parse_or(&mut self, depth: usize) -> Result<Expr, QueryError> {
        let mut expr = self.parse_and(depth)?;
        while self.peek() == Some(&Token::Or) {
            self.reserve_node()?;
            self.cursor += 1;
            expr = Expr::Or(Box::new(expr), Box::new(self.parse_and(depth)?));
        }
        Ok(expr)
    }

    fn parse_and(&mut self, depth: usize) -> Result<Expr, QueryError> {
        let mut expr = self.parse_unary(depth)?;
        while self.peek() == Some(&Token::And) {
            self.reserve_node()?;
            self.cursor += 1;
            expr = Expr::And(Box::new(expr), Box::new(self.parse_unary(depth)?));
        }
        Ok(expr)
    }

    fn parse_unary(&mut self, depth: usize) -> Result<Expr, QueryError> {
        if self.peek() == Some(&Token::Not) {
            self.check_depth(depth)?;
            self.reserve_node()?;
            self.cursor += 1;
            return Ok(Expr::Not(Box::new(self.parse_unary(depth + 1)?)));
        }
        if self.peek() == Some(&Token::LParen) {
            self.check_depth(depth)?;
            self.cursor += 1;
            let nested = self.parse_or(depth + 1)?;
            if !self.take(&Token::RParen) {
                return Err(self.error("expected ')'"));
            }
            return Ok(nested);
        }
        self.parse_term()
    }

    fn parse_term(&mut self) -> Result<Expr, QueryError> {
        self.reserve_node()?;
        let mut quoted = matches!(self.peek(), Some(Token::Quoted(_)));
        let first = self.value()?;
        let exact = self.take(&Token::Equals);
        if exact || self.take(&Token::Contains) {
            let value = self.value()?;
            return Ok(Expr::Value {
                field: (first != "*").then(|| first.to_lowercase()),
                value: value.to_lowercase(),
                exact,
            });
        }
        let (field, mut value) = if self.take(&Token::Colon) {
            quoted = matches!(self.peek(), Some(Token::Quoted(_)));
            (Some(first.to_lowercase()), self.value()?)
        } else {
            (None, first)
        };
        if let Some(field) = &field
            && value == "*"
            && !quoted
        {
            return Ok(Expr::Exists(field.clone()));
        }
        let prefix = !quoted && value.ends_with('*') && value.len() > 1;
        if prefix {
            value.pop();
        }
        if field.is_none() && !prefix {
            return Ok(Expr::Value {
                field,
                value: value.to_lowercase(),
                exact: false,
            });
        }
        Ok(Expr::Term {
            field,
            value: value.to_lowercase(),
            prefix,
        })
    }

    fn value(&mut self) -> Result<String, QueryError> {
        let token = self.peek().cloned();
        match token {
            Some(Token::Word(value)) | Some(Token::Quoted(value)) => {
                self.cursor += 1;
                Ok(value)
            }
            _ => Err(self.error("expected search term")),
        }
    }

    fn take(&mut self, expected: &Token) -> bool {
        if self.peek() == Some(expected) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn error(&self, message: &str) -> QueryError {
        QueryError {
            message: message.into(),
            offset: self
                .tokens
                .get(self.cursor)
                .map(|token| token.offset)
                .unwrap_or(self.input_bytes),
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.cursor).map(|token| &token.token)
    }

    fn reserve_node(&mut self) -> Result<(), QueryError> {
        if self.nodes == self.limits.max_nodes {
            return Err(self.error("query is too complex"));
        }
        self.nodes += 1;
        Ok(())
    }

    fn check_depth(&self, depth: usize) -> Result<(), QueryError> {
        if depth == self.limits.max_depth {
            return Err(self.error("query exceeds nesting limit"));
        }
        Ok(())
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

    #[test]
    fn reports_query_ast_complexity() {
        assert_eq!(complexity(&parse("a AND (b OR NOT c)").unwrap()), 6);
    }

    #[test]
    fn bounds_utf8_bytes_before_lexing_and_match_all() {
        let limits = QueryLimits::default();
        for input in [
            "x".repeat(limits.max_bytes),
            "я".repeat(limits.max_bytes / 2),
        ] {
            assert!(parse(&input).is_ok());
            let oversized = format!("{input}я");
            let error = parse(&oversized).unwrap_err();
            assert_eq!(error.message, "query exceeds byte limit");
            assert_eq!(error.offset, limits.max_bytes);
            assert!(oversized.is_char_boundary(error.offset));
        }
        assert!(parse(&" ".repeat(limits.max_bytes)).is_ok());
        assert_eq!(
            parse(&" ".repeat(limits.max_bytes + 1))
                .unwrap_err()
                .message,
            "query exceeds byte limit"
        );
        let input = "я".repeat(4);
        let error = parse_with_limits(
            &input,
            QueryLimits {
                max_bytes: 5,
                ..limits
            },
        )
        .unwrap_err();
        assert_eq!(error.offset, 6);
        assert!(input.is_char_boundary(error.offset));
    }

    #[test]
    fn token_budget_counts_operators_and_stops_before_next_token() {
        let limits = QueryLimits {
            max_tokens: 3,
            ..QueryLimits::default()
        };
        assert!(parse_with_limits("поле=\"значение\"", limits).is_ok());
        let input = "поле=\"значение\" OR другое";
        let error = parse_with_limits(input, limits).unwrap_err();
        assert_eq!(error.message, "query exceeds token limit");
        assert_eq!(error.offset, input.find("OR").unwrap());
        let limits = QueryLimits::default();
        let input = "(".repeat(limits.max_tokens + 1);
        let error = parse(&input).unwrap_err();
        assert_eq!(error.message, "query exceeds token limit");
        assert_eq!(error.offset, limits.max_tokens);
    }

    #[test]
    fn bounds_parentheses_not_and_combined_nesting() {
        let limits = QueryLimits::default();
        for depth in [limits.max_depth, limits.max_depth + 1] {
            for input in [
                format!("{}x{}", "(".repeat(depth), ")".repeat(depth)),
                format!("{}x", "NOT ".repeat(depth)),
                format!(
                    "{}{}x{}",
                    "(".repeat(depth / 2),
                    "NOT ".repeat(depth - depth / 2),
                    ")".repeat(depth / 2)
                ),
            ] {
                if depth == limits.max_depth {
                    assert!(parse(&input).is_ok(), "{input}");
                } else {
                    let error = parse(&input).unwrap_err();
                    assert_eq!(error.message, "query exceeds nesting limit", "{input}");
                    assert!(input.is_char_boundary(error.offset));
                }
            }
        }
        let error = parse(&format!("{}x", "(".repeat(100))).unwrap_err();
        assert_eq!(error.message, "query exceeds nesting limit");
        assert_eq!(error.offset, limits.max_depth);
    }

    #[test]
    fn reserves_all_ast_nodes_before_building_expression() {
        let limit = QueryLimits::default().max_nodes;
        for operator in [" AND ", " OR "] {
            let input = vec!["x"; limit / 2].join(operator);
            let boundary = format!("NOT x{operator}{}", vec!["x"; limit / 2 - 1].join(operator));
            assert_eq!(complexity(&parse(&input).unwrap()), limit - 1);
            assert_eq!(complexity(&parse(&boundary).unwrap()), limit);
            let error = parse(&format!("{input}{operator}x")).unwrap_err();
            assert_eq!(error.message, "query is too complex");
            let error = parse(&format!("{boundary}{operator}x")).unwrap_err();
            assert_eq!(error.message, "query is too complex");
            assert_eq!(error.offset, boundary.len() + 1);
        }
        let limits = QueryLimits {
            max_nodes: 1,
            ..QueryLimits::default()
        };
        for input in [
            "*", "", "x", "field:*", "field:x", "field=x", "field~x", "(x)",
        ] {
            assert!(parse_with_limits(input, limits).is_ok(), "{input}");
        }
        for input in ["NOT x", "x AND y", "x OR y"] {
            assert_eq!(
                parse_with_limits(input, limits).unwrap_err().message,
                "query is too complex"
            );
        }
    }

    #[test]
    fn reports_actual_utf8_byte_offsets_for_syntax_errors() {
        for (input, expected) in [
            ("я AND )", 7),
            ("я OR", 5),
            ("(я", 3),
            ("я другое", 3),
            ("поле:\"broken", 9),
        ] {
            let error = parse(input).unwrap_err();
            assert_eq!(error.offset, expected, "{input}");
            assert!(input.is_char_boundary(error.offset));
        }
    }

    #[test]
    fn preserves_filter_semantics_and_escaped_literals() {
        assert_eq!(
            parse("source:windows.*").unwrap(),
            Expr::Term {
                field: Some("source".into()),
                value: "windows.".into(),
                prefix: true,
            }
        );
        assert_eq!(parse("field:*").unwrap(), Expr::Exists("field".into()));
        assert_eq!(
            parse("field:\"*\"").unwrap(),
            Expr::Term {
                field: Some("field".into()),
                value: "*".into(),
                prefix: false,
            }
        );
        assert_eq!(
            parse("*=\"Foo\"").unwrap(),
            Expr::Value {
                field: None,
                value: "foo".into(),
                exact: true,
            }
        );
        assert_eq!(
            parse(r#"field~"Я\"\\() NOT""#).unwrap(),
            Expr::Value {
                field: Some("field".into()),
                value: "я\"\\() not".into(),
                exact: false,
            }
        );
    }

    #[test]
    fn configuration_can_only_tighten_safety_ceilings() {
        let limits = QueryLimits::from_lookup(|_| Ok(Some("1".into()))).unwrap();
        assert_eq!(limits.max_bytes, 1);
        assert_eq!(limits.max_tokens, 1);
        assert_eq!(limits.max_depth, 1);
        assert_eq!(limits.max_nodes, 1);
        for (name, ceiling) in [
            ("REDTRACE_QUERY_MAX_BYTES", 8192),
            ("REDTRACE_QUERY_MAX_TOKENS", 256),
            ("REDTRACE_QUERY_MAX_DEPTH", 16),
            ("REDTRACE_QUERY_MAX_NODES", 64),
        ] {
            for value in ["0".into(), "invalid".into(), (ceiling + 1).to_string()] {
                let result =
                    QueryLimits::from_lookup(|key| Ok((key == name).then(|| value.clone())));
                assert!(result.unwrap_err().contains(name));
            }
        }
        assert!(QueryLimits::from_lookup(|_| Err("invalid encoding".into())).is_err());
        for limits in [
            QueryLimits {
                max_bytes: 0,
                ..QueryLimits::default()
            },
            QueryLimits {
                max_tokens: 257,
                ..QueryLimits::default()
            },
            QueryLimits {
                max_depth: usize::MAX,
                ..QueryLimits::default()
            },
            QueryLimits {
                max_nodes: usize::MAX,
                ..QueryLimits::default()
            },
        ] {
            assert_eq!(
                parse_with_limits("*", limits).unwrap_err().message,
                "invalid query limits"
            );
        }
    }
}
