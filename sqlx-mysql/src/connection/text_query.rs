//! Client-side parameter interpolation for the MySQL COM_QUERY (text)
//! protocol — used when the prepared-statement cache is disabled.
//!
//! # Why this exists
//!
//! sqlx normally executes parameterized queries via the binary
//! prepared-statement protocol:
//! `COM_STMT_PREPARE` → `COM_STMT_EXECUTE` → (optionally) `COM_STMT_CLOSE`.
//! That's efficient for repeated queries (the server caches the plan)
//! and security-friendly (parameter values travel out-of-band from SQL
//! text and can never reach a code position). It is, however, hostile
//! to MySQL connection proxies. The moment a client opens a prepared statement,
//! the proxy has to **pin** that client to a specific backend connection,
//! because the numeric `COM_STMT_*` statement ID is only meaningful on the
//! backend that issued it. Pinning defeats the whole point of running a proxy
//! (multiplexing client connections over a smaller backend pool), and is one of
//! the dominant reasons real-world deployments reach for an "interpolate
//! parameters client-side" knob: Go's `interpolateParams=true`, JDBC's
//! `useServerPrepStmts=false`, Node-`mysql2`'s `connection.query()` vs
//! `.execute()`, PHP-PDO's emulated prepares, etc.
//!
//! sqlx upstream has declined to expose this toggle — see issue
//! <https://github.com/launchbadge/sqlx/issues/3273> ("Can not disable
//! Prepared statement in SqlX") and rejected PR
//! <https://github.com/launchbadge/sqlx/pull/3280> ("support disable
//! prepared statement"). The maintainer pointed users to
//! `sqlx::raw_sql` (<https://docs.rs/sqlx/0.8.6/sqlx/fn.raw_sql.html>),
//! which has no bind-parameter ergonomics and forces users to write
//! their own escaping. This module is the missing piece: when a user
//! opts in via [`MySqlConnectOptions::statement_cache_capacity(0)`][cap],
//! the executor (`connection/executor.rs::run`) routes parameterized
//! queries through [`interpolate`] here, which renders the bind values
//! inline and sends a single `COM_QUERY` packet — bind ergonomics
//! preserved, no statement IDs minted, proxy multiplexing intact.
//!
//! [cap]: crate::options::MySqlConnectOptions::statement_cache_capacity
//!
//! # How it works
//!
//! The public entry point is [`interpolate`]. It runs in two phases:
//!
//! 1. [`decode_arguments`] walks the `COM_STMT_EXECUTE`-shaped values
//!    blob that sqlx has already built up in [`MySqlArguments`]
//!    (`values: Vec<u8>` plus per-parameter [`MySqlTypeInfo`] and the
//!    NULL bitmap) and turns each parameter back into a
//!    [`mysql_common::value::Value`]. Each `decode_*` function cites the
//!    relevant section of the MySQL binary-protocol reference.
//!
//! 2. [`splice`] is a small streaming MySQL-lexer subset that walks the
//!    SQL text and finds the `?` characters that are *outside* string
//!    literals, backtick identifiers, and line/block comments — i.e.
//!    the placeholders MySQL would actually bind. For each one, it
//!    emits `Value::as_sql(no_backslash_escape)` (the routine the
//!    canonical `mysql` / `mysql_async` drivers use to render SQL
//!    literals). Each branch of the lexer cites its rule in the MySQL
//!    8.0 reference manual.
//!
//! # Security model
//!
//! All value escaping is delegated to [`mysql_common::value::Value::as_sql`],
//! which implements the same byte-level escapes as
//! `mysql_real_escape_string`: `\0 \' \" \b \n \r \t \Z \\` (or
//! `''`-doubling under `NO_BACKSLASH_ESCAPES`). Floats/ints go through
//! `Display`; `Value::Bytes` payloads that aren't UTF-8-decodable are
//! emitted as `0x…` hex literals. So **every spliced fragment is a
//! syntactic literal** — there is no path from a bind value to a code
//! position via the value itself.
//!
//! The only theoretical injection vector is a *parser disagreement*
//! between this module's lexer and the MySQL server's: if our lexer
//! thought a `?` was outside a string when MySQL thinks it's inside
//! (or vice versa), we might splice in an unexpected place. The
//! branches in `splice` are written and tested against the MySQL 8.0
//! reference manual specifically to close that gap; see the inline
//! citations and the `tests` module below for adversarial inputs.
//!
//! # Vendor-patch hygiene
//!
//! This module is a vendored patch on top of upstream sqlx. It is
//! deliberately self-contained — the only edits to existing files are a
//! single new branch in `connection/executor.rs::run` and a single
//! `mod text_query;` line in `connection/mod.rs`. Future upstream
//! merges should not conflict with anything in this file unless
//! upstream itself adds the feature.
//!
//! # Known limitations
//!
//! 1. **Connection charset must be a UTF-8 superset.** Byte-wise
//!    escaping (what `Value::as_sql` and `mysql_real_escape_string` do)
//!    is only safe when the connection's character set is
//!    ASCII-compatible. sqlx-mysql forces `utf8mb4` on connect, so the
//!    default is fine. Do **not** issue
//!    `SET NAMES gbk` / `big5` / `gb2312` / `cp932` / `sjis` (or any
//!    other non-ASCII-superset charset) on a connection that uses this
//!    path — doing so reopens the classic `mysql_real_escape_string`
//!    GBK SQL-injection vector. (The same constraint Go's
//!    `interpolateParams` documents.)
//!
//! 2. **`ANSI_QUOTES` sql_mode is not tracked.** Under that mode `"…"`
//!    is an identifier delimiter (like backticks) and `\` is not an
//!    escape character inside it. We always treat `"…"` like a
//!    single-quoted string, so SQL such as `WHERE "a\"b" = ?` will
//!    misalign placeholder counts under `ANSI_QUOTES`. Worst case is a
//!    runtime arity error, not a silent injection (every spliced value
//!    is still a syntactic literal). If you need `ANSI_QUOTES`, prefer
//!    the prepared-statement path.
//!
//!    Note: sqlx-mysql itself **never** sets `ANSI_QUOTES` (see
//!    `options/connect.rs` — it only ever appends `PIPES_AS_CONCAT`
//!    and/or `NO_ENGINE_SUBSTITUTION` via
//!    `SET sql_mode = (SELECT CONCAT(@@sql_mode, ',…'))`), and MySQL's
//!    default `@@sql_mode` does not include `ANSI_QUOTES` on any
//!    supported server version. So this limitation only matters if
//!    either (a) the MySQL server's global `@@sql_mode` was
//!    administratively configured to include `ANSI_QUOTES`, or (b) the
//!    application issues `SET sql_mode = '…,ANSI_QUOTES'` (or
//!    `SET sql_mode = 'ANSI'`, a shorthand that includes it) on the
//!    connection at runtime.
use mysql_common::value::Value;

use crate::error::Error;
use crate::protocol::text::{ColumnFlags, ColumnType};
use crate::{MySqlArguments, MySqlTypeInfo};

/// Interpolate `arguments` into `sql` and return the resulting SQL string.
///
/// `no_backslash_escape` should reflect the connection's current
/// `SERVER_STATUS_NO_BACKSLASH_ESCAPES` status flag.
pub(crate) fn interpolate(
    sql: &str,
    arguments: &MySqlArguments,
    no_backslash_escape: bool,
) -> Result<String, Error> {
    let values = decode_arguments(arguments)?;
    splice(sql, &values, no_backslash_escape)
}

#[derive(Copy, Clone)]
enum State {
    Normal,
    /// Inside a `'…'`, `"…"`, or `` `…` `` literal; field is the opening byte.
    Quoted(u8),
    LineComment,
    BlockComment,
}

/// Walk `sql` byte-by-byte, replacing each `?` placeholder (in Normal
/// state) with the corresponding `Value::as_sql(...)` rendering. The state
/// machine implements the subset of MySQL's lexer needed to *find* real
/// placeholders — i.e. distinguish `?` characters that live inside string
/// literals, backtick identifiers, line comments, and block comments
/// from those that don't.
///
/// References:
/// - String literals & escape table:
///   <https://dev.mysql.com/doc/refman/8.0/en/string-literals.html>
/// - Identifiers (backtick / `ANSI_QUOTES`):
///   <https://dev.mysql.com/doc/refman/8.0/en/identifiers.html>
/// - Comment syntax (`--`, `#`, `/* */`, `/*! */`):
///   <https://dev.mysql.com/doc/refman/8.0/en/comments.html>
/// - Optimizer hints (`/*+ */`):
///   <https://dev.mysql.com/doc/refman/8.0/en/optimizer-hints.html>
/// - Server SQL modes (`NO_BACKSLASH_ESCAPES`, `ANSI_QUOTES`):
///   <https://dev.mysql.com/doc/refman/8.0/en/sql-mode.html>
fn splice(sql: &str, values: &[Value], no_backslash_escape: bool) -> Result<String, Error> {
    let mut out = String::with_capacity(sql.len() + values.len() * 8);
    let bytes = sql.as_bytes();
    let mut next_param = 0usize;
    let mut state = State::Normal;
    let mut seg_start = 0usize;
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        match state {
            State::Normal => match b {
                b'\'' | b'"' | b'`' => {
                    // `'…'` and `"…"` are string literals; `` `…` `` is
                    // always an identifier delimiter. Under `ANSI_QUOTES`
                    // sql_mode `"…"` becomes an identifier instead of a
                    // string — we don't track that mode here (see module
                    // docs), but the find-the-closing-quote logic below
                    // is correct for either interpretation.
                    //
                    // — https://dev.mysql.com/doc/refman/8.0/en/string-literals.html
                    // — https://dev.mysql.com/doc/refman/8.0/en/identifiers.html
                    state = State::Quoted(b);
                    i += 1;
                }
                b'-' if bytes.get(i + 1) == Some(&b'-')
                    && bytes
                        .get(i + 2)
                        .is_none_or(|c| c.is_ascii_whitespace() || c.is_ascii_control()) =>
                {
                    // MySQL's `--` line comment requires the second dash to
                    // be followed by "whitespace or a control character"
                    // (or EOF). Without that, `--` is two unary minuses,
                    // e.g. `b--?` parses as `b - -?` with `?` as a
                    // placeholder.
                    //
                    // > In MySQL, the `--` (double-dash) comment style
                    // > requires the second dash to be followed by at
                    // > least one whitespace or control character, such
                    // > as a space or tab.
                    //
                    // — https://dev.mysql.com/doc/refman/8.0/en/comments.html
                    state = State::LineComment;
                    i += 2;
                }
                b'#' => {
                    // `#` always starts a line comment — no whitespace
                    // requirement (unlike `--`).
                    //
                    // > From a `#` character to the end of the line.
                    //
                    // — https://dev.mysql.com/doc/refman/8.0/en/comments.html
                    state = State::LineComment;
                    i += 1;
                }
                b'/' if bytes.get(i + 1) == Some(&b'*') => {
                    // `/*! … */` is a "conditional / executable comment":
                    // MySQL parses and executes its contents as SQL, so `?`
                    // placeholders inside are real placeholders.
                    //
                    // > MySQL Server parses and executes the code within
                    // > the comment as it would any other SQL statement.
                    //
                    // — https://dev.mysql.com/doc/refman/8.0/en/comments.html
                    //
                    // `/*+ … */` is an optimizer hint. Hint contents are
                    // *hint syntax*, not SQL, and the docs explicitly state
                    // hints "must specify literal values, table names, and
                    // index names directly in the SQL text" — placeholders
                    // are not accepted. We therefore treat optimizer hints
                    // as plain block comments here, matching the
                    // prepared-statement path's behavior.
                    //
                    // — https://dev.mysql.com/doc/refman/8.0/en/optimizer-hints.html
                    if bytes.get(i + 2) == Some(&b'!') {
                        i += 3;
                    } else {
                        state = State::BlockComment;
                        i += 2;
                    }
                }
                b'?' => {
                    // sqlx's bind-parameter convention. MySQL itself uses
                    // `?` placeholders only in COM_STMT_PREPARE; in plain
                    // SQL `?` is just an unrecognized character. Once the
                    // value below has been spliced via
                    // `mysql_common::Value::as_sql`, the resulting text
                    // contains only literal SQL tokens that COM_QUERY
                    // understands.
                    //
                    // — https://dev.mysql.com/doc/refman/8.0/en/sql-prepared-statements.html
                    out.push_str(&sql[seg_start..i]);
                    let value = values.get(next_param).ok_or_else(|| {
                        err_protocol!(
                            "interpolation: SQL has more `?` placeholders than bound arguments ({})",
                            values.len()
                        )
                    })?;
                    out.push_str(&value.as_sql(no_backslash_escape));
                    next_param += 1;
                    i += 1;
                    seg_start = i;
                }
                // Any other byte in Normal state is just a regular SQL
                // token character; no placeholder action.
                _ => i += 1,
            },
            State::Quoted(q) => {
                if b == b'\\' && !no_backslash_escape && q != b'`' && i + 1 < bytes.len() {
                    // Backslash escape sequences (`\0 \' \" \b \n \r \t \Z
                    // \\ \% \_`) consume two bytes — the backslash and the
                    // following character. Apply only inside `'…'` /
                    // `"…"` string literals, and only when `sql_mode` does
                    // NOT include `NO_BACKSLASH_ESCAPES`. Backslash is not
                    // special inside backtick (or `ANSI_QUOTES`-mode
                    // double-quoted) identifiers.
                    //
                    // > Within a string, certain sequences have special
                    // > meaning unless the `NO_BACKSLASH_ESCAPES` SQL mode
                    // > is enabled.
                    //
                    // — https://dev.mysql.com/doc/refman/8.0/en/string-literals.html
                    i += 2;
                } else if b == q {
                    if bytes.get(i + 1) == Some(&q) {
                        // Doubled-quote escape: `''` inside `'…'`, `""`
                        // inside `"…"`, `` `` `` inside `` `…` ``.
                        // Doubling is the *only* escape inside backtick
                        // identifiers, and the only escape inside string
                        // literals under `NO_BACKSLASH_ESCAPES`.
                        //
                        // — https://dev.mysql.com/doc/refman/8.0/en/string-literals.html
                        // — https://dev.mysql.com/doc/refman/8.0/en/identifiers.html
                        i += 2;
                    } else {
                        // Closing quote — exit the literal/identifier.
                        state = State::Normal;
                        i += 1;
                    }
                } else {
                    // Ordinary byte inside the literal/identifier; copy
                    // through (the surrounding span flush handles output).
                    i += 1;
                }
            }
            State::LineComment => {
                // Line comments terminate at `\n`. (CR alone doesn't end a
                // line comment per the manual; only the linefeed does.)
                //
                // — https://dev.mysql.com/doc/refman/8.0/en/comments.html
                if b == b'\n' {
                    state = State::Normal;
                }
                i += 1;
            }
            State::BlockComment => {
                // Block comments terminate at the first `*/`. MySQL
                // explicitly does not support nesting, so we don't either.
                //
                // > Nested comments are not supported, and are deprecated;
                // > expect them to be removed in a future MySQL release.
                //
                // — https://dev.mysql.com/doc/refman/8.0/en/comments.html
                if b == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    state = State::Normal;
                    i += 2;
                } else {
                    i += 1;
                }
            }
        }
    }
    out.push_str(&sql[seg_start..]);

    if next_param != values.len() {
        return Err(err_protocol!(
            "interpolation: bound {} arguments but SQL contains {} `?` placeholders",
            values.len(),
            next_param
        ));
    }

    Ok(out)
}

/// Decode the contiguous parameter-values blob from a `MySqlArguments`
/// into a `Vec<Value>`, using the per-parameter `MySqlTypeInfo` and the
/// NULL bitmap to know how many bytes each value occupies.
///
/// The on-wire layout matches what `COM_STMT_EXECUTE` builds in
/// `sqlx-mysql/src/protocol/statement/execute.rs`: a NULL bitmap, then
/// type tags, then the value bytes back-to-back. The encoding for each
/// `MYSQL_TYPE_*` value is documented in the binary-protocol reference:
///
/// — <https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_protocol_binary_resultset.html#sect_protocol_binary_resultset_row_value>
/// — <https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_protocol_com_stmt_execute.html>
fn decode_arguments(arguments: &MySqlArguments) -> Result<Vec<Value>, Error> {
    let mut out = Vec::with_capacity(arguments.types.len());
    let mut buf: &[u8] = &arguments.values;

    for (i, ty) in arguments.types.iter().enumerate() {
        if is_null(arguments, i) {
            // NULL parameters contribute zero bytes to the values blob;
            // the NULL bitmap (read by `is_null`) is the sole signal.
            out.push(Value::NULL);
            continue;
        }

        out.push(decode_one(ty, &mut buf)?);
    }

    if !buf.is_empty() {
        return Err(err_protocol!(
            "interpolation: {} trailing bytes after decoding {} parameters",
            buf.len(),
            arguments.types.len()
        ));
    }

    Ok(out)
}

/// Look up the i-th NULL flag in the COM_STMT_EXECUTE NULL bitmap. The
/// bitmap has one bit per parameter, packed little-endian within each byte
/// (LSB first).
///
/// — <https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_protocol_com_stmt_execute.html>
fn is_null(arguments: &MySqlArguments, i: usize) -> bool {
    let bitmap: &[u8] = &arguments.null_bitmap;
    let byte = i / 8;
    let bit = i % 8;
    bitmap.get(byte).is_some_and(|b| (b >> bit) & 1 == 1)
}

/// Decode a single parameter value at the head of `buf` using its declared
/// `MySqlTypeInfo`. Each branch's byte layout is fixed by the binary
/// resultset / `COM_STMT_EXECUTE` protocol:
///
/// — <https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_protocol_binary_resultset.html#sect_protocol_binary_resultset_row_value>
fn decode_one(ty: &MySqlTypeInfo, buf: &mut &[u8]) -> Result<Value, Error> {
    let unsigned = ty.flags.contains(ColumnFlags::UNSIGNED);

    match ty.r#type {
        // MYSQL_TYPE_TINY: 1-byte fixed. Sign determined by UNSIGNED flag.
        ColumnType::Tiny => {
            let bytes = take_fixed::<1>(buf)?;
            Ok(if unsigned {
                Value::UInt(u64::from(u8::from_le_bytes(bytes)))
            } else {
                Value::Int(i64::from(i8::from_le_bytes(bytes)))
            })
        }
        // MYSQL_TYPE_SHORT / MYSQL_TYPE_YEAR: 2-byte little-endian fixed.
        ColumnType::Short | ColumnType::Year => {
            let bytes = take_fixed::<2>(buf)?;
            Ok(if unsigned {
                Value::UInt(u64::from(u16::from_le_bytes(bytes)))
            } else {
                Value::Int(i64::from(i16::from_le_bytes(bytes)))
            })
        }
        // MYSQL_TYPE_LONG / MYSQL_TYPE_INT24: 4-byte little-endian fixed.
        // (INT24 is sign-extended into 4 bytes by the encoder.)
        ColumnType::Long | ColumnType::Int24 => {
            let bytes = take_fixed::<4>(buf)?;
            Ok(if unsigned {
                Value::UInt(u64::from(u32::from_le_bytes(bytes)))
            } else {
                Value::Int(i64::from(i32::from_le_bytes(bytes)))
            })
        }
        // MYSQL_TYPE_LONGLONG: 8-byte little-endian fixed.
        ColumnType::LongLong => {
            let bytes = take_fixed::<8>(buf)?;
            Ok(if unsigned {
                Value::UInt(u64::from_le_bytes(bytes))
            } else {
                Value::Int(i64::from_le_bytes(bytes))
            })
        }
        // MYSQL_TYPE_FLOAT: 4-byte IEEE-754 little-endian.
        ColumnType::Float => {
            let bytes = take_fixed::<4>(buf)?;
            Ok(Value::Float(f32::from_le_bytes(bytes)))
        }
        // MYSQL_TYPE_DOUBLE: 8-byte IEEE-754 little-endian.
        ColumnType::Double => {
            let bytes = take_fixed::<8>(buf)?;
            Ok(Value::Double(f64::from_le_bytes(bytes)))
        }
        // MYSQL_TYPE_DATE / DATETIME / TIMESTAMP: 1-byte length prefix
        // (0/4/7/11) followed by year(2)+month(1)+day(1)
        // [+hour(1)+min(1)+sec(1) [+micros(4)]]. See decode_date.
        //
        // — https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_protocol_binary_resultset.html#sect_protocol_binary_resultset_row_value_date
        ColumnType::Date | ColumnType::Datetime | ColumnType::Timestamp => decode_date(buf),
        // MYSQL_TYPE_TIME: 1-byte length prefix (0/8/12) followed by
        // is_negative(1)+days(4)+hour(1)+min(1)+sec(1) [+micros(4)].
        //
        // — https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_protocol_binary_resultset.html#sect_protocol_binary_resultset_row_value_time
        ColumnType::Time => decode_time(buf),

        // MYSQL_TYPE_{VAR_,}STRING, _BLOB, _DECIMAL, _JSON, _BIT,
        // _GEOMETRY, _ENUM, _SET: all encoded as a length-encoded byte
        // string (`int<lenenc>` length followed by raw bytes).
        //
        // `Value::Bytes` round-trips through `as_sql` as either `'…'`
        // for UTF-8-decodable payloads or `0x…` hex for the rest — both
        // are valid in COM_QUERY.
        //
        // — https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_protocol_basic_dt_strings.html
        ColumnType::Decimal
        | ColumnType::NewDecimal
        | ColumnType::VarChar
        | ColumnType::VarString
        | ColumnType::String
        | ColumnType::Blob
        | ColumnType::TinyBlob
        | ColumnType::MediumBlob
        | ColumnType::LongBlob
        | ColumnType::Json
        | ColumnType::Bit
        | ColumnType::Geometry
        | ColumnType::Enum
        | ColumnType::Set => {
            let bytes = take_lenenc_bytes(buf)?;
            Ok(Value::Bytes(bytes.to_vec()))
        }

        // MYSQL_TYPE_NULL: contributes no bytes at all (handled mostly
        // via the NULL bitmap; this branch is defensive).
        ColumnType::Null => Ok(Value::NULL),
    }
}

/// Decode a binary-protocol DATE/DATETIME/TIMESTAMP value. The encoder
/// (`sqlx-mysql/src/types/chrono.rs::encode_date`) writes:
///
/// - length byte: 0, 4, 7, or 11
/// - if ≥ 4: year (u16 LE), month (u8), day (u8)
/// - if ≥ 7: hour (u8), minute (u8), second (u8)
/// - if = 11: microseconds (u32 LE)
///
/// — <https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_protocol_binary_resultset.html#sect_protocol_binary_resultset_row_value_date>
fn decode_date(buf: &mut &[u8]) -> Result<Value, Error> {
    let len = take_u8(buf)?;
    match len {
        // Length 0 means the encoder elided the entire value (all zeros).
        0 => Ok(Value::Date(0, 0, 0, 0, 0, 0, 0)),
        4 | 7 | 11 => {
            let payload = take_n(buf, usize::from(len))?;
            let year = u16::from_le_bytes([payload[0], payload[1]]);
            let month = payload[2];
            let day = payload[3];
            let (hour, minute, second) = if len >= 7 {
                (payload[4], payload[5], payload[6])
            } else {
                (0, 0, 0)
            };
            let micros = if len == 11 {
                u32::from_le_bytes([payload[7], payload[8], payload[9], payload[10]])
            } else {
                0
            };
            Ok(Value::Date(year, month, day, hour, minute, second, micros))
        }
        other => Err(err_protocol!(
            "interpolation: unexpected DATE/DATETIME length {other}"
        )),
    }
}

/// Decode a binary-protocol TIME value. The encoder
/// (`sqlx-mysql/src/types/mysql_time.rs::Encode`) writes:
///
/// - length byte: 0, 8, or 12
/// - if ≥ 8: is_negative (u8), days (u32 LE), hour (u8), minute (u8), second (u8)
/// - if = 12: microseconds (u32 LE)
///
/// — <https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_protocol_binary_resultset.html#sect_protocol_binary_resultset_row_value_time>
fn decode_time(buf: &mut &[u8]) -> Result<Value, Error> {
    let len = take_u8(buf)?;
    match len {
        // Length 0 means the value is exactly zero.
        0 => Ok(Value::Time(false, 0, 0, 0, 0, 0)),
        8 | 12 => {
            let payload = take_n(buf, usize::from(len))?;
            let is_neg = payload[0] != 0;
            let days = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
            let hours = payload[5];
            let minutes = payload[6];
            let seconds = payload[7];
            let micros = if len == 12 {
                u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]])
            } else {
                0
            };
            Ok(Value::Time(is_neg, days, hours, minutes, seconds, micros))
        }
        other => Err(err_protocol!(
            "interpolation: unexpected TIME length {other}"
        )),
    }
}

fn take_u8(buf: &mut &[u8]) -> Result<u8, Error> {
    let (head, tail) = buf
        .split_first()
        .ok_or_else(|| err_protocol!("interpolation: unexpected end of argument buffer"))?;
    *buf = tail;
    Ok(*head)
}

fn take_fixed<const N: usize>(buf: &mut &[u8]) -> Result<[u8; N], Error> {
    if buf.len() < N {
        return Err(err_protocol!(
            "interpolation: need {N} bytes, have {}",
            buf.len()
        ));
    }
    let (head, tail) = buf.split_at(N);
    let mut out = [0u8; N];
    out.copy_from_slice(head);
    *buf = tail;
    Ok(out)
}

fn take_n<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], Error> {
    if buf.len() < n {
        return Err(err_protocol!(
            "interpolation: need {n} bytes, have {}",
            buf.len()
        ));
    }
    let (head, tail) = buf.split_at(n);
    *buf = tail;
    Ok(head)
}

/// Read a `string<lenenc>`: a length-encoded integer followed by exactly
/// that many raw bytes.
///
/// — <https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_protocol_basic_dt_strings.html>
fn take_lenenc_bytes<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    let len = take_lenenc_int(buf)?;
    let len = usize::try_from(len)
        .map_err(|_| err_protocol!("interpolation: lenenc length overflows usize: {len}"))?;
    take_n(buf, len)
}

/// Read an `int<lenenc>`. First byte determines the width:
///
/// - `0x00..=0xFA`: that byte is the value (1 byte total).
/// - `0xFC`: 2-byte little-endian unsigned follows.
/// - `0xFD`: 3-byte little-endian unsigned follows.
/// - `0xFE`: 8-byte little-endian unsigned follows.
/// - `0xFB` / `0xFF` aren't valid in this context (NULL-marker / error
///   sentinels in other parts of the protocol); we don't expect to see
///   them in a parameter values blob and just treat them as a literal
///   single-byte length to avoid panicking on malformed input.
///
/// — <https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_protocol_basic_dt_integers.html>
fn take_lenenc_int(buf: &mut &[u8]) -> Result<u64, Error> {
    let first = take_u8(buf)?;
    match first {
        0xfc => Ok(u64::from(u16::from_le_bytes(take_fixed::<2>(buf)?))),
        0xfd => {
            let b = take_fixed::<3>(buf)?;
            Ok(u64::from(u32::from_le_bytes([b[0], b[1], b[2], 0])))
        }
        0xfe => Ok(u64::from_le_bytes(take_fixed::<8>(buf)?)),
        v => Ok(u64::from(v)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arguments::MySqlArguments;

    fn args_with<F: FnOnce(&mut MySqlArguments)>(f: F) -> MySqlArguments {
        let mut a = MySqlArguments::default();
        f(&mut a);
        a
    }

    #[test]
    fn splice_basic_int_string() {
        let args = args_with(|a| {
            a.add(42i32).unwrap();
            a.add("o'reilly").unwrap();
        });
        let out = interpolate("SELECT ?, ?", &args, false).unwrap();
        assert_eq!(out, "SELECT 42, 'o\\'reilly'");
    }

    #[test]
    fn splice_no_backslash_escape() {
        let args = args_with(|a| {
            a.add("o'reilly").unwrap();
        });
        let out = interpolate("SELECT ?", &args, true).unwrap();
        assert_eq!(out, "SELECT 'o''reilly'");
    }

    #[test]
    fn splice_skips_question_mark_in_string_literal() {
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        let out = interpolate("SELECT '?', ?", &args, false).unwrap();
        assert_eq!(out, "SELECT '?', 1");
    }

    #[test]
    fn splice_skips_question_mark_in_line_comment() {
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        let out = interpolate("SELECT 1 -- ?\n, ?", &args, false).unwrap();
        assert_eq!(out, "SELECT 1 -- ?\n, 1");
    }

    #[test]
    fn splice_skips_question_mark_in_block_comment() {
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        let out = interpolate("SELECT /* ? */ ?", &args, false).unwrap();
        assert_eq!(out, "SELECT /* ? */ 1");
    }

    #[test]
    fn splice_preserves_multibyte_utf8() {
        let args = args_with(|a| {
            a.add(7i32).unwrap();
        });
        // The crab emoji is 4 bytes in UTF-8; ensure it round-trips.
        let out = interpolate("SELECT '🦀', ?", &args, false).unwrap();
        assert_eq!(out, "SELECT '🦀', 7");
    }

    #[test]
    fn splice_arity_mismatch_too_few_placeholders() {
        let args = args_with(|a| {
            a.add(1i32).unwrap();
            a.add(2i32).unwrap();
        });
        assert!(interpolate("SELECT ?", &args, false).is_err());
    }

    #[test]
    fn splice_arity_mismatch_too_many_placeholders() {
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        assert!(interpolate("SELECT ?, ?", &args, false).is_err());
    }

    #[test]
    fn splice_null_argument() {
        let args = args_with(|a| {
            a.add(Option::<i32>::None).unwrap();
        });
        let out = interpolate("SELECT ?", &args, false).unwrap();
        assert_eq!(out, "SELECT NULL");
    }

    #[test]
    fn splice_doubled_quote_inside_string() {
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        // The inner `''` is an escaped single quote; the `?` between them is
        // still inside the string literal.
        let out = interpolate("SELECT 'a''?b', ?", &args, false).unwrap();
        assert_eq!(out, "SELECT 'a''?b', 1");
    }

    #[test]
    fn splice_unsigned_int() {
        let args = args_with(|a| {
            a.add(u32::MAX).unwrap();
        });
        let out = interpolate("SELECT ?", &args, false).unwrap();
        assert_eq!(out, "SELECT 4294967295");
    }

    #[test]
    fn splice_negative_int() {
        let args = args_with(|a| {
            a.add(-7i64).unwrap();
        });
        let out = interpolate("SELECT ?", &args, false).unwrap();
        assert_eq!(out, "SELECT -7");
    }

    // -- Comment edge cases ------------------------------------------------

    #[test]
    fn splice_dash_dash_no_whitespace_is_not_comment() {
        // `b--?` parses as `b - -?` in MySQL (no whitespace after `--`),
        // so the `?` IS a placeholder.
        let args = args_with(|a| {
            a.add(5i32).unwrap();
        });
        let out = interpolate("SELECT b--?", &args, false).unwrap();
        assert_eq!(out, "SELECT b--5");
    }

    #[test]
    fn splice_dash_dash_eof_is_comment() {
        // `--` at end-of-input is a comment (whitespace requirement is
        // satisfied by EOF). No splice happens; arity must still match.
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        let out = interpolate("SELECT ?--", &args, false).unwrap();
        assert_eq!(out, "SELECT 1--");
    }

    #[test]
    fn splice_dash_dash_tab_is_comment() {
        // Tab counts as whitespace, so this IS a comment.
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        let out = interpolate("SELECT 1 --\t? \n, ?", &args, false).unwrap();
        assert_eq!(out, "SELECT 1 --\t? \n, 1");
    }

    #[test]
    fn splice_hash_comment_swallows_question_mark() {
        let args = args_with(|a| {
            a.add(7i32).unwrap();
        });
        let out = interpolate("SELECT 1 # ?\n, ?", &args, false).unwrap();
        assert_eq!(out, "SELECT 1 # ?\n, 7");
    }

    #[test]
    fn splice_conditional_comment_is_executed() {
        // `/*! … */` is executed by MySQL — the `?` inside is a real
        // placeholder, not a comment.
        let args = args_with(|a| {
            a.add(3i32).unwrap();
            a.add(4i32).unwrap();
        });
        let out = interpolate("SELECT /*! ? */, ?", &args, false).unwrap();
        assert_eq!(out, "SELECT /*! 3 */, 4");
    }

    #[test]
    fn splice_optimizer_hint_treated_as_comment() {
        // `/*+ … */` is a hint comment whose contents are *hint syntax*,
        // not SQL — the MySQL manual explicitly says hints don't accept
        // placeholders. So we treat them like a regular block comment:
        // any `?` inside is swallowed (MySQL's parser would reject it
        // anyway in the prepared-statement path).
        let args = args_with(|a| {
            a.add(42i32).unwrap();
        });
        let out =
            interpolate("SELECT /*+ MAX_EXECUTION_TIME(1000) */ ?", &args, false).unwrap();
        assert_eq!(out, "SELECT /*+ MAX_EXECUTION_TIME(1000) */ 42");
    }

    #[test]
    fn splice_dash_dash_control_char_is_comment() {
        // The MySQL spec says `--` requires "whitespace or control
        // character" — bell (0x07) is a control char but not whitespace.
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        let out = interpolate("SELECT 1 --\x07?\n, ?", &args, false).unwrap();
        assert_eq!(out, "SELECT 1 --\x07?\n, 1");
    }

    #[test]
    fn splice_block_comment_with_string_inside_does_not_open_string() {
        // The `'` inside `/* … */` is part of the comment, not a string
        // delimiter. After the comment closes, the `?` is a placeholder.
        let args = args_with(|a| {
            a.add(9i32).unwrap();
        });
        let out = interpolate("SELECT /* it's fine */ ?", &args, false).unwrap();
        assert_eq!(out, "SELECT /* it's fine */ 9");
    }

    #[test]
    fn splice_unclosed_block_comment_swallows_remainder() {
        // No `*/` ever arrives; everything (including the `?`) is part of
        // the comment. Server will error, but we shouldn't splice.
        let args = args_with(|a| {});
        let out = interpolate("SELECT 1 /* ? trailing", &args, false).unwrap();
        assert_eq!(out, "SELECT 1 /* ? trailing");
    }

    #[test]
    fn splice_unclosed_line_comment_swallows_remainder() {
        let args = args_with(|a| {});
        let out = interpolate("SELECT 1 -- ? trailing", &args, false).unwrap();
        assert_eq!(out, "SELECT 1 -- ? trailing");
    }

    // -- String / identifier edge cases ------------------------------------

    #[test]
    fn splice_empty_string_then_placeholder() {
        let args = args_with(|a| {
            a.add(2i32).unwrap();
        });
        let out = interpolate("SELECT '', ?", &args, false).unwrap();
        assert_eq!(out, "SELECT '', 2");
    }

    #[test]
    fn splice_string_with_only_doubled_quotes() {
        // `''''` is a string containing one `'`. The `?` after it is a
        // placeholder.
        let args = args_with(|a| {
            a.add(8i32).unwrap();
        });
        let out = interpolate("SELECT '''', ?", &args, false).unwrap();
        assert_eq!(out, "SELECT '''', 8");
    }

    #[test]
    fn splice_question_mark_in_backtick_identifier() {
        // Backticks delimit identifiers; `?` inside is part of the name.
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        let out = interpolate("SELECT `weird?col` FROM t WHERE x = ?", &args, false).unwrap();
        assert_eq!(out, "SELECT `weird?col` FROM t WHERE x = 1");
    }

    #[test]
    fn splice_doubled_backtick_identifier() {
        // `` `a``b` `` is identifier "a`b". `?` outside is a placeholder.
        let args = args_with(|a| {
            a.add(0i32).unwrap();
        });
        let out = interpolate("SELECT `a``b` = ?", &args, false).unwrap();
        assert_eq!(out, "SELECT `a``b` = 0");
    }

    #[test]
    fn splice_backslash_inside_backtick_is_not_escape() {
        // Backslash is not special inside `…` identifiers.
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        let out = interpolate("SELECT `a\\` = ?", &args, false).unwrap();
        assert_eq!(out, "SELECT `a\\` = 1");
    }

    #[test]
    fn splice_charset_introducer_string() {
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        let out = interpolate("SELECT _utf8'?' = ?", &args, false).unwrap();
        assert_eq!(out, "SELECT _utf8'?' = 1");
    }

    #[test]
    fn splice_n_quoted_string() {
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        let out = interpolate("SELECT N'?' = ?", &args, false).unwrap();
        assert_eq!(out, "SELECT N'?' = 1");
    }

    #[test]
    fn splice_hex_literal_then_placeholder() {
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        let out = interpolate("SELECT x'AABB', ?", &args, false).unwrap();
        assert_eq!(out, "SELECT x'AABB', 1");
    }

    #[test]
    fn splice_adjacent_strings_with_placeholder_between() {
        // `'a' ? 'b'` — between the two strings we are in Normal state, so
        // the `?` is a placeholder.
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        let out = interpolate("SELECT 'a' ? 'b'", &args, false).unwrap();
        assert_eq!(out, "SELECT 'a' 1 'b'");
    }

    #[test]
    fn splice_escaped_quote_then_placeholder() {
        // `'foo\''` is a string containing `foo'`; the trailing `, ?` is a
        // placeholder.
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        let out = interpolate("SELECT 'foo\\'', ?", &args, false).unwrap();
        assert_eq!(out, "SELECT 'foo\\'', 1");
    }

    #[test]
    fn splice_doubled_backslash_then_close_quote_then_placeholder() {
        // `'\\\\'` is a string containing two backslashes; close-quote is
        // the final `'`. `?` after it is a placeholder.
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        let out = interpolate("SELECT '\\\\', ?", &args, false).unwrap();
        assert_eq!(out, "SELECT '\\\\', 1");
    }

    #[test]
    fn splice_unclosed_string_swallows_remainder() {
        // String never closes — everything after the open quote is "inside"
        // and we don't splice.
        let args = args_with(|a| {});
        let out = interpolate("SELECT 'oops ? ", &args, false).unwrap();
        assert_eq!(out, "SELECT 'oops ? ");
    }

    #[test]
    fn splice_trailing_backslash_in_string_does_not_overrun() {
        // `'\` at end-of-input: the backslash escape would consume the next
        // byte, but there isn't one. Must not panic / overrun.
        let args = args_with(|a| {});
        let out = interpolate("SELECT '\\", &args, false).unwrap();
        assert_eq!(out, "SELECT '\\");
    }

    #[test]
    fn splice_nbse_doubled_quote_in_double_string() {
        // Under NO_BACKSLASH_ESCAPES, `""` inside `"…"` is the only escape.
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        let out = interpolate("SELECT \"a\"\"b\", ?", &args, true).unwrap();
        assert_eq!(out, "SELECT \"a\"\"b\", 1");
    }

    #[test]
    fn splice_string_with_question_then_normal_question() {
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        let out = interpolate("SELECT '?'?''", &args, false).unwrap();
        assert_eq!(out, "SELECT '?'1''");
    }

    #[test]
    fn splice_full_width_question_mark_is_not_placeholder() {
        // FULLWIDTH QUESTION MARK (U+FF1F) encodes as 0xEF 0xBC 0x9F — none
        // of those bytes is 0x3F (`?`), so it must not match our finder.
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        let out = interpolate("SELECT ？, ?", &args, false).unwrap();
        assert_eq!(out, "SELECT ？, 1");
    }

    #[test]
    fn splice_question_mark_inside_block_comment_then_after() {
        let args = args_with(|a| {
            a.add(1i32).unwrap();
        });
        let out = interpolate("SELECT /*?*/?", &args, false).unwrap();
        assert_eq!(out, "SELECT /*?*/1");
    }

    #[test]
    fn splice_multi_statement() {
        let args = args_with(|a| {
            a.add(1i32).unwrap();
            a.add(2i32).unwrap();
        });
        let out = interpolate("SELECT ?; SELECT ?", &args, false).unwrap();
        assert_eq!(out, "SELECT 1; SELECT 2");
    }

    // -- Defensive: deliberately nasty bind values -------------------------

    #[test]
    fn splice_value_containing_quote_does_not_break_out() {
        // The classic injection attempt: a value like `' OR 1=1 --`. Must
        // come out fully escaped inside its `'…'` quoting.
        let args = args_with(|a| {
            a.add("' OR 1=1 --").unwrap();
        });
        let out = interpolate("SELECT * FROM t WHERE name = ?", &args, false).unwrap();
        assert_eq!(out, "SELECT * FROM t WHERE name = '\\' OR 1=1 --'");
        // Even more sanity: the spliced text contains a single opening and
        // closing quote that bracket the entire payload.
        assert!(out.ends_with("--'"));
    }

    #[test]
    fn splice_value_containing_backslash_quote_in_nbse_doubles_quote() {
        // Under NO_BACKSLASH_ESCAPES, `\` is literal and `'` doubles.
        let args = args_with(|a| {
            a.add("a'b\\c").unwrap();
        });
        let out = interpolate("SELECT ?", &args, true).unwrap();
        assert_eq!(out, "SELECT 'a''b\\c'");
    }

    #[test]
    fn splice_value_containing_null_and_newline() {
        let args = args_with(|a| {
            a.add("a\0b\nc").unwrap();
        });
        let out = interpolate("SELECT ?", &args, false).unwrap();
        // mysql_common escapes NUL as `\0` and newline as `\n`.
        assert_eq!(out, "SELECT 'a\\0b\\nc'");
    }
}
