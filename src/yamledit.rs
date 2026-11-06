//! Format-preserving edits of the policy YAML (the MCP write tools).
//!
//! The owner's files are full of comments (above keys, after list items,
//! inside multi-line flow sequences, commented-out entries), so a write tool
//! must change only what it was asked to change. Re-serializing a parsed
//! model would drop every comment; instead each [`Edit`] is applied twice:
//!
//! - on the **text**, as minimal byte-range edits located with the
//!   [`yamlpath`] crate (a lossless tree-sitter CST of the document, with
//!   byte spans and the removal rules of block and flow collections): an
//!   item appended to a flow sequence goes before its `]`, to a block
//!   sequence on a new `- ` line, a new key after the mapping's last pair,
//!   a list update only removes/appends the items that changed;
//! - on the parsed **value** ([`serde_yaml_ng::Value`]), which is what the
//!   edit means.
//!
//! [`apply_verified`] accepts the new text only if it parses (with the
//! typed, `deny_unknown_fields` model the server uses) to exactly the value
//! the edit means. A text edit that would come out different (some layout
//! the editor does not handle) is refused, never committed: the caller
//! can still replace the whole file (`write_policy`).
//!
//! List updates ([`Edit::Set`] of a sequence) are item-wise: items that stay
//! keep their place (and comments), removed ones disappear, new ones are
//! appended. Order does not matter in most policy lists (packages, SSIDs,
//! restrictions, downtime windows, limits, overrides), so the resulting
//! order is "kept items, then new ones" in both the text and the value.
//! Lists whose order matters (notification thresholds, strictly ascending)
//! use [`Edit::Replace`], which rewrites the value as a whole.

use serde::de::DeserializeOwned;
use serde_yaml_ng::{Mapping, Value};
use yamlpath::{Component, Document, FeatureKind, Route};

/// One step of a path into the document.
#[derive(Clone, Debug, PartialEq)]
pub enum Seg {
    Key(String),
    Index(usize),
}

pub fn key(k: &str) -> Seg {
    Seg::Key(k.to_string())
}

/// A semantic edit.
#[derive(Clone, Debug)]
pub enum Edit {
    /// Set the value at a path (missing parent mappings are created).
    /// `Null` removes the key. Sequences are updated item-wise, mappings
    /// key-wise, anything else replaced.
    Set(Vec<Seg>, Value),
    /// Remove a mapping key or a sequence item (absent key: nothing to do).
    Remove(Vec<Seg>),
    /// Append an item to the sequence at the path (created when absent).
    Push(Vec<Seg>, Value),
    /// Replace the value at a path as a whole, in the given order (created
    /// when absent; `Null` removes the key): for lists whose order matters,
    /// which the item-wise [`Edit::Set`] would reorder.
    Replace(Vec<Seg>, Value),
}

/// YAML text -> value (`Null` for an empty or comment-only document).
pub fn parse(text: &str) -> Result<Value, String> {
    serde_yaml_ng::from_str::<Option<Value>>(text)
        .map(|v| v.unwrap_or(Value::Null))
        .map_err(|e| e.to_string())
}

/// Apply `edits` to `text` keeping its formatting and comments, and check the
/// result means exactly what the edits mean (typed as `T`). Errors:
/// `Invalid` when the edits produce something `T` rejects (a user error),
/// `Internal` when the text edit did not come out as intended.
pub fn apply_verified<T: DeserializeOwned + PartialEq + std::fmt::Debug>(
    text: &str,
    edits: &[Edit],
) -> Result<String, EditError> {
    let mut expected =
        parse(text).map_err(|e| EditError::Invalid(format!("current file does not parse: {e}")))?;
    for e in edits {
        value_apply(&mut expected, e).map_err(EditError::Invalid)?;
    }
    let want: T = typed(&expected)
        .map_err(|e| EditError::Invalid(format!("the change makes the file invalid: {e}")))?;
    let mut out = text.to_string();
    for e in edits {
        out = text_apply(&out, e).map_err(EditError::Internal)?;
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    let got: T = serde_yaml_ng::from_str(&out)
        .map_err(|e| EditError::Internal(format!("edited text does not parse ({e}):\n{out}")))?;
    if got != want {
        return Err(EditError::Internal(format!(
            "edited text means something else than intended:\n{out}"
        )));
    }
    Ok(out)
}

#[derive(Debug, PartialEq)]
pub enum EditError {
    /// The requested change is not valid (unknown field, wrong type...).
    Invalid(String),
    /// The format-preserving editor could not express it faithfully.
    Internal(String),
}

impl std::fmt::Display for EditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EditError::Invalid(e) => write!(f, "{e}"),
            EditError::Internal(e) => write!(
                f,
                "the comment-preserving editor could not apply this change safely, nothing was changed \
                 (use write_policy with the full file instead): {e}"
            ),
        }
    }
}

/// Typed view of a value, through YAML text: `serde_yaml_ng` reads scalars
/// leniently from text (`default: 0` into a `String`), not from a `Value`.
fn typed<T: DeserializeOwned>(v: &Value) -> Result<T, String> {
    let text = serde_yaml_ng::to_string(v).map_err(|e| e.to_string())?;
    serde_yaml_ng::from_str(&text).map_err(|e| e.to_string())
}

// ------------------------------------------------------------ value level

fn get<'a>(v: &'a Value, path: &[Seg]) -> Option<&'a Value> {
    let mut cur = v;
    for s in path {
        cur = match (s, cur) {
            (Seg::Key(k), Value::Mapping(m)) => m.get(k.as_str())?,
            (Seg::Index(i), Value::Sequence(q)) => q.get(*i)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// Mutable access, creating mappings for missing keys (and for `Null`).
fn get_mut_create<'a>(v: &'a mut Value, path: &[Seg]) -> Result<&'a mut Value, String> {
    let mut cur = v;
    for (i, s) in path.iter().enumerate() {
        if cur.is_null() && matches!(s, Seg::Key(_)) {
            *cur = Value::Mapping(Mapping::new());
        }
        cur = match (s, cur) {
            (Seg::Key(k), Value::Mapping(m)) => {
                m.entry(Value::String(k.clone())).or_insert(Value::Null)
            }
            (Seg::Index(n), Value::Sequence(q)) => {
                let len = q.len();
                q.get_mut(*n).ok_or_else(|| {
                    format!("{}: index {n} out of range ({len} items)", show(&path[..i]))
                })?
            }
            (_, other) => {
                return Err(format!(
                    "{}: not a {} ({})",
                    show(&path[..=i]),
                    container(s),
                    kind(other)
                ));
            }
        };
    }
    Ok(cur)
}

fn container(s: &Seg) -> &'static str {
    match s {
        Seg::Key(_) => "mapping",
        Seg::Index(_) => "list",
    }
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "empty",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Sequence(_) => "list",
        Value::Mapping(_) => "mapping",
        Value::Tagged(_) => "tagged value",
    }
}

/// `device.hidden[2]`
pub fn show(path: &[Seg]) -> String {
    let mut s = String::new();
    for p in path {
        match p {
            Seg::Key(k) => {
                if !s.is_empty() {
                    s.push('.');
                }
                s.push_str(k);
            }
            Seg::Index(i) => s.push_str(&format!("[{i}]")),
        }
    }
    if s.is_empty() { "(document)".into() } else { s }
}

/// Item-wise list update: which old items stay (by index) and which new
/// items get appended. Equal items are matched one to one.
fn seq_plan(old: &[Value], new: &[Value]) -> (Vec<usize>, Vec<Value>) {
    let mut used = vec![false; new.len()];
    let mut keep = Vec::new();
    for (i, o) in old.iter().enumerate() {
        if let Some(j) = (0..new.len()).find(|&j| !used[j] && new[j] == *o) {
            used[j] = true;
            keep.push(i);
        }
    }
    let add = new
        .iter()
        .zip(&used)
        .filter(|(_, u)| !**u)
        .map(|(v, _)| v.clone())
        .collect();
    (keep, add)
}

fn value_set(slot: &mut Value, new: Value) {
    match (slot, new) {
        (Value::Sequence(old), Value::Sequence(new)) => {
            let (keep, add) = seq_plan(old, &new);
            let mut out: Vec<Value> = keep.into_iter().map(|i| old[i].clone()).collect();
            out.extend(add);
            *old = out;
        }
        (Value::Mapping(old), Value::Mapping(new)) => {
            let gone: Vec<Value> = old
                .keys()
                .filter(|k| !new.contains_key(*k))
                .cloned()
                .collect();
            for k in gone {
                old.shift_remove(&k);
            }
            for (k, v) in new {
                if v.is_null() {
                    old.shift_remove(&k);
                } else {
                    value_set(old.entry(k).or_insert(Value::Null), v);
                }
            }
        }
        (slot, new) => *slot = new,
    }
}

fn value_remove(root: &mut Value, path: &[Seg]) -> Result<(), String> {
    let Some((last, parent)) = path.split_last() else {
        return Err("cannot remove the whole document".into());
    };
    if get(root, parent).is_none() {
        return Ok(());
    }
    match (last, get_mut_create(root, parent)?) {
        (Seg::Key(k), Value::Mapping(m)) => {
            m.shift_remove(k.as_str());
        }
        (Seg::Index(i), Value::Sequence(q)) if *i < q.len() => {
            q.remove(*i);
        }
        (Seg::Index(i), Value::Sequence(q)) => {
            return Err(format!(
                "{}: index {i} out of range ({} items)",
                show(parent),
                q.len()
            ));
        }
        (Seg::Key(_), Value::Null) => {}
        (s, other) => {
            return Err(format!(
                "{}: not a {} ({})",
                show(parent),
                container(s),
                kind(other)
            ));
        }
    }
    Ok(())
}

pub fn value_apply(root: &mut Value, e: &Edit) -> Result<(), String> {
    match e {
        Edit::Set(path, v) if v.is_null() => value_remove(root, path),
        Edit::Set(path, v) => {
            value_set(get_mut_create(root, path)?, v.clone());
            Ok(())
        }
        Edit::Remove(path) => value_remove(root, path),
        Edit::Replace(path, v) if v.is_null() => value_remove(root, path),
        Edit::Replace(path, v) => {
            *get_mut_create(root, path)? = v.clone();
            Ok(())
        }
        Edit::Push(path, item) => match get_mut_create(root, path)? {
            slot @ Value::Null => {
                *slot = Value::Sequence(vec![item.clone()]);
                Ok(())
            }
            Value::Sequence(q) => {
                q.push(item.clone());
                Ok(())
            }
            other => Err(format!("{}: not a list ({})", show(path), kind(other))),
        },
    }
}

// ------------------------------------------------------------- rendering

const RESERVED: &[&str] = &[
    "y", "n", "yes", "no", "on", "off", "true", "false", "null", "~",
];

fn is_duration(s: &str) -> bool {
    // 1h30m, 45m, 90s: digits followed by a unit, repeated.
    let b = s.as_bytes();
    let mut i = 0;
    let mut any = false;
    while i < b.len() {
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start || i == b.len() || !matches!(b[i], b'h' | b'm' | b's') {
            return false;
        }
        i += 1;
        any = true;
    }
    any
}

/// A string as a YAML scalar: plain when unambiguous (package names, names,
/// durations), otherwise double-quoted (JSON escaping is valid YAML).
fn scalar_str(s: &str) -> String {
    let plain = s
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '/'))
        && !RESERVED.contains(&s.to_ascii_lowercase().as_str());
    if plain || is_duration(s) {
        s.to_string()
    } else {
        serde_json::to_string(s).expect("string")
    }
}

fn scalar(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => scalar_str(s),
        other => flow(other),
    }
}

/// Flow style: `[a, b]`, `{k: v, k2: v2}`.
pub fn flow(v: &Value) -> String {
    match v {
        Value::Sequence(q) => format!("[{}]", q.iter().map(flow).collect::<Vec<_>>().join(", ")),
        Value::Mapping(m) => {
            format!(
                "{{{}}}",
                m.iter()
                    .map(|(k, v)| format!("{}: {}", scalar(k), flow(v)))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        Value::Tagged(t) => flow(&t.value),
        other => scalar(other),
    }
}

fn is_seq_of_maps(v: &Value) -> bool {
    matches!(v, Value::Sequence(q) if !q.is_empty() && q.iter().all(Value::is_mapping))
}

/// What follows `key:` for a value placed in a block mapping whose keys sit
/// at column `indent`, in the style of the policy files: a top-level section
/// (`device:`) is a block mapping, a list of mappings (`downtime`, `limits`,
/// `overrides`) one `- {flow}` per line; anything else is flow (` 30m`,
/// ` [a, b]`, ` {allow: [x]}`).
fn after_colon(v: &Value, indent: usize) -> String {
    let pad = " ".repeat(indent + 2);
    match v {
        Value::Mapping(m) if !m.is_empty() && indent == 0 => m
            .iter()
            .map(|(k, v)| format!("\n{pad}{}:{}", scalar(k), after_colon(v, indent + 2)))
            .collect(),
        q if is_seq_of_maps(q) => {
            let Value::Sequence(q) = q else {
                unreachable!()
            };
            q.iter().map(|i| format!("\n{pad}- {}", flow(i))).collect()
        }
        other => format!(" {}", flow(other)),
    }
}

// ------------------------------------------------------------- text level

fn route(path: &[Seg]) -> Route<'static> {
    Route::from(
        path.iter()
            .map(|s| match s {
                Seg::Key(k) => Component::Key(k.clone().into()),
                Seg::Index(i) => Component::Index(*i),
            })
            .collect::<Vec<_>>(),
    )
}

fn doc(text: &str) -> Result<Document, String> {
    Document::new(text.to_string()).map_err(|e| format!("YAML: {e}"))
}

fn line_start(text: &str, pos: usize) -> usize {
    text[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0)
}

/// Byte just after the end of the line containing `pos` (after its `\n`).
fn next_line(text: &str, pos: usize) -> usize {
    text[pos..]
        .find('\n')
        .map(|i| pos + i + 1)
        .unwrap_or(text.len())
}

fn col(text: &str, pos: usize) -> usize {
    text[line_start(text, pos)..pos].chars().count()
}

fn splice(text: &str, range: std::ops::Range<usize>, with: &str) -> String {
    let mut s = String::with_capacity(text.len() + with.len());
    s.push_str(&text[..range.start]);
    s.push_str(with);
    s.push_str(&text[range.end..]);
    s
}

/// Insert a whole line before byte `at` (a line start), adding the missing
/// newline at the end of a file that has none.
fn insert_line(text: &str, at: usize, line: &str) -> String {
    if at == text.len() && !text.is_empty() && !text.ends_with('\n') {
        return format!("{text}\n{line}\n");
    }
    splice(text, at..at, &format!("{line}\n"))
}

/// Byte offset just after the `:` that follows the key at `path`.
fn colon_after_key(d: &Document, path: &[Seg]) -> Result<usize, String> {
    let k = d
        .query_key_only(&route(path))
        .map_err(|e| format!("{}: {e}", show(path)))?;
    let src = d.source();
    let end = k.location.byte_span.1;
    // The key may be quoted; the colon follows it (maybe after spaces).
    let rel = src[end..]
        .find(':')
        .ok_or_else(|| format!("{}: no ':' after the key", show(path)))?;
    if !src[end..end + rel].trim().is_empty()
        && !src[end..end + rel]
            .trim()
            .chars()
            .all(|c| c == '"' || c == '\'')
    {
        return Err(format!(
            "{}: unexpected text between key and ':'",
            show(path)
        ));
    }
    Ok(end + rel + 1)
}

/// End of the last real content of the value at `path`. The CST node of a
/// block collection (and so of a key/value pair holding one) also spans the
/// comments and blank lines after it, even those introducing the next key:
/// recurse to the last scalar or flow node, whose span is exact.
fn content_end(d: &Document, cur: &Value, path: &[Seg]) -> Result<usize, String> {
    let f = d
        .query_exact(&route(path))
        .map_err(|e| format!("{}: {e}", show(path)))?;
    let Some(f) = f else {
        return match path.last() {
            Some(Seg::Key(_)) => colon_after_key(d, path),
            _ => Err(format!("{}: empty list item", show(path))),
        };
    };
    let mut p = path.to_vec();
    match (f.kind(), get(cur, path)) {
        (FeatureKind::BlockSequence, Some(Value::Sequence(q))) if !q.is_empty() => {
            p.push(Seg::Index(q.len() - 1))
        }
        (FeatureKind::BlockMapping, Some(Value::Mapping(m))) if !m.is_empty() => p.push(Seg::Key(
            m.keys()
                .last()
                .and_then(Value::as_str)
                .ok_or("non-string key")?
                .to_string(),
        )),
        _ => return Ok(f.location.byte_span.1),
    }
    content_end(d, cur, &p)
}

/// Byte range removing the element at `path` from a block mapping or block
/// sequence: its whole lines (indentation, value, same-line comment,
/// newline), but not the comment lines that follow it.
fn block_removal(
    d: &Document,
    text: &str,
    cur: &Value,
    path: &[Seg],
) -> Result<std::ops::Range<usize>, String> {
    let end = next_line(text, content_end(d, cur, path)?);
    match path.last() {
        Some(Seg::Key(k)) => {
            let ks = d
                .query_key_only(&route(path))
                .map_err(|e| format!("{}: {e}", show(path)))?
                .location
                .byte_span
                .0;
            let ls = line_start(text, ks);
            if text[ls..ks].trim().is_empty() {
                return Ok(ls..end);
            }
            // First key of a `- key: value` item: the next key slides onto
            // the dash line (removing the whole line would drop the dash).
            let parent = &path[..path.len() - 1];
            let Some(Value::Mapping(m)) = get(cur, parent) else {
                return Err(format!("{}: unexpected layout", show(path)));
            };
            let keys: Vec<&str> = m.keys().filter_map(Value::as_str).collect();
            let i = keys
                .iter()
                .position(|x| x == k)
                .ok_or_else(|| format!("{}: key not found", show(path)))?;
            let next = keys
                .get(i + 1)
                .ok_or_else(|| format!("{}: only key of a list item", show(path)))?;
            let mut np = parent.to_vec();
            np.push(key(next));
            let ns = d
                .query_key_only(&route(&np))
                .map_err(|e| format!("{}: {e}", show(&np)))?
                .location
                .byte_span
                .0;
            Ok(ks..ns)
        }
        Some(Seg::Index(_)) => {
            let f = d
                .query_exact(&route(path))
                .map_err(|e| format!("{}: {e}", show(path)))?
                .ok_or("empty list item")?;
            let vs = f.location.byte_span.0;
            let ls = line_start(text, vs);
            if text[ls..vs].trim() != "-" {
                return Err(format!("{}: unexpected layout of a list item", show(path)));
            }
            Ok(ls..end)
        }
        None => Err("cannot remove the whole document".into()),
    }
}

pub fn text_apply(text: &str, e: &Edit) -> Result<String, String> {
    match e {
        Edit::Set(path, v) => t_set(text, path, v),
        Edit::Remove(path) => t_remove(text, path),
        Edit::Push(path, item) => t_push(text, path, item),
        Edit::Replace(path, v) => t_replace_whole(text, path, v),
    }
}

/// [`Edit::Replace`]: the value at `path` becomes exactly `new`.
fn t_replace_whole(text: &str, path: &[Seg], new: &Value) -> Result<String, String> {
    if new.is_null() {
        return t_remove(text, path);
    }
    let cur = parse(text)?;
    match get(&cur, path) {
        None => t_add(text, &cur, path, new),
        Some(old) if old == new => Ok(text.to_string()),
        Some(_) => t_replace(text, path, new),
    }
}

fn t_set(text: &str, path: &[Seg], new: &Value) -> Result<String, String> {
    if new.is_null() {
        return t_remove(text, path);
    }
    let cur = parse(text)?;
    match get(&cur, path) {
        None => t_add(text, &cur, path, new),
        Some(old) if old == new => Ok(text.to_string()),
        Some(Value::Sequence(old)) if new.is_sequence() => {
            let Value::Sequence(newq) = new else {
                unreachable!()
            };
            let (keep, add) = seq_plan(old, newq);
            let mut out = text.to_string();
            // Remove from the end so earlier indexes stay valid.
            for i in (0..old.len()).rev().filter(|i| !keep.contains(i)) {
                let mut p = path.to_vec();
                p.push(Seg::Index(i));
                out = t_remove(&out, &p)?;
            }
            for item in add {
                out = t_push(&out, path, &item)?;
            }
            Ok(out)
        }
        Some(Value::Mapping(old)) if new.is_mapping() => {
            let Value::Mapping(newm) = new else {
                unreachable!()
            };
            let mut out = text.to_string();
            for k in old.keys().filter(|k| !newm.contains_key(*k)) {
                let mut p = path.to_vec();
                p.push(Seg::Key(k.as_str().ok_or("non-string key")?.to_string()));
                out = t_remove(&out, &p)?;
            }
            for (k, v) in newm {
                let mut p = path.to_vec();
                p.push(Seg::Key(k.as_str().ok_or("non-string key")?.to_string()));
                out = t_set(&out, &p, v)?;
            }
            Ok(out)
        }
        Some(_) => t_replace(text, path, new),
    }
}

/// Replace the value at `path` (which exists, maybe empty) with `new`.
fn t_replace(text: &str, path: &[Seg], new: &Value) -> Result<String, String> {
    let d = doc(text)?;
    let r = route(path);
    let feature = d
        .query_exact(&r)
        .map_err(|e| format!("{}: {e}", show(path)))?;
    let in_block_mapping = matches!(path.last(), Some(Seg::Key(_)))
        && parent_kind(&d, path)? == Some(FeatureKind::BlockMapping);
    match feature {
        // `key:` with no value: write after the colon.
        None => {
            let c = colon_after_key(&d, path)?;
            let k = d.query_key_only(&r).map_err(|e| e.to_string())?;
            let ind = col(text, k.location.byte_span.0);
            let with = if in_block_mapping {
                after_colon(new, ind)
            } else {
                format!(" {}", flow(new))
            };
            Ok(splice(text, c..c, &with))
        }
        Some(f) => {
            let (s, e) = f.location.byte_span;
            if in_block_mapping {
                // From the colon to the end of the value's content (a block
                // value starts on the next line); a comment after a scalar
                // or flow value, and the comment lines after a block value,
                // stay.
                let c = colon_after_key(&d, path)?;
                let mut e = content_end(&d, &parse(text)?, path)?;
                if matches!(
                    f.kind(),
                    FeatureKind::BlockMapping | FeatureKind::BlockSequence
                ) {
                    // The last item's same-line comment goes with it.
                    e = next_line(text, e);
                    if text[..e].ends_with('\n') {
                        e -= 1;
                    }
                }
                let k = d.query_key_only(&r).map_err(|e| e.to_string())?;
                let ind = col(text, k.location.byte_span.0);
                Ok(splice(text, c..e, &after_colon(new, ind)))
            } else {
                Ok(splice(text, s..e, &flow(new)))
            }
        }
    }
}

/// Kind of the collection that directly contains `path`'s last segment.
fn parent_kind(d: &Document, path: &[Seg]) -> Result<Option<FeatureKind>, String> {
    let parent = &path[..path.len() - 1];
    if parent.is_empty() {
        return Ok(d.top_feature().ok().map(|f| f.kind()));
    }
    Ok(d.query_exact(&route(parent))
        .map_err(|e| format!("{}: {e}", show(parent)))?
        .map(|f| f.kind()))
}

fn t_remove(text: &str, path: &[Seg]) -> Result<String, String> {
    let cur = parse(text)?;
    if get(&cur, path).is_none() {
        return Ok(text.to_string());
    }
    let (last, parent) = path
        .split_last()
        .ok_or("cannot remove the whole document")?;
    // The last item of a list: leave an explicit `[]` (an absent list can
    // mean something else, e.g. permitted_input_methods).
    if let (Seg::Index(_), Some(Value::Sequence(q))) = (last, get(&cur, parent))
        && q.len() == 1
    {
        return t_replace(text, parent, &Value::Sequence(vec![]));
    }
    let d = doc(text)?;
    match parent_kind(&d, path)? {
        Some(FeatureKind::BlockMapping) => {
            // The only key of a nested block mapping: remove the mapping's
            // own key (an empty block mapping would read as null).
            if let Some(Value::Mapping(m)) = get(&cur, parent)
                && m.len() == 1
                && !parent.is_empty()
            {
                return t_remove(text, parent);
            }
            Ok(splice(text, block_removal(&d, text, &cur, path)?, ""))
        }
        Some(FeatureKind::BlockSequence) => {
            Ok(splice(text, block_removal(&d, text, &cur, path)?, ""))
        }
        // Flow collections: yamlpath removes the element and one comma.
        _ => {
            let span = d
                .removal_span(&route(path))
                .map_err(|e| format!("{}: {e}", show(path)))?;
            Ok(splice(text, span, ""))
        }
    }
}

/// Add a key that does not exist yet (`path` = parent path + key), creating
/// missing parent mappings in one go.
fn t_add(text: &str, cur: &Value, path: &[Seg], new: &Value) -> Result<String, String> {
    // Longest existing prefix.
    let mut n = path.len() - 1;
    while n > 0 && get(cur, &path[..n]).is_none() {
        n -= 1;
    }
    // Wrap the missing tail into nested mappings.
    let mut value = new.clone();
    for s in path[n + 1..].iter().rev() {
        let Seg::Key(k) = s else {
            return Err(format!("{}: list index on a missing list", show(path)));
        };
        let mut m = Mapping::new();
        m.insert(Value::String(k.clone()), value);
        value = Value::Mapping(m);
    }
    let Seg::Key(k) = &path[n] else {
        return Err(format!("{}: index out of range", show(&path[..=n])));
    };
    let parent = &path[..n];
    match get(cur, parent) {
        Some(Value::Mapping(m)) if !m.is_empty() => add_to_mapping(text, parent, m, k, &value),
        Some(Value::Mapping(_)) if !parent.is_empty() => {
            // `{}`: fill it, still in flow style.
            let d = doc(text)?;
            let f = d
                .query_exact(&route(parent))
                .map_err(|e| e.to_string())?
                .ok_or("empty mapping")?;
            let (fs, fe) = f.location.byte_span;
            if f.kind() != FeatureKind::FlowMapping {
                return Err(format!("{}: unexpected empty {:?}", show(parent), f.kind()));
            }
            let open = text[fs..fe].find('{').ok_or("no '{'")? + fs;
            let close = text[fs..fe].rfind('}').ok_or("no '}'")? + fs;
            Ok(splice(
                text,
                open + 1..close,
                &format!("{}: {}", scalar_str(k), flow(&value)),
            ))
        }
        Some(Value::Mapping(_)) | Some(Value::Null) => {
            let mut m = Mapping::new();
            m.insert(Value::String(k.clone()), value);
            if parent.is_empty() {
                // Empty or comment-only document: append at the end.
                let mut out = text.to_string();
                if !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(&format!(
                    "{}:{}\n",
                    scalar_str(k),
                    after_colon(&m[k.as_str()], 0)
                ));
                return Ok(out);
            }
            t_replace(text, parent, &Value::Mapping(m))
        }
        Some(other) => Err(format!("{}: not a mapping ({})", show(parent), kind(other))),
        None => Err(format!("{}: missing", show(parent))),
    }
}

fn add_to_mapping(
    text: &str,
    parent: &[Seg],
    m: &Mapping,
    k: &str,
    value: &Value,
) -> Result<String, String> {
    let d = doc(text)?;
    let last_key = m
        .keys()
        .last()
        .and_then(Value::as_str)
        .ok_or("non-string key")?
        .to_string();
    let mut lp = parent.to_vec();
    lp.push(Seg::Key(last_key));
    let lr = route(&lp);
    let key_f = d
        .query_key_only(&lr)
        .map_err(|e| format!("{}: {e}", show(&lp)))?;
    let end = content_end(&d, &parse(text)?, &lp)?;
    let container = if parent.is_empty() {
        d.top_feature().map_err(|e| e.to_string())?.kind()
    } else {
        d.query_exact(&route(parent))
            .map_err(|e| e.to_string())?
            .ok_or("empty mapping")?
            .kind()
    };
    match container {
        FeatureKind::BlockMapping => {
            let ind = col(text, key_f.location.byte_span.0);
            let line = format!(
                "{}{}:{}",
                " ".repeat(ind),
                scalar_str(k),
                after_colon(value, ind)
            );
            Ok(insert_line(text, next_line(text, end), &line))
        }
        FeatureKind::FlowMapping => Ok(splice(
            text,
            end..end,
            &format!(", {}: {}", scalar_str(k), flow(value)),
        )),
        other => Err(format!("{}: cannot add a key to a {other:?}", show(parent))),
    }
}

/// Lines longer than this get the appended flow item on a new line (only in
/// flow sequences that already span several lines).
const WRAP: usize = 100;

fn t_push(text: &str, path: &[Seg], item: &Value) -> Result<String, String> {
    let cur = parse(text)?;
    let existing = match get(&cur, path) {
        None | Some(Value::Null) => return t_set(text, path, &Value::Sequence(vec![item.clone()])),
        Some(Value::Sequence(q)) => q.clone(),
        Some(other) => return Err(format!("{}: not a list ({})", show(path), kind(other))),
    };
    let d = doc(text)?;
    let f = d
        .query_exact(&route(path))
        .map_err(|e| format!("{}: {e}", show(path)))?
        .ok_or("empty list")?;
    let (fs, fe) = f.location.byte_span;
    if existing.is_empty() {
        // `[]`: a list of mappings becomes a block list, scalars stay flow.
        if item.is_mapping()
            && matches!(path.last(), Some(Seg::Key(_)))
            && parent_kind(&d, path)? == Some(FeatureKind::BlockMapping)
        {
            return t_replace(text, path, &Value::Sequence(vec![item.clone()]));
        }
        let open = text[fs..fe].find('[').ok_or("no '[' in empty list")? + fs;
        let close = text[fs..fe].rfind(']').ok_or("no ']' in empty list")? + fs;
        return Ok(splice(text, open + 1..close, &flow(item)));
    }
    let mut lp = path.to_vec();
    lp.push(Seg::Index(existing.len() - 1));
    let last = d
        .query_exact(&route(&lp))
        .map_err(|e| format!("{}: {e}", show(&lp)))?
        .ok_or("empty last item")?;
    let (ls, le) = last.location.byte_span;
    match f.kind() {
        FeatureKind::FlowSequence => {
            let rendered = flow(item);
            let line_len = text[line_start(text, le)..next_line(text, le)]
                .trim_end()
                .chars()
                .count();
            if f.is_multiline() && line_len + rendered.len() + 2 > WRAP {
                // Indent like the first item starting on the last item's line.
                let first_on_line = (0..existing.len())
                    .filter_map(|i| {
                        let mut p = path.to_vec();
                        p.push(Seg::Index(i));
                        d.query_exact(&route(&p))
                            .ok()
                            .flatten()
                            .map(|f| f.location.byte_span.0)
                    })
                    .find(|s| line_start(text, *s) == line_start(text, ls))
                    .unwrap_or(ls);
                let ind = col(text, first_on_line);
                Ok(splice(
                    text,
                    le..le,
                    &format!(",\n{}{rendered}", " ".repeat(ind)),
                ))
            } else {
                Ok(splice(text, le..le, &format!(", {rendered}")))
            }
        }
        FeatureKind::BlockSequence => {
            let ls0 = line_start(text, ls);
            let dash = text[ls0..ls]
                .find('-')
                .map(|i| ls0 + i)
                .ok_or("block list item without '-' on its line")?;
            if !text[ls0..dash].trim().is_empty() {
                return Err(format!("{}: unexpected layout of the last item", show(&lp)));
            }
            let ind = col(text, dash);
            let rendered = match item {
                // Like the neighbours: a block mapping item stays a block.
                Value::Mapping(m) if last.kind() == FeatureKind::BlockMapping && !m.is_empty() => {
                    let pad = " ".repeat(ind + 2);
                    m.iter()
                        .enumerate()
                        .map(|(i, (k, v))| {
                            format!(
                                "{}{}:{}",
                                if i == 0 {
                                    String::new()
                                } else {
                                    format!("\n{pad}")
                                },
                                scalar(k),
                                after_colon(v, ind + 2)
                            )
                        })
                        .collect()
                }
                other => flow(other),
            };
            let end = content_end(&d, &cur, &lp)?;
            Ok(insert_line(
                text,
                next_line(text, end),
                &format!("{}- {rendered}", " ".repeat(ind)),
            ))
        }
        other => Err(format!("{}: not a list ({other:?})", show(path))),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::policy::{OverridesFile, PolicyFile};

    /// Shaped like a real, heavily commented policy: comments above keys, after
    /// block items, inside a multi-line flow sequence, commented-out items.
    pub(crate) const COMMENTED: &str = r#"# Test child - rules. Package names: MCP tool `apps`.
child: kid
timezone: Europe/Brussels

downtime:
  - {start: "22:00", end: "07:00"}

# Never limited, usable during downtime.
always_allowed:
  - com.google.android.dialer             # Phone
  - com.google.android.apps.messaging     # Messages
  - com.example.piano                     # piano: unlimited

# Never usable.
blocked:
  - com.zhiliaoapp.musically              # TikTok

# Apps installed by the child stay suspended until listed.
approval: true
# Unlimited outside downtime: approved, and excluded from "general".
approved:
  - com.example.flow                      # flow (piano)
  - com.duolingo                          # Duolingo

limits:
  # Sub-cap: also counts toward "general".
  - name: social
    apps: [com.instagram.android, com.snapchat.android, com.whatsapp, com.discord,
           com.reddit.frontpage, com.facebook.katana]
    daily: {weekdays: 30m, weekend: 45m}
  - name: video
    apps: [com.netflix.mediaclient, com.google.android.youtube]
    daily: {fri: 2h30m, sat: 2h30m, default: 0}
  - name: general
    apps: ["*"]
    exclude: [com.netflix.mediaclient, com.google.android.youtube,
              # unlimited outside downtime (see approved):
              com.example.flow, com.duolingo]
    daily: {weekdays: 1h, weekend: 1h30m}

device:
  lock_screen_info: "Téléphone de test — si trouvé, appeler"
  restrictions:
    - no_factory_reset
    - no_safe_boot
    # Enable once the account is added:
    # - no_modify_accounts
  uninstall_blocked: []
  # always_on_vpn: {package: com.tailscale.ipn, lockdown: true}
"#;

    const COMMENTS: &[&str] = &[
        "# Test child - rules. Package names: MCP tool `apps`.",
        "# Never limited, usable during downtime.",
        "# Phone",
        "# Messages",
        "# piano: unlimited",
        "# Never usable.",
        "# TikTok",
        "# Apps installed by the child stay suspended until listed.",
        "# Unlimited outside downtime: approved, and excluded from \"general\".",
        "# Sub-cap: also counts toward \"general\".",
        "# unlimited outside downtime (see approved):",
        "# Enable once the account is added:",
        "# - no_modify_accounts",
        "# always_on_vpn: {package: com.tailscale.ipn, lockdown: true}",
    ];

    fn s(v: &str) -> Value {
        Value::String(v.into())
    }

    fn y(text: &str) -> Value {
        serde_yaml_ng::from_str(text).unwrap()
    }

    fn p(parts: &[&str]) -> Vec<Seg> {
        parts
            .iter()
            .map(|x| {
                x.parse::<usize>()
                    .map(Seg::Index)
                    .unwrap_or_else(|_| key(x))
            })
            .collect()
    }

    fn ok(text: &str, edits: &[Edit]) -> String {
        let out = apply_verified::<PolicyFile>(text, edits).unwrap_or_else(|e| panic!("{e}"));
        crate::policy::compile(&out, None, 0).unwrap_or_else(|e| panic!("{e:?}\n{out}"));
        out
    }

    fn all_comments_kept(out: &str, except: &[&str]) {
        for c in COMMENTS.iter().filter(|c| !except.contains(c)) {
            assert!(out.contains(c), "lost comment {c:?}:\n{out}");
        }
    }

    /// Lines of `b` that are not in `a` and vice versa (a tiny line diff).
    fn changed_lines(a: &str, b: &str) -> (Vec<String>, Vec<String>) {
        let al: Vec<&str> = a.lines().collect();
        let bl: Vec<&str> = b.lines().collect();
        let gone = al
            .iter()
            .filter(|l| !bl.contains(l))
            .map(|l| l.to_string())
            .collect();
        let new = bl
            .iter()
            .filter(|l| !al.contains(l))
            .map(|l| l.to_string())
            .collect();
        (gone, new)
    }

    #[test]
    fn fixture_is_a_valid_policy() {
        crate::policy::compile(COMMENTED, None, 0).unwrap();
    }

    #[test]
    fn push_to_block_list_keeps_comments_and_style() {
        let out = ok(
            COMMENTED,
            &[Edit::Push(
                p(&["always_allowed"]),
                s("com.google.android.calendar"),
            )],
        );
        all_comments_kept(&out, &[]);
        let (gone, new) = changed_lines(COMMENTED, &out);
        assert!(gone.is_empty(), "{gone:?}");
        assert_eq!(new, vec!["  - com.google.android.calendar"]);
        // Right after the last item (and its comment), before the blank line.
        assert!(
            out.contains("# piano: unlimited\n  - com.google.android.calendar\n\n# Never usable."),
            "{out}"
        );
    }

    #[test]
    fn push_to_flow_lists_single_and_multi_line() {
        let out = ok(
            COMMENTED,
            &[Edit::Push(
                p(&["limits", "1", "apps"]),
                s("com.disney.disneyplus"),
            )],
        );
        assert!(out.contains("    apps: [com.netflix.mediaclient, com.google.android.youtube, com.disney.disneyplus]\n"), "{out}");
        all_comments_kept(&out, &[]);
        // Multi-line flow list with a comment inside: appended after the last item.
        let out = ok(
            COMMENTED,
            &[Edit::Push(
                p(&["limits", "2", "exclude"]),
                s("com.amazon.kindle"),
            )],
        );
        all_comments_kept(&out, &[]);
        assert!(
            out.contains("              com.example.flow, com.duolingo, com.amazon.kindle]\n"),
            "{out}"
        );
        // A long last line wraps, aligned with the first item of that line.
        let out = ok(
            COMMENTED,
            &[Edit::Push(
                p(&["limits", "0", "apps"]),
                s("com.example.a.very.long.package.name.for.wrapping"),
            )],
        );
        assert!(
            out.contains("           com.reddit.frontpage, com.facebook.katana,\n           com.example.a.very.long.package.name.for.wrapping]\n"),
            "{out}"
        );
    }

    #[test]
    fn remove_items_from_block_and_flow_lists() {
        let out = ok(
            COMMENTED,
            &[Edit::Set(
                p(&["limits", "2", "exclude"]),
                y("[com.netflix.mediaclient, com.google.android.youtube, com.example.flow]"),
            )],
        );
        all_comments_kept(&out, &[]);
        assert!(out.contains("com.example.flow]\n"), "{out}");
        assert!(!out.contains("com.duolingo]"), "{out}");
        // Removing a block item takes its line and trailing comment only.
        let out = ok(
            COMMENTED,
            &[Edit::Set(
                p(&["always_allowed"]),
                y("[com.google.android.dialer, com.example.piano]"),
            )],
        );
        all_comments_kept(&out, &["# Messages"]);
        let (gone, new) = changed_lines(COMMENTED, &out);
        assert_eq!(
            gone,
            vec!["  - com.google.android.apps.messaging     # Messages"]
        );
        assert!(new.is_empty(), "{new:?}");
        // The last item of a list leaves an explicit [] (the key and the comment above stay).
        let out = ok(COMMENTED, &[Edit::Set(p(&["blocked"]), y("[]"))]);
        assert!(out.contains("# Never usable.\nblocked: []\n"), "{out}");
        let out = ok(
            COMMENTED,
            &[Edit::Set(
                p(&["limits", "1", "apps"]),
                y("[com.netflix.mediaclient]"),
            )],
        );
        assert!(
            out.contains("    apps: [com.netflix.mediaclient]\n"),
            "{out}"
        );
    }

    #[test]
    fn add_keys_where_they_belong() {
        // New top-level key: after the last one (device), in block style.
        let out = ok(
            COMMENTED,
            &[Edit::Set(
                p(&["device", "camera_disabled"]),
                Value::Bool(true),
            )],
        );
        all_comments_kept(&out, &[]);
        let (gone, new) = changed_lines(COMMENTED, &out);
        assert!(gone.is_empty(), "{gone:?}");
        assert_eq!(new, vec!["  camera_disabled: true"]);
        let out = ok(
            COMMENTED,
            &[Edit::Set(
                p(&["device", "wifi_ssids"]),
                y("{allow: [HomeNet, \"École du Centre\"]}"),
            )],
        );
        assert!(
            out.contains("  wifi_ssids: {allow: [HomeNet, \"École du Centre\"]}\n"),
            "{out}"
        );
        // Into a flow mapping.
        let out = ok(
            COMMENTED,
            &[Edit::Set(p(&["limits", "0", "daily", "sun"]), s("1h"))],
        );
        assert!(
            out.contains("daily: {weekdays: 30m, weekend: 45m, sun: 1h}"),
            "{out}"
        );
        // A missing parent is created with the key.
        let bare = "child: kid\ntimezone: UTC\n";
        let out = ok(
            bare,
            &[Edit::Set(
                p(&["device", "hidden"]),
                y("[com.android.chrome]"),
            )],
        );
        assert_eq!(
            out,
            "child: kid\ntimezone: UTC\ndevice:\n  hidden: [com.android.chrome]\n"
        );
    }

    #[test]
    fn set_mapping_keywise_and_scalars() {
        let out = ok(
            COMMENTED,
            &[Edit::Set(
                p(&["limits", "2", "daily"]),
                y("{weekdays: 1h, weekend: 2h}"),
            )],
        );
        assert!(out.contains("daily: {weekdays: 1h, weekend: 2h}"), "{out}");
        let out = ok(
            COMMENTED,
            &[Edit::Set(p(&["limits", "2", "daily"]), y("{default: 40s}"))],
        );
        assert!(out.contains("    daily: {default: 40s}\n"), "{out}");
        let out = ok(
            COMMENTED,
            &[Edit::Set(
                p(&["device", "lock_screen_info"]),
                s("Lost? Call 123"),
            )],
        );
        assert!(
            out.contains("  lock_screen_info: \"Lost? Call 123\"\n"),
            "{out}"
        );
        all_comments_kept(&out, &[]);
        let out = ok(
            COMMENTED,
            &[Edit::Set(p(&["approval"]), Value::Bool(false))],
        );
        assert!(out.contains("\napproval: false\n# Unlimited"), "{out}");
        // Null removes the key (and only its line).
        let out = ok(
            COMMENTED,
            &[Edit::Set(p(&["device", "lock_screen_info"]), Value::Null)],
        );
        let (gone, new) = changed_lines(COMMENTED, &out);
        assert_eq!((gone.len(), new.len()), (1, 0), "{out}");
        all_comments_kept(&out, &[]);
    }

    #[test]
    fn set_list_of_mappings_itemwise() {
        let out = ok(
            COMMENTED,
            &[Edit::Set(
                p(&["downtime"]),
                y(
                    r#"[{start: "22:00", end: "07:00"}, {start: "13:00", end: "14:00", days: [sat, sun], lock_screen: true}]"#,
                ),
            )],
        );
        assert!(
            out.contains("downtime:\n  - {start: \"22:00\", end: \"07:00\"}\n  - {start: \"13:00\", end: \"14:00\", days: [sat, sun], lock_screen: true}\n"),
            "{out}"
        );
        let out = ok(COMMENTED, &[Edit::Set(p(&["downtime"]), y("[]"))]);
        assert!(out.contains("\ndowntime: []\n"), "{out}");
        // A new limit after block-mapping items is a block mapping too.
        let out = ok(
            COMMENTED,
            &[Edit::Push(
                p(&["limits"]),
                y("{name: games, apps: [com.mojang.minecraftpe], daily: {default: 30m}}"),
            )],
        );
        assert!(
            out.contains("    daily: {weekdays: 1h, weekend: 1h30m}\n  - name: games\n    apps: [com.mojang.minecraftpe]\n    daily: {default: 30m}\n\ndevice:"),
            "{out}"
        );
        all_comments_kept(&out, &[]);
    }

    #[test]
    fn replace_keeps_the_given_order() {
        // Set is item-wise ([50, 80] -> [30, 50, 80] would give [50, 80, 30]);
        // Replace writes the list as given (thresholds must be ascending).
        let base = format!("notify: {{}}\n{COMMENTED}");
        let with = ok(
            &base,
            &[Edit::Replace(
                p(&["limits", "1", "notify_at"]),
                y("[50, 80]"),
            )],
        );
        assert!(with.contains("    notify_at: [50, 80]\n"), "{with}");
        let set = apply_verified::<PolicyFile>(
            &with,
            &[Edit::Set(
                p(&["limits", "1", "notify_at"]),
                y("[30, 50, 80]"),
            )],
        )
        .unwrap();
        assert!(set.contains("    notify_at: [50, 80, 30]\n"), "{set}");
        let out = ok(
            &with,
            &[Edit::Replace(
                p(&["limits", "1", "notify_at"]),
                y("[30, 50, 80]"),
            )],
        );
        assert!(out.contains("    notify_at: [30, 50, 80]\n"), "{out}");
        let (gone, new) = changed_lines(&with, &out);
        assert_eq!(
            (gone, new),
            (
                vec!["    notify_at: [50, 80]".to_string()],
                vec!["    notify_at: [30, 50, 80]".to_string()]
            )
        );
        all_comments_kept(&out, &[]);
        // Same value: no-op; [] stays explicit; Null removes the key.
        assert_eq!(
            ok(
                &out,
                &[Edit::Replace(
                    p(&["limits", "1", "notify_at"]),
                    y("[30, 50, 80]")
                )]
            ),
            out
        );
        let none = ok(
            &out,
            &[Edit::Replace(p(&["limits", "1", "notify_at"]), y("[]"))],
        );
        assert!(none.contains("    notify_at: []\n"), "{none}");
        let gone = ok(
            &out,
            &[Edit::Replace(p(&["limits", "1", "notify_at"]), Value::Null)],
        );
        assert!(!gone.contains("notify_at"), "{gone}");
        assert_eq!(gone, base);
    }

    #[test]
    fn overrides_push_remove_and_empty_files() {
        let o = "# Temporary exceptions.\n#   - {lock: true, until: \"2026-10-20T19:00\"}\noverrides: []\n";
        let entry = y(r#"{lock: true, screen: true, until: "2026-10-20T19:00", note: "devoirs"}"#);
        let out =
            apply_verified::<OverridesFile>(o, &[Edit::Push(p(&["overrides"]), entry.clone())])
                .unwrap();
        assert_eq!(
            out,
            "# Temporary exceptions.\n#   - {lock: true, until: \"2026-10-20T19:00\"}\noverrides:\n  - {lock: true, screen: true, until: \"2026-10-20T19:00\", note: devoirs}\n"
        );
        let two = apply_verified::<OverridesFile>(
            &out,
            &[Edit::Push(
                p(&["overrides"]),
                y(r#"{extra: 30m, limit: video, until: "2026-10-24T23:00"}"#),
            )],
        )
        .unwrap();
        assert!(
            two.ends_with(
                "note: devoirs}\n  - {extra: 30m, limit: video, until: \"2026-10-24T23:00\"}\n"
            ),
            "{two}"
        );
        let back =
            apply_verified::<OverridesFile>(&two, &[Edit::Remove(p(&["overrides", "0"]))]).unwrap();
        assert!(
            back.ends_with(
                "overrides:\n  - {extra: 30m, limit: video, until: \"2026-10-24T23:00\"}\n"
            ),
            "{back}"
        );
        let empty = apply_verified::<OverridesFile>(&back, &[Edit::Remove(p(&["overrides", "0"]))])
            .unwrap();
        assert!(
            empty.starts_with("# Temporary exceptions.\n#   - {lock"),
            "{empty}"
        );
        assert!(empty.ends_with("overrides: []\n"), "{empty}");
        // Comment-only and empty files.
        for start in ["", "# nothing yet\n", "overrides:\n"] {
            let out = apply_verified::<Option<OverridesFile>>(
                start,
                &[Edit::Push(p(&["overrides"]), entry.clone())],
            )
            .unwrap();
            assert!(out.ends_with("overrides:\n  - {lock: true, screen: true, until: \"2026-10-20T19:00\", note: devoirs}\n"), "{start:?} -> {out}");
            assert!(
                out.starts_with(start.trim_end_matches("overrides:\n")),
                "{out}"
            );
        }
        // Flow list with existing entries stays flow.
        let f = "overrides: [{lock: true, until: \"2026-10-20T19:00\"}]\n";
        let out = apply_verified::<OverridesFile>(
            f,
            &[Edit::Push(
                p(&["overrides"]),
                y(r#"{unlock: true, until: "2026-10-21T19:00"}"#),
            )],
        )
        .unwrap();
        assert_eq!(
            out,
            "overrides: [{lock: true, until: \"2026-10-20T19:00\"}, {unlock: true, until: \"2026-10-21T19:00\"}]\n"
        );
    }

    #[test]
    fn scalars_are_quoted_when_needed() {
        for (v, want) in [
            ("com.a.b", "com.a.b"),
            ("30m", "30m"),
            ("1h30m", "1h30m"),
            ("0", "\"0\""),
            ("22:00", "\"22:00\""),
            ("*", "\"*\""),
            ("yes", "\"yes\""),
            ("null", "\"null\""),
            ("École", "\"École\""),
            ("a b", "\"a b\""),
            ("say \"hi\"\n", "\"say \\\"hi\\\"\\n\""),
            ("2026-10-20", "\"2026-10-20\""),
            ("-x", "\"-x\""),
        ] {
            assert_eq!(scalar_str(v), want, "{v}");
            let back: String = serde_yaml_ng::from_str(&scalar_str(v)).unwrap();
            assert_eq!(back, v);
        }
    }

    #[test]
    fn invalid_changes_are_reported_as_such() {
        // Unknown device field: the typed model refuses it, nothing is edited.
        let e = apply_verified::<PolicyFile>(
            COMMENTED,
            &[Edit::Set(
                p(&["device", "no_such_field"]),
                Value::Bool(true),
            )],
        )
        .unwrap_err();
        assert!(
            matches!(&e, EditError::Invalid(m) if m.contains("unknown field")),
            "{e:?}"
        );
        let e = apply_verified::<PolicyFile>(
            COMMENTED,
            &[Edit::Set(p(&["device", "camera_disabled"]), s("maybe"))],
        )
        .unwrap_err();
        assert!(matches!(e, EditError::Invalid(_)), "{e:?}");
        let e = apply_verified::<PolicyFile>(COMMENTED, &[Edit::Push(p(&["child"]), s("x"))])
            .unwrap_err();
        assert!(
            matches!(&e, EditError::Invalid(m) if m.contains("not a list")),
            "{e:?}"
        );
        let e = apply_verified::<PolicyFile>(
            "child: [unclosed\n",
            &[Edit::Set(p(&["approval"]), Value::Bool(true))],
        )
        .unwrap_err();
        assert!(matches!(e, EditError::Invalid(_)), "{e:?}");
    }

    #[test]
    fn unchanged_value_is_a_noop() {
        let out = ok(COMMENTED, &[Edit::Set(p(&["approval"]), Value::Bool(true))]);
        assert_eq!(out, COMMENTED);
        let out = ok(
            COMMENTED,
            &[Edit::Set(p(&["blocked"]), y("[com.zhiliaoapp.musically]"))],
        );
        assert_eq!(out, COMMENTED);
    }

    #[test]
    fn every_edit_on_the_spec_policy() {
        // The repo's reference policy (block and flow styles, comments).
        let spec = include_str!("../spec/vectors-policy.yaml");
        let out = ok(
            spec,
            &[
                Edit::Push(p(&["approved"]), s("com.duolingo")),
                Edit::Push(p(&["blocked"]), s("com.android.chrome")),
                Edit::Set(
                    p(&["device", "hidden"]),
                    y("[com.google.android.deskclock]"),
                ),
                Edit::Set(p(&["device", "organization_name"]), s("Famille")),
                Edit::Set(p(&["device", "wifi_ssids"]), y("{deny: [Hotspot]}")),
                Edit::Set(p(&["device", "default_apps", "browser"]), Value::Null),
                Edit::Set(p(&["downtime"]), y(r#"[{start: "22:00", end: "07:00"}]"#)),
            ],
        );
        assert!(out.contains("approved: [com.duolingo]\n"), "{out}");
        assert!(out.contains("  wifi_ssids: {deny: [Hotspot]}\n"), "{out}");
        assert!(
            out.contains("  default_apps: {launcher: com.google.android.apps.nexuslauncher}\n"),
            "{out}"
        );
        assert!(out.contains("# Rules of a fictional child, Alex."), "{out}");
        assert!(!out.contains("lock_screen: true"), "{out}");
    }

    /// The CST node of a block list spans the comments after it (checked
    /// here, the reason for `content_end`): removing or replacing a block
    /// value must leave the comments that follow it, which introduce the
    /// next key.
    #[test]
    fn block_values_end_before_the_comments_after_them() {
        let d = Document::new(COMMENTED.to_string()).unwrap();
        let f = d.query_exact(&route(&p(&["downtime"]))).unwrap().unwrap();
        assert!(
            COMMENTED[f.location.byte_span.0..f.location.byte_span.1]
                .ends_with("# Never limited, usable during downtime.")
        );
        let cur = parse(COMMENTED).unwrap();
        let e = content_end(&d, &cur, &p(&["downtime"])).unwrap();
        assert!(COMMENTED[..e].ends_with("{start: \"22:00\", end: \"07:00\"}"));
        // Remove whole block-valued keys: only their own lines go.
        for (k, own) in [
            ("downtime", vec![]),
            (
                "always_allowed",
                vec!["# Phone", "# Messages", "# piano: unlimited"],
            ),
            ("approved", vec!["# flow (piano)", "# Duolingo"]),
            ("blocked", vec!["# TikTok"]),
        ] {
            let out = text_apply(COMMENTED, &Edit::Remove(p(&[k]))).unwrap();
            assert!(!out.contains(&format!("\n{k}:")), "{out}");
            let (gone, new) = changed_lines(COMMENTED, &out);
            assert!(new.is_empty(), "{k}: {new:?}");
            for g in &gone {
                assert!(
                    !g.trim_start().starts_with('#'),
                    "{k}: removed a comment line {g:?}"
                );
            }
            all_comments_kept(&out, &own);
        }
        // Replacing a block list (with trailing comments) by [] keeps them.
        let out = text_apply(
            COMMENTED,
            &Edit::Set(p(&["device", "restrictions"]), y("[]")),
        )
        .unwrap();
        assert!(out.contains("  restrictions: []\n    # Enable once the account is added:\n    # - no_modify_accounts\n"), "{out}");
        let out = text_apply(COMMENTED, &Edit::Set(p(&["downtime"]), y("[]"))).unwrap();
        assert!(
            out.contains(
                "downtime: []\n\n# Never limited, usable during downtime.\nalways_allowed:"
            ),
            "{out}"
        );
        // A new key after a block list with trailing comments goes after the
        // list's last item (before the comments).
        let out = ok(
            COMMENTED,
            &[Edit::Set(
                p(&["device", "restrictions"]),
                y("[no_factory_reset, no_safe_boot, no_add_user]"),
            )],
        );
        assert!(
            out.contains("    - no_safe_boot\n    - no_add_user\n    # Enable once"),
            "{out}"
        );
        // Removing the first key of a `- key: v` item keeps the dash.
        let out = text_apply(COMMENTED, &Edit::Remove(p(&["limits", "1", "name"]))).unwrap();
        assert!(
            out.contains(
                "  - apps: [com.netflix.mediaclient, com.google.android.youtube]\n    daily: {fri"
            ),
            "{out}"
        );
        // The only key of a nested block mapping removes the mapping's key.
        let t = "child: kid\ntimezone: UTC\ndevice:\n  hidden: [com.a.b]\n# end\n";
        let out = ok(t, &[Edit::Set(p(&["device", "hidden"]), Value::Null)]);
        assert_eq!(out, "child: kid\ntimezone: UTC\n# end\n");
    }

    #[test]
    fn replace_downtime_window_keeps_following_comment() {
        let w = y(r#"[{start: "13:00", end: "14:00", days: [sat], lock_screen: true}]"#);
        let out = ok(COMMENTED, &[Edit::Set(p(&["downtime"]), w)]);
        all_comments_kept(&out, &[]);
        assert!(
            out.contains("downtime:\n  - {start: \"13:00\", end: \"14:00\", days: [sat], lock_screen: true}\n\n# Never limited"),
            "{out}"
        );
    }
}
