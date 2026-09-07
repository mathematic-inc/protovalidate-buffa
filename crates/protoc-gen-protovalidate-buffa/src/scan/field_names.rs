//! Match buffa 0.9's private `field_names` planner and insertion-only converter.
//!
//! Source: <https://github.com/anthropics/buffa/blob/v0.9.1/buffa-codegen/src/field_names.rs>.
//! Exceptions are shared across the entire descriptor set by (name, number),
//! including imports. Verbatim fallback takes precedence over a numbered suffix.
//! Keep this in step with buffa upgrades; the conformance fixtures compile both
//! generators' output together to detect drift. Proto names remain untouched.

use std::collections::{HashMap, HashSet};

use buffa_codegen::generated::descriptor::{DescriptorProto, FileDescriptorProto};

use super::MessageValidators;

#[derive(Default)]
pub(super) struct FieldNames {
    /// Field exceptions before Rust keyword escaping.
    fields: HashMap<(String, i32), String>,
    /// Oneof names whose conversion collides anywhere in the request.
    verbatim_oneofs: HashSet<String>,
}

impl FieldNames {
    pub(super) fn new(files: &[FileDescriptorProto]) -> Self {
        let mut names = Self::default();
        for file in files {
            for message in &file.message_type {
                names.plan_message(message);
            }
        }
        names
    }

    fn plan_message(&mut self, message: &DescriptorProto) {
        if message
            .options
            .as_option()
            .is_some_and(|o| o.map_entry == Some(true))
        {
            return;
        }
        for nested in &message.nested_type {
            self.plan_message(nested);
        }

        // Real oneof variants do not occupy the struct's field namespace.
        // Proto3 optional fields do; their synthetic oneofs do not.
        let mut real_oneofs = HashSet::new();
        let mut members = Vec::new();
        for field in &message.field {
            let Some(name) = field.name.as_deref() else {
                continue;
            };
            if let Some(index) = field.oneof_index
                && !field.proto3_optional.unwrap_or(false)
            {
                real_oneofs.insert(index);
                continue;
            }
            members.push((name, Some(field.number.unwrap_or(0)), snake_case(name)));
        }
        for (index, oneof) in message.oneof_decl.iter().enumerate() {
            if real_oneofs.contains(&(index as i32))
                && let Some(name) = oneof.name.as_deref()
            {
                members.push((name, None, snake_case(name)));
            }
        }

        let mut counts = HashMap::new();
        for (_, _, converted) in &members {
            *counts.entry(converted.as_str()).or_insert(0usize) += 1;
        }
        let mut finals: Vec<String> = members
            .iter()
            .map(|(name, number, converted)| {
                if counts[converted.as_str()] > 1 && converted != name {
                    number.map_or_else(|| (*name).to_string(), |n| format!("{converted}_f{n}"))
                } else {
                    converted.clone()
                }
            })
            .collect();

        // A suffix may collide with a literal name. Buffa then reverts EVERY
        // changed member of this message, including unrelated conversions.
        if finals.iter().collect::<HashSet<_>>().len() != finals.len() {
            for ((name, _, converted), resolved) in members.iter().zip(&mut finals) {
                if converted != name {
                    *resolved = (*name).to_string();
                }
            }
        }
        for ((name, number, converted), resolved) in members.into_iter().zip(finals) {
            if resolved == converted {
                continue;
            }
            if let Some(number) = number {
                let entry = self
                    .fields
                    .entry((name.to_string(), number))
                    .or_insert_with(|| resolved.clone());
                if resolved == name {
                    *entry = resolved;
                }
            } else {
                self.verbatim_oneofs.insert(name.to_string());
            }
        }
    }

    pub(super) fn apply(&self, message: &mut MessageValidators) {
        for field in message.field_rules.iter_mut().chain(
            message
                .oneof_rules
                .iter_mut()
                .flat_map(|oneof| &mut oneof.fields),
        ) {
            field.rust_name = self
                .fields
                .get(&(field.field_name.clone(), field.field_number))
                .cloned()
                .unwrap_or_else(|| snake_case(&field.field_name));
        }
        for oneof in &mut message.oneof_rules {
            oneof.rust_name = if self.verbatim_oneofs.contains(&oneof.name) {
                oneof.name.clone()
            } else {
                snake_case(&oneof.name)
            };
        }
    }
}

fn snake_case(name: &str) -> String {
    let mut chars = name.chars().peekable();
    let mut result = String::with_capacity(name.len());
    let mut last_cased: Option<char> = None;
    while let Some(c) = chars.next() {
        if c == '_' {
            last_cased = None;
            result.push(c);
            continue;
        }
        if c.is_uppercase()
            && last_cased.is_some_and(|previous| {
                previous.is_lowercase() || chars.peek().is_some_and(|next| next.is_lowercase())
            })
        {
            result.push('_');
        }
        result.extend(c.to_lowercase());
        if c.is_lowercase() || c.is_uppercase() {
            last_cased = Some(c);
        }
    }
    result
}
