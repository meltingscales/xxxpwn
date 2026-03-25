use std::collections::HashSet;
use std::sync::atomic::AtomicU64;

use crossbeam_channel::{Receiver, Sender};

pub const BAD_CHAR: char = '?';
pub const COUNT_OPTIMIZE: usize = 30;
pub const ROOT_NODE: &str = "/*[1]";

/// Python's string.printable minus \x0b and \x0c
pub const DEFAULT_CHARSET: &str =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r";

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Config {
    pub case_sensitive: bool,
    pub urlencode: bool,
    pub htmlencode: bool,
    pub use_ssl: bool,
    pub inject_content: String,
    pub match_pattern: String,
    pub host: String,
    pub port: u16,
    pub verbose_attack: bool,
    pub summary: bool,
    pub no_root: bool,
    pub no_comments: bool,
    pub no_processor: bool,
    pub no_attributes: bool,
    pub no_values: bool,
    pub no_text: bool,
    pub no_child: bool,
    pub use_lowercase: bool,
    pub global_count: bool,
    pub normalize_space: bool,
    pub optimize_charset: bool,
    pub xml_match: bool,
    pub len_low: i64,
    pub len_high: i64,
    pub start_node: String,
    pub character_set: String,
    pub threads: usize,
    pub xpath2: bool,
    pub search: Option<String>,
    pub search_start: bool,
}

pub struct CharJob {
    pub node: String,
    pub position: usize,
    pub chars: String,
}

pub struct CharResult {
    pub position: usize,
    pub ch: char,
}

pub struct AttackCtx {
    pub config: Config,
    pub request_count: AtomicU64,
    pub thread_tx: Option<Sender<CharJob>>,
    pub result_rx: Option<Receiver<CharResult>>,
}

pub struct XmlState {
    pub root_nodes: i64,
    pub root_comments: i64,
    pub root_instructions: i64,
    pub nodes_total: i64,
    pub attributes_total: i64,
    pub comments_total: i64,
    pub instructions_total: i64,
    pub text_total: i64,
    pub elements_total: i64,
    pub node_names: HashSet<String>,
    pub attribute_names: HashSet<String>,
}

impl Default for XmlState {
    fn default() -> Self {
        XmlState {
            root_nodes: -1,
            root_comments: -1,
            root_instructions: -1,
            nodes_total: -1,
            attributes_total: -1,
            comments_total: -1,
            instructions_total: -1,
            text_total: -1,
            elements_total: -1,
            node_names: HashSet::new(),
            attribute_names: HashSet::new(),
        }
    }
}
