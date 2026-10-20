use anyhow::{bail, Result};
use std::collections::HashMap;

#[derive(Debug)]
pub struct ParsedIncantation {
    pub command: String,
    pub args:    HashMap<String, String>,
    pub flags:   Vec<String>,
    pub nowrap:  bool,
    pub debug:   bool,
}

impl ParsedIncantation {
    pub fn parse(argv: &[String]) -> Result<Self> {
        if argv.is_empty() {
            bail!("no incantation supplied");
        }
        let command = argv[0].to_ascii_lowercase();
        let mut args  = HashMap::new();
        let mut flags = Vec::new();
        let mut nowrap = false;
        let mut debug  = false;

        let mut i = 1;
        while i < argv.len() {
            let token = &argv[i];
            if token == "/nowrap" || token == "--nowrap" {
                nowrap = true;
            } else if token == "/debug" || token == "--debug" {
                debug = true;
            } else if let Some(kv) = strip_slash(token) {
                if let Some(sep) = kv.find(':') {
                    let key = kv[..sep].to_ascii_lowercase();
                    let val = kv[sep + 1..].to_owned();
                    if val.is_empty() && i + 1 < argv.len() && !argv[i + 1].starts_with('/') {
                        // value is next token
                        i += 1;
                        args.insert(key, argv[i].clone());
                    } else {
                        args.insert(key, val);
                    }
                } else {
                    flags.push(kv.to_ascii_lowercase());
                    args.insert(kv.to_ascii_lowercase(), String::new());
                }
            }
            i += 1;
        }
        Ok(Self { command, args, flags, nowrap, debug })
    }
}

fn strip_slash(s: &str) -> Option<&str> {
    if s.starts_with('/') {
        Some(&s[1..])
    } else if s.starts_with("--") {
        Some(&s[2..])
    } else {
        None
    }
}
