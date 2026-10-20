mod about;
mod dungeon;
mod incantation;
mod spell_book;
mod spells;

use incantation::ParsedIncantation;
use spell_book::SpellBook;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    about::print_banner();

    if args.is_empty() || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
        SpellBook::new().print_help();
        std::process::exit(0);
    }

    let parsed = match ParsedIncantation::parse(&args) {
        Ok(p) => p,
        Err(e) => {
            dungeon::display_charm::print_error(&format!("Argument parse error: {}", e));
            SpellBook::new().print_help();
            std::process::exit(1);
        }
    };

    if parsed.debug {
        eprintln!("[DEBUG] command={} args={:?}", parsed.command, parsed.args);
    }

    let book = SpellBook::new();
    match book.cast(&parsed.command, &parsed.args) {
        Ok(()) => {}
        Err(e) => {
            dungeon::display_charm::print_error(&format!("{}", e));
            std::process::exit(1);
        }
    }
}
