pub const VERSION: &str = "0.1.0";

pub fn print_banner() {
    println!(r#"
  ______     _ _ _   _   _                     _     _
 |  ____|   (_) | | | | | |                   (_)   | |
 | |__  __  ___| | | | |_| | __ _  __ _ _ __ _  __| |
 |  __| \ \/ / | | |  _  |/ _` |/ _` | '__| |/ _` |
 | |____ >  <| | | | | | | (_| | (_| | |  | | (_| |
 |______/_/\_\_|_| |_| |_|\__,_|\__, |_|  |_|\__,_|
                                   __/ |
                                  |___/

  EvilHagrid v{} — Kerberos Interaction & Manipulation
  For authorized security research and lab use only
"#, VERSION);
}
