use colored::*;

pub struct GrimoireTable {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    col_widths: Vec<usize>,
}

impl GrimoireTable {
    pub fn new(headers: Vec<&str>) -> Self {
        let widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
        Self {
            headers: headers.iter().map(|s| s.to_string()).collect(),
            rows: Vec::new(),
            col_widths: widths,
        }
    }

    pub fn add_row(&mut self, row: Vec<String>) {
        for (i, cell) in row.iter().enumerate() {
            if i < self.col_widths.len() {
                self.col_widths[i] = self.col_widths[i].max(cell.len());
            }
        }
        self.rows.push(row);
    }

    pub fn print(&self) {
        let sep = self.separator();
        println!("{}", sep);
        let header_row: Vec<String> = self.headers.iter().enumerate()
            .map(|(i, h)| format!(" {:width$} ", h, width = self.col_widths[i]))
            .collect();
        println!("|{}|", header_row.join("|").bold());
        println!("{}", sep);
        for row in &self.rows {
            let cells: Vec<String> = (0..self.headers.len())
                .map(|i| {
                    let cell = row.get(i).map(|s| s.as_str()).unwrap_or("");
                    format!(" {:width$} ", cell, width = self.col_widths[i])
                })
                .collect();
            println!("|{}|", cells.join("|"));
        }
        println!("{}", sep);
    }

    fn separator(&self) -> String {
        let parts: Vec<String> = self.col_widths.iter()
            .map(|&w| "-".repeat(w + 2))
            .collect();
        format!("+{}+", parts.join("+"))
    }
}

pub fn print_banner(text: &str) {
    println!("{}", format!("\n[*] {}", text).cyan());
}

pub fn print_success(text: &str) {
    println!("{}", format!("[+] {}", text).green());
}

pub fn print_warning(text: &str) {
    println!("{}", format!("[!] {}", text).yellow());
}

pub fn print_error(text: &str) {
    eprintln!("{}", format!("[-] {}", text).red());
}

pub fn print_info(key: &str, value: &str) {
    println!("  {}: {}", key.bold(), value);
}

pub fn print_hex_dump(label: &str, data: &[u8]) {
    println!("  {}:", label.bold());
    for chunk in data.chunks(16) {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        let ascii: String = chunk.iter().map(|&b| if b.is_ascii_graphic() { b as char } else { '.' }).collect();
        println!("    {:<48}  {}", hex.join(" "), ascii);
    }
}
