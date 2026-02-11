use pulldown_cmark::{html, Options, Parser};
use std::fs;
use std::io::Write;
use std::path::Path;

/// Ordered list of doc files to render.
const DOC_FILES: &[&str] = &[
    "overview.md",
    "installation.md",
    "configuration.md",
    "security.md",
    "roles-and-access-control.md",
    "integrations.md",
    "netbox.md",
    "api.md",
];

fn main() {
    println!("cargo::rerun-if-changed=docs/");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("docs-rendered.rs");
    let mut out = fs::File::create(&out_path).expect("Failed to create docs-rendered.rs");

    writeln!(out, "pub const DOCS: &[(&str, &str, &str)] = &[").unwrap();

    for filename in DOC_FILES {
        let path = Path::new("docs").join(filename);
        let md = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("cargo:warning=Could not read {}: {}", path.display(), e);
                continue;
            }
        };

        // Derive slug from filename (strip .md)
        let slug = filename.trim_end_matches(".md");

        // Extract title from first # heading
        let title = md
            .lines()
            .find(|l| l.starts_with("# "))
            .map(|l| l.trim_start_matches("# ").trim())
            .unwrap_or(slug);

        // Render markdown to HTML
        let opts =
            Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
        let parser = Parser::new_ext(&md, opts);
        let mut html_output = String::new();
        html::push_html(&mut html_output, parser);

        // Escape for Rust string literal
        let escaped = html_output
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "");

        let title_escaped = title.replace('\\', "\\\\").replace('"', "\\\"");

        writeln!(out, "    (\"{slug}\", \"{title_escaped}\", \"{escaped}\"),").unwrap();
    }

    writeln!(out, "];").unwrap();
}
