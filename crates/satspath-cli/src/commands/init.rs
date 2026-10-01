use anyhow::Result;
use std::fs;

use super::satspath_dir;

pub fn cmd_init() -> Result<()> {
    let dir = satspath_dir();
    fs::create_dir_all(&dir)?;

    let registry_path = dir.join("registry.json");
    if !registry_path.exists() {
        fs::write(&registry_path, "{\"profiles\":{}}")?;
        println!("Created {}", registry_path.display());
    } else {
        println!("Registry already exists at {}", registry_path.display());
    }

    println!();
    println!("SatsPath initialized at {}/", dir.display());
    println!("NOTE: .satspath/ is git-ignored and stays local to this machine.");
    Ok(())
}
