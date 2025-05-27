use colored::*;
use enable_ansi_support;
use rand::Rng;
use std::io::Write;
use std::process::Command;
use std::{env, fs, io, path::Path, process};
use term_size;
use winreg::enums::*;
use winreg::RegKey;

#[derive(Debug)]
struct NetworkAdapter { // god i love pasting
    id: String,
    description: String,
    connection_name: String,
}

fn main() {
    if cfg!(windows) {
        if let Err(e) = enable_ansi_support::enable_ansi_support() {
            eprintln!("{} Failed to enable ANSI support: {:?}", "[!]".yellow(), e);
        }
    }
    colored::control::set_override(true);

    let title = "ByeBanAsync v2.2 | centerepic";
    let title_with_prefix = format!("{} {}", "[?]".blue(), title);
    let terminal_width = term_size::dimensions().map(|(w, _)| w).unwrap_or(80);

    let title_display_length = title.len() + "[?] ".len();
    if title_display_length < terminal_width {
        let padding = (terminal_width - title_display_length) / 2;
        println!("{}{}{}", " ".repeat(padding), title_with_prefix, "\n");
    } else {
        println!("{}{}", title_with_prefix, "\n");
    }

    println!(
        "{} Ensure you are logged out of the banned account before running this program!",
        "[!]".yellow()
    );

    let user_profile = match env::var("USERPROFILE") {
        Ok(val) => val,
        Err(_) => {
            println!(
                "{} Could not get USERPROFILE environment variable.",
                "[!!!]".red()
            );
            exit_program();
            return;
        }
    };
    let cookie_path =
        Path::new(&user_profile).join("AppData/Local/Roblox/LocalStorage/RobloxCookies.dat");

    if !cookie_path.exists() {
        println!(
            "{} Roblox cookie file not found at {:?}!",
            "[!!!]".red(),
            cookie_path
        );
    } else {
        if let Err(msg) = fs::remove_file(&cookie_path) {
            println!(
                "{} Failed to delete Roblox cookie file! Err: {:?}",
                "[!!!]".red(),
                msg
            );
        } else {
            println!("{} Roblox cookie file has been deleted!", "[√]".green());
        }
    }

    // MAC address stuff
    println!("\n{}", "--- MAC Address Spoofing ---".bold().purple());
    print!(
        "{} Do you want to attempt to change your MAC address? (y/n): ",
        "[?]".cyan()
    );
    io::stdout().flush().unwrap();

    let mut change_mac_choice = String::new();
    io::stdin().read_line(&mut change_mac_choice).unwrap();

    if change_mac_choice.trim().eq_ignore_ascii_case("y") {
        match list_network_adapters() {
            Ok(adapters) => {
                if adapters.is_empty() {
                    println!(
                        "{} No suitable network adapters found to modify.",
                        "[!]".yellow()
                    );
                } else {
                    println!("\n{} Available network adapters:", "[i]".blue());
                    for (i, adapter) in adapters.iter().enumerate() {
                        println!(
                            "  {}{}{}: {}",
                            "[".bold(),
                            (i + 1).to_string().bold().cyan(),
                            "]".bold(),
                            adapter.description.italic()
                        );
                        println!(
                            "     └─ Connection Name: '{}'",
                            adapter.connection_name.dimmed()
                        );
                    }

                    let selected_adapter = loop {
                        print!(
                            "\n{} Enter the number of the adapter to change: ",
                            "[?]".cyan()
                        );
                        io::stdout().flush().unwrap(); // flush is now available
                        let mut input = String::new();
                        io::stdin().read_line(&mut input).unwrap();
                        match input.trim().parse::<usize>() {
                            Ok(num) if num > 0 && num <= adapters.len() => {
                                break &adapters[num - 1];
                            }
                            _ => {
                                println!(
                                    "{} Invalid selection. Please enter a number from the list.",
                                    "[!]".red()
                                );
                            }
                        }
                    };

                    let random_mac = generate_random_mac_address();
                    println!(
                        "{} Attempting to set MAC for adapter: '{}' (ID: {})...",
                        "[>]".magenta(),
                        selected_adapter.description.italic(),
                        selected_adapter.id
                    );

                    match change_mac_address(&selected_adapter.id, &random_mac) {
                        Ok(_) => {
                            println!(
                                "{} Successfully updated registry for MAC address.",
                                "[√]".green()
                            );
                            println!(
                                "{} Attempting to restart network adapter '{}' to apply changes...",
                                "[>]".magenta(),
                                selected_adapter.connection_name.italic()
                            );
                            if let Err(e) =
                                restart_network_adapter(&selected_adapter.connection_name)
                            {
                                eprintln!("{} Error restarting network adapter: {}. You may need to do this manually or reboot.", "[!!!]".red(), e);
                            } else {
                                println!("{} Network adapter '{}' restarted. MAC address change should now be active.", "[√]".green(), selected_adapter.connection_name.italic());
                                println!(
                                    "{} Verify with 'ipconfig /all' or 'getmac'.",
                                    "[i]".blue()
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "{} Error changing MAC address in registry: {}",
                                "[!!!]".red(),
                                e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                println!("{} Error listing network adapters: {}", "[!!!]".red(), e);
            }
        }
    } else {
        println!("{} Skipping MAC address change.", "[i]".blue());
    }

    exit_program();
}

fn exit_program() {
    println!("\n{} Press Enter to exit...", "[...]".dimmed());
    let _ = io::stdin().read_line(&mut String::new());
    process::exit(0);
}

fn generate_random_mac_address() -> String {
    let mut rng = rand::rng();
    let mut mac_bytes: [u8; 6] = [0; 6];

    // Has to be 02 so wireless adapters work. No idea why, but TMAC said so.
    mac_bytes[0] = 0x02;

    for i in 1..6 {
        mac_bytes[i] = rng.random::<u8>();
    }

    mac_bytes
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<String>>()
        .join("")
}

fn list_network_adapters() -> io::Result<Vec<NetworkAdapter>> {
    let mut adapters = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let class_key_path =
        r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
    let class_key = hklm.open_subkey(class_key_path)?;

    for i in 0.. {
        let subkey_name = format!("{:04}", i);
        match class_key.open_subkey(&subkey_name) {
            Ok(adapter_key) => {
                if let Ok(driver_desc) = adapter_key.get_value::<String, _>("DriverDesc") {
                    if let Ok(net_cfg_instance_id) =
                        adapter_key.get_value::<String, _>("NetCfgInstanceID")
                    {
                        let connection_name_path = format!( // y is ts the only way to get it
                            r"SYSTEM\CurrentControlSet\Control\Network\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\{}\Connection",
                            net_cfg_instance_id
                        );
                        let connection_name = hklm.open_subkey(connection_name_path)
                            .and_then(|conn_key| conn_key.get_value::<String, _>("Name"))
                            .unwrap_or_else(|_| {
                                println!("{} Could not find friendly 'Name' for adapter '{}' (ID: {}). Using DriverDesc as fallback.", "[!]".yellow(), driver_desc, subkey_name);
                                driver_desc.clone()
                            });

                        let lower_desc = driver_desc.to_lowercase(); // why so many pasted adapters
                        if !lower_desc.contains("virtual")
                            && !lower_desc.contains("loopback")
                            && !lower_desc.contains("bluetooth")
                            && !lower_desc.contains("wan miniport")
                            && !lower_desc.contains("tap-windows")
                            && !lower_desc.contains("pseudo")
                        {
                            adapters.push(NetworkAdapter {
                                id: subkey_name.clone(),
                                description: driver_desc,
                                connection_name,
                            });
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                break;
            }
            Err(e) => {
                eprintln!(
                    "{} Error reading adapter subkey {}: {}",
                    "[!]".yellow(),
                    subkey_name,
                    e
                );
            }
        }
    }
    Ok(adapters)
}

fn change_mac_address(adapter_id: &str, mac_address: &str) -> io::Result<()> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let path = format!(
        r"SYSTEM\CurrentControlSet\Control\Class\{{4d36e972-e325-11ce-bfc1-08002be10318}}\{}",
        adapter_id
    );

    let adapter_key = hklm.open_subkey_with_flags(&path, KEY_WRITE)?;

    println!(
        "{} Setting 'NetworkAddress' to '{}'",
        "[>]".dimmed(),
        mac_address
    );
    adapter_key.set_value("NetworkAddress", &mac_address)?;
    Ok(())
}

fn restart_network_adapter(adapter_connection_name: &str) -> io::Result<()> {
    println!(
        "{} Disabling adapter: '{}'",
        "[>]".dimmed(),
        adapter_connection_name
    );
    let disable_output = Command::new("netsh")
        .args([
            "interface",
            "set",
            "interface",
            "name=",
            adapter_connection_name,
            "admin=disable",
        ])
        .output()?;

    if !disable_output.status.success() {
        let error_message = String::from_utf8_lossy(&disable_output.stderr);
        eprintln!(
            "{} Failed to disable network adapter. Netsh output: {}",
            "[!!!]".red(),
            error_message.trim()
        );
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to disable network adapter: {}", error_message),
        ));
    }

    std::thread::sleep(std::time::Duration::from_secs(2));

    println!(
        "{} Enabling adapter: '{}'",
        "[>]".dimmed(),
        adapter_connection_name
    );
    let enable_output = Command::new("netsh")
        .args([
            "interface",
            "set",
            "interface",
            "name=",
            adapter_connection_name,
            "admin=enable",
        ])
        .output()?;

    if !enable_output.status.success() {
        let error_message = String::from_utf8_lossy(&enable_output.stderr);
        eprintln!(
            "{} Failed to enable network adapter. Netsh output: {}",
            "[!!!]".red(),
            error_message.trim()
        );
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to enable network adapter: {}", error_message),
        ));
    }
    Ok(())
}
