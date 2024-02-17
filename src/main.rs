use std::io;
use std::path::Path;

use clap::{Arg, Command};

use winreg::enums::*;
use winreg::RegKey;

fn main() -> io::Result<()> {
    // Parse command line arguments
    const PWR_ARG: &str = "power";
    const MON_ARG: &str = "monitor";
    let cmd = Command::new("chgpwrdsp")
        .subcommand_required(true)
        .subcommand(Command::new("list").about("List available power and monitor profiles"))
        .subcommand(
            Command::new("set")
                .about("Set power and monitor profiles")
                .arg_required_else_help(true)
                .arg(
                    Arg::new(PWR_ARG)
                        .help("Power profile to set")
                        .short('p')
                        .long("power")
                        .action(clap::ArgAction::Set),
                )
                .arg(
                    Arg::new(MON_ARG)
                        .help("Monitor profile to set")
                        .short('m')
                        .long("monitor")
                        .action(clap::ArgAction::Set),
                ),
        );

    let matches = cmd.get_matches();

    match matches.subcommand() {
        Some(("list", _)) => print_profiles()?,
        Some(("set", sub_matches)) => {
            // Set power
            let arg_pwr: &str;
            let arg_pwr_opt = sub_matches.try_get_one::<String>(PWR_ARG);
            if let Ok(Some(p)) = arg_pwr_opt {
                arg_pwr = p;
            } else {
                arg_pwr = "";
            }
            let spwr = set_power_profile(arg_pwr);
            if spwr.is_err() {
                println!("{}", spwr.unwrap_err());
            }

            // Set monitor profile
            let arg_mon: &str;
            let arg_mon_opt = sub_matches.try_get_one::<String>(MON_ARG);
            if let Ok(Some(p)) = arg_mon_opt {
                arg_mon = p;
            } else {
                arg_mon = "";
            }
            let smon = set_monitor_profile(arg_mon);
            if smon.is_err() {
                println!("{}", smon.unwrap_err());
            }
        }
        _ => unreachable!(),
    }

    Ok(())
}

// Set displayFusion
// "C:\Program Files\DisplayFusion\DisplayFusionCommand.exe" -monitorloadprofile "<profile
// name>"
fn set_monitor_profile(profile: &str) -> io::Result<()> {
    if profile.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "No monitor profile given",
        ));
    }
    let profiles = df_monitor_profiles()?;
    let mut profile_found = false;
    for prof in profiles.iter() {
        if prof == profile {
            profile_found = true;
            break;
        }
    }
    if !profile_found {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Monitor profile not found",
        ));
    }
    println!("Setting monitor profile to: '{}'", profile);

    // DisplayFusionCommand.exe isn't typically in the path
    const DF_CMD: &str = r#"C:\Program Files\DisplayFusion\DisplayFusionCommand.exe"#;
    let mut cmd = std::process::Command::new(DF_CMD);
    let opts = ["-monitorloadprofile", profile];
    let cmd = cmd.args(opts);

    let status = cmd.status();
    if status.is_err() {
        Err(io::Error::new(io::ErrorKind::Other, status.err().unwrap()))
    } else if !status.unwrap().success() {
        let output = cmd.output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        let err_msg = format!("Error setting monitor profile: {}", stderr);
        Err(io::Error::new(io::ErrorKind::Other, err_msg))
    } else {
        Ok(())
    }
}

fn find_power_profile_by_name<'a>(
    profile_name: &'a str,
    profiles: &'a Vec<PowerProfile>,
) -> Option<&'a PowerProfile> {
    for p in profiles.iter() {
        if p.name.as_str() == profile_name {
            return Some(p);
        }
    }
    None
}

fn set_power_profile(profile: &str) -> io::Result<()> {
    // run the `powercfg /S` comand
    if profile.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "No power profile given",
        ));
    }
    let profiles = power_profiles()?;
    let p_opt = find_power_profile_by_name(profile, &profiles);
    if p_opt.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Power profile not found",
        ));
    }
    let p = p_opt.unwrap();
    if p.active {
        println!("Power profile already set to: '{}'/{}", profile, p.guid);
        return Ok(());
    }
    println!("Setting power profile to: '{}'/{}", profile, p.guid);

    let opts = ["/S", &p.guid.to_string()];
    let mut cmd = std::process::Command::new("powercfg");
    let cmd = cmd.args(opts);

    let status = cmd.status();
    // let stdout = String::from_utf8_lossy(&output.stdout);
    if status.is_err() {
        Err(io::Error::new(io::ErrorKind::Other, status.err().unwrap()))
    } else if !status.unwrap().success() {
        let output = cmd.output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        let err_msg = format!("Error setting power profile: {}", stderr);
        Err(io::Error::new(io::ErrorKind::Other, err_msg))
    } else {
        Ok(())
    }
}

fn print_profiles() -> io::Result<()> {
    // Get monitor profiles
    println!("\nMONITOR PROFILES");
    let monitor_cfgs = df_monitor_profiles()?;
    for mon_cfg in monitor_cfgs.iter() {
        println!("{}", mon_cfg);
    }

    println!("\nPOWER PROFILES");
    let power_cfgs = power_profiles()?;
    for pwr_cfg in power_cfgs.iter() {
        println!("{}", pwr_cfg.name);
    }
    Ok(())
}

fn df_monitor_profiles() -> Result<Vec<String>, io::Error> {
    println!("Looking at the registry");
    const BIN_SW_KEY: &str = r#"Software\Binary Fortress Software\DisplayFusion\MonitorConfig"#;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let mon_cfgs = hkcu.open_subkey(BIN_SW_KEY)?;
    let mut profiles: Vec<String> = vec![];
    for value in mon_cfgs.enum_keys().map(|x| x.unwrap()) {
        let cfg_path = Path::new(BIN_SW_KEY).join(&value);
        let key = hkcu.open_subkey(cfg_path)?;
        let name: String = key.get_value("Name")?;
        profiles.push(name);
    }
    Ok(profiles)
}

#[derive(Debug)]
struct PowerProfile {
    name: Box<String>,
    guid: Box<String>,
    active: bool,
}

impl PowerProfile {
    fn new(name: &str, guid: &str, active: bool) -> Self {
        Self {
            name: Box::new(name.to_string()),
            guid: Box::new(guid.to_string()),
            active,
        }
    }
}

/* trait Runner {
    fn run(arg: Type) -> RetType {
        unimplemented!();
    }
} */

fn power_profiles() -> io::Result<Vec<PowerProfile>> {
    let mut profiles: Vec<PowerProfile> = vec![];
    // run the `powercfg /L` comand    // run the `powercfg /L` comand
    let output = std::process::Command::new("powercfg")
        .arg("/L")
        .output()
        .unwrap();
    let output = String::from_utf8_lossy(&output.stdout);
    for line in output.lines() {
        if line.starts_with("Power Scheme GUID:") {
            let parts = line.splitn(2, ": ").last();
            if let Some(data) = parts {
                // split at two spaces
                let (guid, scheme) = data.split_once("  ").unwrap_or(("", ""));
                if guid.is_empty() || scheme.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid data"));
                }
                let active = scheme.ends_with('*');
                let name = scheme
                    .trim_start_matches('(')
                    .trim_end_matches([')', ' ', '*']);
                let current = PowerProfile::new(name, guid, active);

                profiles.push(current);
            } else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid data"));
            }
        }
    }

    Ok(profiles)
}
// fn spawn_cli_thread();
