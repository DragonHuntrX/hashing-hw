use std::fmt::Display;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Error, ErrorKind};
use std::path::PathBuf;

use clap::clap_derive::{Parser, Subcommand};
use clap::{Args, Parser as _};
use regex::Regex;

use sha2::{Digest, Sha256};

const MODBUS: crc::Crc<u16> = crc::Crc::<u16>::new(&crc::CRC_16_MODBUS);
const HEX_REGEX: &str = r"^([0-9]|[A-F]|[a-f]){1,4}$";
const SHA256_REGEX: &str = r"^([0-9]|[A-F]|[a-f]){64}$";
const NUM_CHARS: usize = 10;
const MIN_CHAR: u8 = 32;
const MAX_CHAR: u8 = 127;

// Helper functions to check command line args

fn valid_hash(r: &str) -> Result<String, Error> {
    let regex = Regex::new(HEX_REGEX).unwrap();
    if regex.is_match(r) {
        Ok(r.to_lowercase())
    } else {
        Err(Error::new(
            ErrorKind::InvalidInput,
            format!("not valid hex: {}; crc must be hex", r),
        ))
    }
}

fn valid_sha256_hash(r: &str) -> Result<String, Error> {
    let regex = Regex::new(SHA256_REGEX).unwrap();
    if regex.is_match(r) {
        Ok(r.to_lowercase())
    } else {
        Err(Error::new(
            ErrorKind::InvalidInput,
            format!("not valid hex: {}; crc must be hex", r),
        ))
    }
}

// Error struct
#[derive(Debug)]
struct DictAttackFailed {
    message: String,
}

impl Display for DictAttackFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

// START: Structs for command line arg parsing

#[derive(Subcommand, Debug)]
enum Command {
    Crc {
        input: PathBuf,
    },
    CrcCrack(CrcCrackArgs),
    #[command(name = "dict")]
    Dictionary(DictionaryArgs),
    #[command(name = "ext")]
    ExtendCrack(ExtendCrackArgs),
}

#[derive(Args, Debug)]
struct CrcCrackArgs {
    #[arg()]
    input: PathBuf,
    #[arg(value_parser = clap::builder::ValueParser::new(valid_hash))]
    crc: String,
    #[arg(long, short, action)]
    verbose: bool,
}

#[derive(Args, Debug)]
struct DictionaryArgs {
    words: PathBuf,
    passwords: PathBuf,
    salt: String,
}

#[derive(Args, Debug)]
struct ExtendCrackArgs {
    #[arg(value_parser=clap::builder::ValueParser::new(valid_sha256_hash))]
    hash: String,
    old_password: String,
    salt: String,
}

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

// END

/// Main function matches subcommand
fn main() {
    let args = Cli::parse();

    match args.command {
        Command::Crc { input } => crc_calc(input),
        Command::CrcCrack(crc_crack_args) => crc_crack(crc_crack_args),
        Command::Dictionary(args) => match dict_attack(args) {
            Ok(_) => (),
            Err(e) => eprintln!("Dictionary attack failed: {e}"),
        },
        Command::ExtendCrack(extend_crack_args) => crack_extended(extend_crack_args),
    }
}

/// Credential storage for dictionary attack
struct Creds {
    user: String,
    passhash: String,
}

/// Dictionary attack reads passwords into vector of creds, then loops through
/// each line of the words file and checks if any of the hashes match.
fn dict_attack(args: DictionaryArgs) -> Result<(), DictAttackFailed> {
    let words = match File::open(args.words) {
        Ok(f) => f,
        Err(e) => {
            return Err(DictAttackFailed {
                message: e.to_string(),
            })
        }
    };

    let passwords = match File::open(args.passwords) {
        Ok(f) => f,
        Err(e) => {
            return Err(DictAttackFailed {
                message: e.to_string(),
            })
        }
    };

    let mut creds = vec![];
    for line in BufReader::new(passwords).lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                return Err(DictAttackFailed {
                    message: format!("Reading lines of password file failed: {e}"),
                })
            }
        };
        let (user, hash) = line.trim().split_once(" ").unwrap();
        creds.push(Creds {
            user: user.to_owned(),
            passhash: hash.to_owned(),
        });
    }

    for line in BufReader::new(words).lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                return Err(DictAttackFailed {
                    message: format!("Reading lines of password file failed: {e}"),
                })
            }
        };
        let mut hasher = Sha256::new();
        let word = line.trim();
        hasher.update(format!("{}{}", word, args.salt).as_bytes());
        let result = hasher.finalize().to_vec();
        let hash = result.into_iter().fold("".to_string(), |total, byte| {
            total + &format!("{:02x}", byte)
        });
        for user in creds.iter() {
            if hash == user.passhash {
                println!("password for {} is: {}", user.user, word)
            }
        }
    }

    Ok(())
}

/// Calculates the crc hash of the file
fn crc_calc(input: PathBuf) {
    let mut data = match fs::read(input) {
        Ok(d) => d,
        Err(e) => {
            println!("Error reading file: {e}");
            return;
        }
    };

    match data[0..2] {
        [0xFF, 0xFE] => data = data.into_iter().skip(2).step_by(2).collect(),
        [0xFE, 0xFF] => data = data.into_iter().skip(3).step_by(2).collect(),
        _ => (),
    }

    println!("CRC: {:#x}", MODBUS.checksum(&data));
}

/// Modifies the final few bytes of the file to ensure that the hashes still match.
fn crc_crack(args: CrcCrackArgs) {
    let mut data = match fs::read(args.input) {
        Ok(d) => d,
        Err(e) => {
            println!("Error reading file: {e}");
            return;
        }
    };
    // Read utf8 from utf16 encoded file
    match data[0..2] {
        [0xFF, 0xFE] => data = data.into_iter().skip(2).step_by(2).collect(),
        [0xFE, 0xFF] => data = data.into_iter().skip(3).step_by(2).collect(),
        _ => (),
    }

    data.append(&mut b"\n\n".to_vec());

    let check = u16::from_str_radix(&args.crc, 16).unwrap();

    data.append(
        &mut b"If you are reading this, you have been compromised. All your files are belong to me.\n\n"
            .to_vec(),
    );

    let data_len = data.len();
    let mut offset = vec![MIN_CHAR; NUM_CHARS];
    data.extend(offset.clone());

    let mut crc = MODBUS.checksum(&data);
    while crc != check {
        if args.verbose {
            println!("{}", String::from_utf8(data.clone()).unwrap());
        };
        increment(&mut offset);
        data.truncate(data_len);
        data.extend(offset.clone());
        crc = MODBUS.checksum(&data);
        if args.verbose {
            println!("{crc:x}")
        }
    }

    let out = match String::from_utf8(data) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("Failed to convert the final message to ascii: {e}");
            return;
        }
    };

    match fs::write("output.txt", out) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error while writing to output.txt: {e}");
            return;
        }
    }
}

/// Increments the vector holding the offset by the specified amount.
///
/// returns `true` if the offset is successfully incremented, and `false` if it is at its max
fn increment(nums: &mut Vec<u8>) -> bool {
    nums[0] += 1;
    for i in 0..NUM_CHARS {
        if nums[i] > MAX_CHAR {
            if i == nums.len() - 1 {
                return false;
            }
            nums[i] = MIN_CHAR;
            nums[i + 1] = nums[i + 1] + 1;
        }
    }
    true
}

/// Cracks a password with a few added characters.
fn crack_extended(args: ExtendCrackArgs) {
    let characters: Vec<char> = r#"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"$#%&'()*+,-./:;<=>?@[\]^_`{|}~"#.chars().collect();
    characters.iter().for_each(|&c1| {
        characters.iter().for_each(|&c2| {
            let hash = Sha256::digest(
                format!("{}{}{}{}", args.old_password, c1, c2, args.salt).as_bytes(),
            )
            .to_vec()
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();
            if hash == args.hash {
                println!("Found: {}{}", c1, c2);
                return;
            }
        });
    });
    println!("Not found");
}
