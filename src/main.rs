use std::env;
use std::fs;
use std::process;

fn print_usage(program: &str) -> ! {
    eprintln!("Verify an Ultra Honk ZK proof.");
    eprintln!("Usage: {program} [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -p, --proof_path <PATH>          Path to the proof");
    eprintln!("  -k, --vk_path <PATH>             Path to the verification key");
    eprintln!("  -i, --public_inputs_path <PATH>  Path to public inputs");
    eprintln!("  -h, --help                       Print this help message");
    process::exit(2);
}

fn parse_args() -> (String, String, String) {
    let args: Vec<String> = env::args().collect();
    let mut proof_path: Option<String> = None;
    let mut vk_path: Option<String> = None;
    let mut pi_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--proof_path" => {
                i += 1;
                proof_path = args.get(i).cloned();
            }
            "-k" | "--vk_path" => {
                i += 1;
                vk_path = args.get(i).cloned();
            }
            "-i" | "--public_inputs_path" => {
                i += 1;
                pi_path = args.get(i).cloned();
            }
            "-h" | "--help" => print_usage(&args[0]),
            other => {
                eprintln!("Unknown option: {other}");
                print_usage(&args[0]);
            }
        }
        i += 1;
    }

    let proof = proof_path.unwrap_or_else(|| {
        eprintln!("Missing required option: -p/--proof_path");
        print_usage(&args[0]);
    });
    let vk = vk_path.unwrap_or_else(|| {
        eprintln!("Missing required option: -k/--vk_path");
        print_usage(&args[0]);
    });
    let pi = pi_path.unwrap_or_else(|| {
        eprintln!("Missing required option: -i/--public_inputs_path");
        print_usage(&args[0]);
    });

    (proof, vk, pi)
}

fn main() {
    let (proof_path, vk_path_str, pi_path) = parse_args();

    let proof_data = fs::read(&proof_path).expect("Failed to read proof file");
    let vk_data = fs::read(&vk_path_str).expect("Failed to read VK file");
    let pi_data = fs::read(&pi_path).expect("Failed to read public inputs file");

    // Read VK hash from sibling file next to the VK
    let vk_path = std::path::Path::new(&vk_path_str);
    let vk_hash_path = vk_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("vk_hash");
    let vk_hash_data = fs::read(&vk_hash_path).ok();

    let valid = armory_verifier::verify(&proof_data, &vk_data, &pi_data, vk_hash_data.as_deref());

    if valid {
        println!("VALID");
    } else {
        eprintln!("INVALID");
        process::exit(1);
    }
}
