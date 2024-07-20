use std::{
    env,
    io::{stdin, Read},
};

use sandbox::{Command, ResourceLimits, Sandbox};

fn main() {
    println!(
        "sandbox {} testing program\nenter input:\n---",
        env!("CARGO_PKG_VERSION")
    );

    let sandbox = Sandbox::new()
        .unwrap()
        .with_rlimits(ResourceLimits::default())
        .enable_seccomp()
        .enable_landlock();

    let command: Command = env::args()
        .skip(1)
        .collect::<Vec<String>>()
        .join(" ")
        .parse()
        .unwrap();

    let mut stdin_buf = Vec::new();
    stdin().read_to_end(&mut stdin_buf).unwrap();

    let output = sandbox.run(&command, &stdin_buf).unwrap();
    println!("---\n{output:#?}");

    if !output.stdout().is_empty() {
        if let Ok(stdout) = output.stdout_utf8() {
            println!("--- stdout ---\n{stdout}");
        }
    }

    if !output.stderr().is_empty() {
        if let Ok(stderr) = output.stderr_utf8() {
            println!("--- stderr ---\n{stderr}");
        }
    }
}
