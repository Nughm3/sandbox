use std::{
    io::{Error, ErrorKind, Read, Result, Write},
    os::unix::process::CommandExt,
    process::{Command as StdCommand, Stdio},
};

use tempfile::TempDir;

pub use crate::{
    command::{Command, EmptyCommand, Output},
    resource::{ResourceLimits, ResourceUsage},
};

mod command;
mod landlock;
mod resource;
mod seccomp;

#[derive(Debug)]
pub struct Sandbox {
    dir: TempDir,
    resource_limits: Option<ResourceLimits>,
    seccomp: bool,
    landlock: bool,
}

impl Sandbox {
    pub fn new() -> Result<Self> {
        Ok(Sandbox {
            dir: TempDir::new()?,
            resource_limits: None,
            seccomp: false,
            landlock: false,
        })
    }

    pub fn with_rlimits(mut self, rlimits: ResourceLimits) -> Self {
        self.resource_limits = Some(rlimits);
        self
    }

    pub fn enable_seccomp(mut self) -> Self {
        self.seccomp = true;
        self
    }

    pub fn enable_landlock(mut self) -> Self {
        self.landlock = true;
        self
    }

    pub fn run(&self, command: &Command, stdin: &[u8]) -> Result<Output> {
        let mut child = {
            let mut cmd = StdCommand::new(&command.executable);

            cmd.args(&command.args)
                .current_dir(&self.dir)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            unsafe {
                let (dir, resource_limits, seccomp, landlock) = (
                    self.dir.path().to_owned(),
                    self.resource_limits,
                    self.seccomp,
                    self.landlock,
                );

                cmd.pre_exec(move || {
                    if landlock {
                        landlock::apply_landlock(&dir).map_err(|e| {
                            Error::new(ErrorKind::Other, format!("landlock failed: {e}"))
                        })?;
                    }

                    if let Some(resource_limits) = resource_limits {
                        resource_limits.set()?;
                    }

                    if seccomp {
                        seccomp::apply_filters().map_err(|e| {
                            Error::new(ErrorKind::Other, format!("seccomp failed: {e}"))
                        })?;
                    }

                    Ok(())
                });
            }

            cmd.spawn()?
        };

        child.stdin.take().expect("no stdin").write_all(stdin)?;

        let (stdout, stderr) = {
            let (mut stdout, mut stderr) = (
                child.stdout.take().expect("no stdout"),
                child.stderr.take().expect("no stderr"),
            );
            let (mut stdout_buf, mut stderr_buf) = (Vec::new(), Vec::new());

            stdout.read_to_end(&mut stdout_buf)?;
            stderr.read_to_end(&mut stderr_buf)?;

            (stdout_buf, stderr_buf)
        };

        let (exit_status, resource_usage) = resource::wait4(child.id() as i32)?;

        Ok(Output {
            exit_status,
            stdout,
            stderr,
            resource_usage,
        })
    }
}
