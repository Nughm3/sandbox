use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::ExitStatus,
    str,
};

use thiserror::Error;

use crate::resource::ResourceUsage;

#[cfg_attr(feature = "serde", derive(serde_with::DeserializeFromStr))]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Command {
    pub(crate) executable: PathBuf,
    pub(crate) args: Vec<OsString>,
}

impl Command {
    pub fn new(
        executable: impl AsRef<Path>,
        args: impl IntoIterator<Item = impl AsRef<OsStr>>,
    ) -> Self {
        Command {
            executable: executable.as_ref().to_path_buf(),
            args: args.into_iter().map(|s| s.as_ref().to_owned()).collect(),
        }
    }
}

#[derive(Debug, Error)]
#[error("empty command")]
pub struct EmptyCommand;

impl str::FromStr for Command {
    type Err = EmptyCommand;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut it = s.split_whitespace();
        Ok(Command {
            executable: it.next().ok_or(EmptyCommand)?.into(),
            args: it.map(|s| s.into()).collect(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub(crate) exit_status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) resource_usage: ResourceUsage,
}

impl Output {
    pub fn exit_status(&self) -> ExitStatus {
        self.exit_status
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stdout_utf8(&self) -> Result<&str, str::Utf8Error> {
        str::from_utf8(&self.stdout)
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    pub fn stderr_utf8(&self) -> Result<&str, str::Utf8Error> {
        str::from_utf8(&self.stderr)
    }

    pub fn resource_usage(&self) -> ResourceUsage {
        self.resource_usage
    }
}
