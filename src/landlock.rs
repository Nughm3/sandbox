use std::{iter, path::Path};

use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError,
    RulesetStatus,
};

const LANDLOCK_ABI: landlock::ABI = landlock::ABI::V4;
const LIBRARY_PATHS: &[&str] = &["/lib", "/usr/lib", "/usr/local/lib", "/nix/store"];

pub fn apply_landlock(dir: impl AsRef<Path>) -> Result<(), RulesetError> {
    let all = AccessFs::from_all(LANDLOCK_ABI);
    let read_only = AccessFs::from_read(LANDLOCK_ABI);

    let status = Ruleset::default()
        .handle_access(all)?
        .create()?
        .add_rules(path_beneath_rules(iter::once(dir), all))?
        .add_rules(path_beneath_rules(LIBRARY_PATHS.iter(), read_only))?
        .restrict_self()?;

    if let RulesetStatus::PartiallyEnforced | RulesetStatus::NotEnforced = status.ruleset {
        panic!("unable to fully enforce landlock ruleset");
    }

    Ok(())
}
