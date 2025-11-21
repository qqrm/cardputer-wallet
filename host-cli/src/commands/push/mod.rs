pub mod artifacts;
pub mod frames;
pub mod plan;

use shared::error::SharedError;

use crate::RepoArgs;
use crate::commands::host_config::HostConfig;
use crate::commands::{DeviceTransport, RepoArtifactStore, print_repo_banner};

pub fn run<T, S>(transport: &mut T, store: &mut S, args: &RepoArgs) -> Result<(), SharedError>
where
    T: DeviceTransport + ?Sized,
    S: RepoArtifactStore + ?Sized,
{
    print_repo_banner(args);

    let config = HostConfig::load(&args.credentials)?;
    let operations = plan::load_local_operations(&args.repo, &config)?;
    if operations.is_empty() {
        println!("No pending operations to push.");
        return Ok(());
    }

    artifacts::apply_operations_to_repo(&args.repo, &config, &operations)?;

    let plan = plan::PushPlan::from_operations(&operations)?;

    println!(
        "Dispatching {} operation{} across {} frame{}…",
        plan.total_operations,
        if plan.total_operations == 1 { "" } else { "s" },
        plan.frames.len(),
        if plan.frames.len() == 1 { "" } else { "s" }
    );

    artifacts::push_vault_artifacts(transport, store)?;
    frames::send_operation_frames(transport, plan.frames)?;

    plan::clear_local_operations(&args.repo)?;
    println!("Push operations completed. Cleared local journal state.");
    Ok(())
}
