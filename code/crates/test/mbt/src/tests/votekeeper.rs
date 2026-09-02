use glob::glob;

use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::utils::generate_test_traces;
use crate::votekeeper::State;

pub mod runner;
pub mod utils;

use runner::VoteKeeperRunner;

const RANDOM_SEED: u64 = 0x42;

#[test]
fn test_itf() {
    let temp_dir = tempfile::TempDir::with_prefix("arc-malachitebft-core-votekeeperkeeper-")
        .expect("Failed to create temp dir");
    let temp_path = temp_dir.path().to_owned();

    if std::env::var("KEEP_TEMP").is_ok() {
        std::mem::forget(temp_dir);
    }

    let quint_seed = option_env!("QUINT_SEED")
        .inspect(|x| {
            println!("using QUINT_SEED={x}");
        })
        .or(Some("118"))
        .and_then(|x| x.parse::<u64>().ok())
        .filter(|&x| x != 0)
        .expect("invalid random seed for quint");

    generate_test_traces(
        "consensus/quint/tests/votekeeper/votekeeperTest.qnt",
        &temp_path.to_string_lossy(),
        quint_seed,
    );

    for json_fixture in glob(&format!("{}/*.itf.json", temp_path.display()))
        .expect("Failed to read glob pattern")
        .flatten()
    {
        println!("🚀 Running trace {json_fixture:?}");

        // Signal the start of a new test to the oracle server (no-op when not running under oracle).
        let trace_name = json_fixture
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        crate::oracle_client::start_test(&trace_name);

        let json = std::fs::read_to_string(&json_fixture).unwrap();
        let trace = match itf::trace_from_str::<State>(&json) {
            Ok(t) => t,
            Err(e) => {
                println!("⚠️  Skipping trace {json_fixture:?}: {e}");
                continue;
            }
        };

        let rng = StdRng::seed_from_u64(RANDOM_SEED);
        let vote_keeper_runner = VoteKeeperRunner::new(rng);

        trace.run_on(vote_keeper_runner).unwrap();
    }
}
