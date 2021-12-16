//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.
//! In this example, you will see the use of the `launcher` feature.
//! The `launcher` will spawn new processes for each cpu core.

use core::time::Duration;
use std::{
    env, fs,
    io::{Read, Write},
    net::SocketAddr,
    path::PathBuf,
};
use structopt::StructOpt;

use libafl::{
    bolts::{
        current_nanos,
        launcher::Launcher,
        os::Cores,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::tuple_list,
    },
    corpus::{
        CachedOnDiskCorpus, Corpus, IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus,
        QueueCorpusScheduler,
    },
    events::EventConfig,
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::{Generator, NautilusContext, NautilusGenerator},
    inputs::{
        EncodedInput, Input, InputDecoder, InputEncoder, NaiveTokenizer, TokenInputEncoderDecoder,
    },
    monitors::MultiMonitor,
    mutators::{encoded_mutations::encoded_mutations, StdScheduledMutator},
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
    Error, Evaluator,
};

use libafl_targets::{libfuzzer_initialize, libfuzzer_test_one_input, EDGES_MAP, MAX_EDGES_NUM};

/// Parses a millseconds int into a [`Duration`], used for commandline arg parsing
fn timeout_from_millis_str(time: &str) -> Result<Duration, Error> {
    Ok(Duration::from_millis(time.parse()?))
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "libafl_quickjs",
    about = "Fuzz quickjs with libafl",
    author = "Andrea Fioraldi <andreafioraldi@gmail.com>"
)]
struct Opt {
    #[structopt(
        short,
        long,
        parse(try_from_str = Cores::from_cmdline),
        help = "Spawn a client in each of the provided cores. Broker runs in the 0th core. 'all' to select all available cores. 'none' to run a client without binding to any core. eg: '1,2-4,6' selects the cores 1,2,3,4,6.",
        name = "CORES"
    )]
    cores: Cores,

    #[structopt(
        short = "p",
        long,
        help = "Choose the broker TCP port, default is 1337",
        name = "PORT"
    )]
    broker_port: u16,

    #[structopt(
        parse(try_from_str),
        short = "a",
        long,
        help = "Specify a remote broker",
        name = "REMOTE"
    )]
    remote_broker_addr: Option<SocketAddr>,

    #[structopt(
        short,
        long,
        parse(try_from_str),
        help = "Set the output directory, default is ./out",
        name = "OUTPUT",
        default_value = "./out"
    )]
    output: PathBuf,

    #[structopt(
        short,
        long,
        parse(try_from_str),
        help = "Convert a stored testcase to JavaScript text",
        name = "REPRO"
    )]
    repro: Option<PathBuf>,

    #[structopt(
        parse(try_from_str = timeout_from_millis_str),
        short,
        long,
        help = "Set the exeucution timeout in milliseconds, default is 1000",
        name = "TIMEOUT",
        default_value = "1000"
    )]
    timeout: Duration,
}

const NUM_GENERATED: usize = 4096;
const CORPUS_CACHE: usize = 4096;

/// The main fn, `no_mangle` as it is a C symbol
#[no_mangle]
pub fn libafl_main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<Tokens>();
    let opt = Opt::from_args();

    let mut initial_dir = opt.output.clone();
    initial_dir.push("initial");
    fs::create_dir_all(&initial_dir).unwrap();

    let context = NautilusContext::from_file(64, "grammar.json");
    let mut tokenizer = NaiveTokenizer::default();
    let mut encoder_decoder = TokenInputEncoderDecoder::new();
    let mut initial_inputs = vec![];

    if let Some(repro) = opt.repro {
        for i in 0..NUM_GENERATED {
            let mut file =
                fs::File::open(&initial_dir.join(format!("id_{}", i))).expect("no file found");
            let mut buffer = vec![];
            file.read_to_end(&mut buffer).expect("buffer overflow");

            let _ = encoder_decoder
                .encode(&buffer, &mut tokenizer)
                .expect("encoding failed");
        }

        let input = EncodedInput::from_file(repro).unwrap();

        let args: Vec<String> = env::args().collect();
        if libfuzzer_initialize(&args) == -1 {
            println!("Warning: LLVMFuzzerInitialize failed with -1")
        }

        let mut bytes = vec![];
        encoder_decoder.decode(&input, &mut bytes).unwrap();
        unsafe {
            println!("Testcase: {}", std::str::from_utf8_unchecked(&bytes));
        }
        libfuzzer_test_one_input(&bytes);

        return;
    }

    let mut generator = NautilusGenerator::new(&context);

    let mut bytes = vec![];
    for i in 0..NUM_GENERATED {
        let nautilus = generator.generate(&mut ()).unwrap();
        nautilus.unparse(&context, &mut bytes);

        let mut file = fs::File::create(&initial_dir.join(format!("id_{}", i))).unwrap();
        file.write_all(&bytes).unwrap();

        let input = encoder_decoder
            .encode(&bytes, &mut tokenizer)
            .expect("encoding failed");
        initial_inputs.push(input);
    }

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    let stats = MultiMonitor::new(|s| println!("{}", s));

    let mut run_client = |state: Option<StdState<_, _, _, _, _>>, mut restarting_mgr, _core_id| {
        let mut objective_dir = opt.output.clone();
        objective_dir.push("crashes");
        let mut corpus_dir = opt.output.clone();
        corpus_dir.push("corpus");

        // Create an observation channel using the coverage map
        let edges = unsafe { &mut EDGES_MAP[0..MAX_EDGES_NUM] };
        let edges_observer = HitcountsMapObserver::new(StdMapObserver::new("edges", edges));

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // The state of the edges feedback.
        let feedback_state = MapFeedbackState::with_observer(&edges_observer);

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::new_tracking(&feedback_state, &edges_observer, true, false),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new_with_observer(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                CachedOnDiskCorpus::new(corpus_dir, CORPUS_CACHE).unwrap(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(objective_dir).unwrap(),
                // States of the feedbacks.
                // They are the data related to the feedbacks that you want to persist in the State.
                tuple_list!(feedback_state),
            )
        });

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // The wrapped harness function, calling out to the LLVM-style harness
        let mut bytes = vec![];
        let mut harness = |input: &EncodedInput| {
            bytes.clear();
            encoder_decoder.decode(input, &mut bytes).unwrap();
            if *bytes.last().unwrap() != 0 {
                bytes.push(0);
            }
            //unsafe {
            //println!(">>> {}", std::str::from_utf8_unchecked(&bytes));
            //}
            libfuzzer_test_one_input(&bytes);
            ExitKind::Ok
        };

        // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
        let mut executor = TimeoutExecutor::new(
            InProcessExecutor::new(
                &mut harness,
                tuple_list!(edges_observer, time_observer),
                &mut fuzzer,
                &mut state,
                &mut restarting_mgr,
            )?,
            opt.timeout,
        );

        // The actual target run starts here.
        // Call LLVMFUzzerInitialize() if present.
        let args: Vec<String> = env::args().collect();
        if libfuzzer_initialize(&args) == -1 {
            println!("Warning: LLVMFuzzerInitialize failed with -1")
        }

        // In case the corpus is empty (on first run), reset
        if state.corpus().count() < 1 {
            for input in &initial_inputs {
                fuzzer
                    .add_input(
                        &mut state,
                        &mut executor,
                        &mut restarting_mgr,
                        input.clone(),
                    )
                    .unwrap();
            }
        }

        // Setup a basic mutator with a mutational stage
        let mutator = StdScheduledMutator::with_max_iterations(encoded_mutations(), 2);
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr)?;
        Ok(())
    };

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_build_id())
        .monitor(stats)
        .run_client(&mut run_client)
        .cores(&opt.cores)
        .broker_port(opt.broker_port)
        .remote_broker_addr(opt.remote_broker_addr)
        .stdout_file(Some("/dev/null"))
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {:?}", err),
    }
}
