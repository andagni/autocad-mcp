fn main() {
    if autocad_writer::portable_plot::run_worker_stdio().is_err() {
        std::process::exit(1);
    }
}
