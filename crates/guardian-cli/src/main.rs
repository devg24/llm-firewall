#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "on" {
        guardian_cli::run_server_with_trust().await;
    } else {
        guardian_cli::run_server().await;
    }
}
