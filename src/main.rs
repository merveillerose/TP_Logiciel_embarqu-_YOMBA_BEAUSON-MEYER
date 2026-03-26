use pcap::Capture;
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    interface: Option<String>,
}


fn main() {
    let _args = Args::parse();
    println!("Hello drone analyzer");
}