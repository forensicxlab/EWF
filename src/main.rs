mod ewf;
mod part;
use env_logger::Env;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let debug = &args[1];
    let file_path = &args[2];

    env_logger::Builder::from_env(Env::default().default_filter_or(debug)).init();
    let mut ewf_file = match ewf::EWF::new(file_path){
        Ok(ewf) => ewf,
        Err(message) => panic!("{}", message)
    };
    ewf_file.print_info();
    ewf_file.seek(0x01BE);
    let mbr_data = ewf_file.read(16);
    let mbr = part::MBR::new(&mbr_data);
    mbr.print_info();
    println!("{}", ewf_file.md5_hash_read());
}
