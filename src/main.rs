mod ewf;
mod part;
use env_logger::Env;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let debug = &args[1];
    let file_path = &args[2];

    env_logger::Builder::from_env(Env::default().default_filter_or(debug)).init();
    
    //let file_path = "/Users/k1nd0ne/work/DFIR/dfir-case1/Case1-Webserver.E01";
    //let file_path = "/Users/k1nd0ne/work/DFIR/Memory Analysis/Cyberdefender/Lenovo-Final/LenovoFinal.E01";
    let mut ewf_file = match ewf::EwfSegment::new(file_path){
        Ok(ewf) => ewf,
        Err(message) => panic!("{}", message)
    };
    ewf_file.print_info();
    
    
    //println!("{}", ewf_file.md5_hash());
    //println!("{}", ewf_file.md5_hash2());
    //hexdump::hexdump(&ewf_file.read(512));
    //ewf_file.read(512);
    ewf_file.seek(0x01BE);
    let mbr_data = ewf_file.read(16);
    let mbr = part::MBR::new(&mbr_data);
    mbr.print_info();
    
    ewf_file.seek(512);
    //hexdump::hexdump(&ewf_file.read(512));
}
