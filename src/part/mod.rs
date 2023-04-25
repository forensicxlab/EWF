
// References
// https://en.wikipedia.org/wiki/Master_boot_record#PTE
// https://en.wikipedia.org/wiki/Partition_type

pub(crate) struct MBR{
    flag: u8,
    ptype: u8,
    first_sector_addr: u32,
    size: u32,
}

impl MBR {
    pub fn new(data: &Vec<u8>) -> MBR{
        return MBR{
            flag: u8::from_le_bytes(data[0x00..0x01].try_into().unwrap()),
            ptype: u8::from_le_bytes(data[0x04..0x05].try_into().unwrap()),
            first_sector_addr: u32::from_le_bytes(data[0x08..0x0C].try_into().unwrap()),
            size: u32::from_le_bytes(data[0x0C..0x10].try_into().unwrap())
        }
    }
        pub fn print_info(&self){
        println!("Boot=0x{:x}, Type=0x{:x}, start_addr=0x{:x}, size=0x{:x}",self.flag,self.ptype,self.first_sector_addr,self.size);  
    }
}