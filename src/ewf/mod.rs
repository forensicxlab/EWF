use md5::{Digest, Md5};
use log::{debug, info};
use core::panic;
use std::fs::{File};
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use flate2::read::ZlibDecoder;

#[derive(Default)]
struct EwfHeader {
    signature: [u8; 8], // 8 bytes
    segment_number: u16, // 2 bytes
}

struct EwfSectionDescriptor {
    // Ref : https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc#31-section-descriptor
    section_type_def: String, // 16 bytes
    next_section_offset: u64, // 8 bytes 
    section_size: u64, // 8 bytes
    checksum: u32, // 4 bytes
}

#[derive(Default)]
struct EwfHeaderSection{
    // Ref: https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc#34-header-section
    data: Vec<u8>,
}

#[derive(Default)]
struct EwfVolumeSection{
    // Ref : https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc#35-volume-section
    chunk_count: u32,
    sector_per_chunk: u32,
    bytes_per_sector: u32,
    total_sector_count: u32,
}

struct Chunk{
    compressed: bool, // Am I compressed ?
    data_offset: u32, // Where are my data starting ?
    chunk_number: usize, // What is my chunk number (absolute) ?
}
struct ChunkCache{
    number: usize,
    segment: usize,
    ptr: usize,
    data: Vec<u8>
}

#[derive(Default)]
pub(crate) struct EWF{
    segments: Vec<File>,
    ewf_header: EwfHeader,
    sections: Vec<EwfSectionDescriptor>,
    header: EwfHeaderSection,
    volume: EwfVolumeSection,
    chunks: HashMap<usize,Vec<Chunk>>,
    end_of_sectors: HashMap<usize,u64>,
    cached_chunk: ChunkCache,
    chunk_count: usize,
}

impl Default for ChunkCache{
    fn default() -> Self {
        ChunkCache { number: 0, segment: 1, ptr: 0, data: Vec::new() }
    }
}

impl  EwfVolumeSection {
    fn new(mut file: &File, offset: u64) -> EwfVolumeSection{
        debug!("Parsing 'Volume' section.");
        let mut chunk_count: [u8; 4] = [0; 4];
        let mut sector_per_chunk: [u8; 4] = [0; 4];
        let mut bytes_per_sector: [u8; 4] = [0; 4];
        let mut total_sector_count: [u8; 4] = [0; 4];
        file.seek(SeekFrom::Start(offset+4)).unwrap();
        file.read(&mut chunk_count).unwrap();
        file.seek(SeekFrom::Start(offset+8)).unwrap();
        file.read(&mut sector_per_chunk).unwrap();
        file.seek(SeekFrom::Start(offset+12)).unwrap();
        file.read(&mut bytes_per_sector).unwrap();
        file.seek(SeekFrom::Start(offset+16)).unwrap();
        file.read(&mut total_sector_count).unwrap();

        return EwfVolumeSection { 
            chunk_count: u32::from_le_bytes(chunk_count),
            sector_per_chunk: u32::from_le_bytes(sector_per_chunk), 
            bytes_per_sector: u32::from_le_bytes(bytes_per_sector), 
            total_sector_count: u32::from_le_bytes(total_sector_count) 
        }
    }

    fn chunk_size(&self) -> usize{
        return self.sector_per_chunk as usize * self.bytes_per_sector as usize;
    }

    fn max_offset(&self) -> usize{
        return self.total_sector_count as usize * self.bytes_per_sector as usize;
    }
    
}

impl EwfHeader{
    fn new(mut file: &File) -> Result<EwfHeader,String>{
        debug!("Parsing EWF File Header section.");
        let  ewf_l01_signature= [0x4d, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
        let  ewf_e01_signature= [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];

        let mut signature: [u8; 8] = [0u8; 8];
        let mut segment_number: [u8; 2] = [0u8; 2];

        file.read(&mut signature).unwrap();
        file.seek(SeekFrom::Start(9)).unwrap();
        file.read(&mut segment_number).unwrap();
        
        if (ewf_l01_signature != signature) && (signature != ewf_e01_signature){
            return Err("Invalid Signature".to_string());
        }
        return Ok(EwfHeader {
            signature: signature,
            segment_number: u16::from_le_bytes(segment_number),
        });      
    }

    fn print_info(&self){
        info!("Segment count : {:?} | signature : {:?}", self.segment_number, self.signature)
    }
}

impl EwfSectionDescriptor{
    fn new(mut file: &File, offset: u64) -> EwfSectionDescriptor{
        debug!("Parsing EWF Section Descriptor.");
        let mut section_type_def = [0; 16];
        let mut next_section_offset: [u8; 8] = [0; 8]; 
        let mut section_size: [u8; 8] = [0; 8]; 
        let mut checksum: [u8; 4] = [0; 4];

        file.seek(SeekFrom::Start(offset)).unwrap();
        file.read(&mut section_type_def).unwrap();
        file.seek(SeekFrom::Start(offset + 16)).unwrap();
        file.read(&mut next_section_offset).unwrap();
        file.seek(SeekFrom::Start(offset + 24)).unwrap();
        file.read(&mut section_size).unwrap();
        file.seek(SeekFrom::Start(offset + 104)).unwrap();
        file.read(&mut checksum).unwrap();
        
        let mut section_type= String::from_utf8(section_type_def.to_vec()).unwrap();
        section_type.retain(|c| c != '\0');


        return EwfSectionDescriptor {
            section_type_def:  section_type,
            next_section_offset: u64::from_le_bytes(next_section_offset),
            section_size: u64::from_le_bytes(section_size),
            checksum: u32::from_le_bytes(checksum),
        };
    }

    fn print_info(&self){
        info!("{:?} : size : {:?}, checksum : {:?}, next: {:?}", self.section_type_def, self.section_size, self.checksum, self.next_section_offset);
    }


}

impl EwfHeaderSection{
    fn new(mut file: &File, offset: u64, section: &EwfSectionDescriptor) -> Result<EwfHeaderSection, String>{
        debug!("Parsing EWF Section Header.");

        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut compressed_data = vec![0;  section.section_size as usize];    
        file.read(&mut compressed_data).unwrap();
        let mut decoder = ZlibDecoder::new(&compressed_data[..]);     
        let mut data = Vec::new();

        match decoder.read_to_end(&mut data){
            Ok(_) => return Ok(EwfHeaderSection{data: data}),
            Err(_) => return Err("Could not decompress the header section".to_string())
        }     
    }

    fn print_info(&self){
        info!("Header section data size : {:?} ", self.data.len());
    }
}

impl EWF{
    pub fn new(file_path: &str) -> Result<EWF, String>{
        debug!("Parsing EWF Segment : {}", file_path);

        let fp: &Path = Path::new(file_path);
        //let entries = fs::read_dir(parent_dir).unwrap();
        let files = 
        match find_files(fp){
            Ok(fp) => fp,
            Err(m) => return Err(m)
        };

        let mut ewf: EWF = EWF::default();

        //Go through all of the segments and parse them.
        for file in files{
            let fd = match File::open(file){
                Ok(file) => file,
                Err(m) => return Err(m.to_string())
            };
            
            ewf = match ewf.parse_segment(fd){
                Ok(ewf) => ewf,
                Err(m) => return Err(m)
            };
        }
        return Ok(ewf);
    }

    fn parse_table(&mut self, mut file: &File, offset: u64) -> Vec<Chunk>{
        // Ref: https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc#391-ewf-specification
        debug!("Parsing Table Section.");
        let mut chunks: Vec<Chunk> = Vec::new();
        let mut buffer: [u8; 4] = [0; 4];
        file.seek(SeekFrom::Start(offset)).unwrap();
        
        file.read(&mut buffer).unwrap();
        let entry_count = u32::from_le_bytes(buffer);
        file.seek(SeekFrom::Start(offset+8)).unwrap();
        
        file.read(&mut buffer).unwrap();
        let table_base_offset = u32::from_le_bytes(buffer);

        
        file.seek(SeekFrom::Start(offset+24)).unwrap(); // We place ourself at the beginning of the first table entry.
        
        let msb: u32 = 0x80000000; // binary representation of the MSB
        let mut tentry: u32;
        let mut ptr:u32;
        for _ in 0..entry_count{
            file.read(&mut buffer).unwrap();
            tentry = u32::from_le_bytes(buffer);
            ptr = tentry & 0x7fffffff; // The first bit is the the compression status.
            ptr = ptr + table_base_offset;  // Now we have our ptr pointing to the offset of the EWF Segment file.
            if tentry & msb == 0{
                // Chunk is uncompressed
                chunks.push(Chunk {compressed: false, data_offset: ptr, chunk_number: self.chunk_count.clone()});
            }
            else{
                // Chunk is compressed
                chunks.push(Chunk {compressed: true, data_offset: ptr, chunk_number: self.chunk_count.clone()});
            }
            self.chunk_count = self.chunk_count + 1; 
        }
        return chunks;
    }


    fn parse_segment(mut self, file: File) -> Result<EWF,String>{   
        self.ewf_header = match EwfHeader::new(&file){
            Ok(header) => header,
            Err(m) => return Err(m)
        };

        // Then, we place our pointer after the header section
        let mut current_offset = 13; //We place our self just after the EWFHeader.
        let ewf_section_descriptor_size = 0x4c; // Each section descriptor size is 0x4c.
        let mut extracted_chunks: Vec<Chunk> = Vec::new();

             
        loop{
            let section: EwfSectionDescriptor = EwfSectionDescriptor::new(&file, current_offset);
            let section_offset = section.next_section_offset.clone();
            let section_size = section.section_size.clone();
            let section_type = section.section_type_def.clone();
            self.sections.push(section);

            if section_type == "header" || section_type == "header2"{
                // We save the header, it contains information about the acquired media.
                self.header = match EwfHeaderSection::new(&file, current_offset+ewf_section_descriptor_size, self.sections.last().unwrap()){
                    Ok(header) => header,
                    Err(m) => return Err(m)
                };
            }

            if section_type == "disk" || section_type == "volume"{
                self.volume = EwfVolumeSection::new(&file, current_offset+ewf_section_descriptor_size);
                // We keep the volume because it has information about the acquired media.
            }

            if section_type == "table"{
               extracted_chunks.extend(self.parse_table(&file, current_offset+ewf_section_descriptor_size));
            }

            if section_type == "sectors"{
                self.end_of_sectors.insert(self.ewf_header.segment_number.clone() as usize, current_offset + section_size);
            }
                      
            if current_offset == section_offset || section_type == "done"{
                break;
            }
            current_offset = section_offset;
        }
        
        self.segments.push(file);
        self.chunks.insert(self.ewf_header.segment_number.clone() as usize, extracted_chunks);
        return Ok(self);
    
    }

    fn read_chunk(&self, segment: usize, chunk_number: usize) -> Vec<u8>{
        debug!("Reading chunk number {:?}, segment {:?}", chunk_number, segment);
        if chunk_number >= self.chunks.get(&segment).unwrap().len(){
            panic!("Could not read chunk number {:?} in segment number {:?}", chunk_number, segment);
        }
        let mut data: Vec<u8>;
        let chunk = &self.chunks[&segment][chunk_number];

        let end_offset: u64;
        let start_offset: u64 = chunk.data_offset as u64;

        self.segments.get(segment as usize - 1).unwrap().seek(SeekFrom::Start(start_offset)).unwrap();

        if !chunk.compressed{
            data = vec![0; self.volume.chunk_size()];
            self.segments.get(segment as usize - 1).unwrap().read(&mut data).unwrap();
        }
        else{
            if chunk.data_offset == self.chunks[&segment].last().unwrap().data_offset{
                end_offset = self.end_of_sectors[&segment];
            }
            else{
                end_offset = self.chunks[&segment][chunk_number+1].data_offset as u64;
            } 
            let mut compressed_data = vec![0; (end_offset - start_offset) as usize];    
            self.segments.get(segment as usize - 1).unwrap().read(&mut compressed_data).unwrap();
            let mut decoder = ZlibDecoder::new(&compressed_data[..]);     
            data = Vec::new();
            decoder.read_to_end(&mut data).unwrap();

        }
        return data;
    }

    pub fn read(&mut self, mut size: usize) -> Vec<u8>{
        
        debug!("Reading {:?} byte", size); 
        let mut data: Vec<u8> = Vec::new();
        if self.cached_chunk.data.is_empty(){ // There is no chunk in cache, the first chunk of the first segment become our cached chunk.
            self.cached_chunk.data = self.read_chunk(self.cached_chunk.segment, self.cached_chunk.number);
        }

        while size>0 {
            if self.volume.chunk_size() - self.cached_chunk.ptr >= size{
                data.extend(&self.cached_chunk.data[self.cached_chunk.ptr..(self.cached_chunk.ptr+size)]);
                self.cached_chunk.ptr = self.cached_chunk.ptr + size;
                size = 0;
            }
            else{

                data.extend(&self.cached_chunk.data[self.cached_chunk.ptr..]);
                size = size - (self.volume.chunk_size() - self.cached_chunk.ptr);
                self.cached_chunk.ptr = self.volume.chunk_size();
                if self.cached_chunk.segment < self.segments.len() || (self.cached_chunk.segment == self.segments.len() && self.cached_chunk.number+1 < self.chunks[&self.cached_chunk.segment].len()){
                    
                    // We get the next chunk number
                    if self.cached_chunk.number+1 < self.chunks[&self.cached_chunk.segment].len(){
                        self.cached_chunk.number += 1;
                    }
                    else{
                        if self.cached_chunk.segment+1 <= self.segments.len(){
                            self.cached_chunk.number = 0;
                            self.cached_chunk.segment += 1;
                        }
                        else{
                            panic!("Could not read next chunk");
                        }
                    }
                    self.cached_chunk.data = self.read_chunk(self.cached_chunk.segment, self.cached_chunk.number);
                    self.cached_chunk.ptr = 0;
                }
                else{
                    return data;
                }
            }
        }
        return data;
    }


    pub fn seek(&mut self, offset: usize){

        if offset > self.volume.max_offset(){
            panic!("Could not compute the offset");
        }

        let mut chunk_number = offset / self.volume.chunk_size();

        if chunk_number >= self.volume.chunk_count as usize{
            panic!("Error the chunk number requested is higher than the total number of chunk")
        }

        let mut segment = 1;
        while self.chunks[&segment][0].chunk_number > chunk_number || chunk_number > self.chunks[&segment].last().unwrap().chunk_number && segment < self.segments.len(){
            segment += 1;
        }

        chunk_number = chunk_number - self.chunks[&segment][0].chunk_number;
        debug!("Chunk number requested {:?}", chunk_number); 
        self.cached_chunk.data = self.read_chunk(segment, chunk_number);
        self.cached_chunk.number = chunk_number;
        self.cached_chunk.segment = segment;
        self.cached_chunk.ptr = offset % self.volume.chunk_size();
    }

    pub fn print_info(&self){
        self.ewf_header.print_info();
        for section in &self.sections{
            section.print_info();
        }
        self.header.print_info();
    }

    pub fn md5_hash_read(& mut self) -> String {
        let buffer_size: usize = 0x40*512-1;
        println!("Computing MD5 hash using read");
        let mut hasher = Md5::new();
        let mut data = self.read(buffer_size);
        while data.len() > 0{
            hasher.update(&data);
            if data.len() < buffer_size{
                return format!("{:x}", hasher.finalize());
            }
            data = self.read(buffer_size);
        }
        return format!("{:x}", hasher.finalize());
    }
}

fn find_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    let path = path.canonicalize().map_err(|_| "Invalid path".to_string())?;
    let ext = path.extension().ok_or_else(|| "Invalid extension".to_string())?;
    let ext_str = ext.to_str().ok_or_else(|| "Invalid extension".to_string())?;

    if !['E', 'L', 'S'].contains(&ext_str.chars().nth(0).unwrap().to_ascii_uppercase()) {
        return Err(format!("Invalid EWF file: {}", path.display()));
    }
    let pattern = format!("{}/*.[ELS]??", path.parent().unwrap().display());
    let files = glob::glob(&pattern).map_err(|_| "Glob error".to_string())?;
    let mut paths: Vec<PathBuf> = files.filter_map(|f| f.ok()).collect();
    paths.sort();
    Ok(paths)
}