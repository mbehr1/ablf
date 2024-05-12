use std::io::{BufRead, Seek};

use binrw::BinRead;
use zune_inflate::{DeflateDecoder, DeflateOptions};

pub struct BlfFile<R: BufRead> {
    reader: R,
    file_stats: BlfFileStats,
}

// MARK: IntoIterator
impl<R: BufRead + Seek> IntoIterator for BlfFile<R> {
    type Item = Object;
    type IntoIter = ObjectIterator<R>;

    fn into_iter(mut self) -> Self::IntoIter {
        // we do seek here once to the start of the objects:
        let _ = self
            .reader
            .seek(std::io::SeekFrom::Start(self.file_stats.stats_size as u64));
        // todo if not successful ensure that next returns None

        ObjectIterator {
            blf: self,
            prev_cont_data: Vec::new(),
            skipped: 0,
            cur_cont_iter: None,
        }
    }
}

// MARK: ObjectIterator
/// Iterator over the objects in the blf file
///
/// This iterator will skip the LogContainer objects and only return the inner objects (or outer non LogContainers)
/// It's a consuming iterator as it will use the Reader of the BlfFile.
/// Use BltFile.into_iter() to get the iterator that seeks to Start of the objects.
pub struct ObjectIterator<R: BufRead> {
    blf: BlfFile<R>,
    prev_cont_data: Vec<u8>,
    cur_cont_iter: Option<LogContainerIter>,
    // infos collected:
    skipped: u64,
}

impl<R: BufRead> ObjectIterator<R> {
    pub fn blf(self) -> BlfFile<R> {
        self.blf
    }
}

impl<R: BufRead + Seek> Iterator for ObjectIterator<R> {
    type Item = Object;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(iter) = &mut self.cur_cont_iter {
            if let Some(obj) = iter.next() {
                return Some(obj);
            }
        }
        if self.cur_cont_iter.is_some() {
            // if we reach here, the cur_cont_iter returned None
            let cont_iter = self.cur_cont_iter.take().unwrap();
            self.prev_cont_data = cont_iter.remaining_data();
        }

        match Object::read(&mut self.blf.reader) {
            Ok(obj) => {
                //println!("{:?}", obj);
                if let ObjectTypes::LogContainer10(cont) = obj.data {
                    self.cur_cont_iter = Some(cont.into_iter(&self.prev_cont_data));
                    if let Some(iter) = &mut self.cur_cont_iter {
                        if let Some(obj) = iter.next() {
                            return Some(obj);
                        }
                    }
                    // if we reach here, the cur_cont_iter returned None
                    let cont_iter = self.cur_cont_iter.take().unwrap();
                    self.prev_cont_data = cont_iter.remaining_data();
                    self.next() // todo remove recursion
                } else {
                    Some(obj)
                }
            }
            Err(e) => {
                if e.is_eof() {
                    None
                } else {
                    match e {
                        binrw::Error::BadMagic { pos, .. } => {
                            println!("ObjectIterator: BadMagic, skipping 1 byte at pos={}", pos);
                            self.skipped += 1;
                            self.blf.reader.seek(std::io::SeekFrom::Current(1)).unwrap();
                            self.next() // todo remove recursion!
                        }
                        _ => {
                            // ... sadly no own type for "Error: not enough bytes in reader..."
                            // which is kind of expected quite often
                            //println!("Error: {:?}", e);
                            None
                        }
                    }
                }
            }
        }
    }
}

// MARK: BlfFileStats
#[derive(Debug, BinRead)]
#[br(little, magic = b"LOGG")]
pub struct BlfFileStats {
    stats_size: u32,
    pub api_version: u32,
    pub application_id: u8,
    pub application_version: (u8, u8, u8),
    #[br(dbg)]
    file_size: u64,
    uncompressed_size: u64,
    pub object_count: u32,
    pub object_read: u32,
    #[br(if(stats_size == 144))]
    pub measurement_start: [u16; 8], // SYSTEMTIME
    #[br(if(stats_size == 144))]
    pub last_object_time: [u16; 8], // SYSTEMTIME
    #[br(if(stats_size == 144))]
    _reserved: [u32; 18],
}

// MARK: Object
#[derive(Debug, BinRead)]
#[br(little, magic = b"LOBJ")]
pub struct Object {
    // the next 4 are part of every header (ObjectHeaderBase)
    pub header_size: u16,
    pub header_version: u16,
    pub object_size: u32,
    pub object_type: u32,
    #[br(args{object_type, remaining_size:object_size - (4+2+2+4+4)})]
    pub data: ObjectTypes,
}

#[derive(Debug, BinRead)]
#[br(little)]
pub struct ObjectHeader {
    pub flags: u32,
    pub client_index: u16,
    pub version: u16,
    pub timestamp_ns: u64,
}

#[derive(Debug, BinRead)]
#[br(little,import{remaining_size: u32, object_type: u32})]
pub enum ObjectTypes {
    #[br(pre_assert(object_type == 10))]
    LogContainer10(#[br(args{object_size:remaining_size})] LogContainer),
    #[br(pre_assert(object_type == 86))]
    CanMessage86(#[br(args{remaining_size})] CanMessage2),
    #[br(pre_assert([65, 72, 6, 7, 8, 9, 90, 96, 92].contains(&object_type)))]
    UnsupportedPadded {
        #[br(count = remaining_size)]
        data: Vec<u8>,
        #[br(count=(remaining_size)%4)]
        padding: Vec<u8>,
    },
    Unsupported(#[br(count = remaining_size)] Vec<u8>),
}

// MARK: LogContainer
#[derive(Debug, BinRead)]
#[br(little,import{object_size: u32})]
pub struct LogContainer {
    // object_type == 10
    #[br(calc = object_size - (2 + 6 + 4 + 4))]
    pub compressed_size: u32,
    pub compression_method: u16,
    _unknown: [u8; 6],
    pub uncompressed_size: u32,
    _unknown2: u32, //[u8;4], // 0xffffff or 0x1a6
    #[br(pad_after=compressed_size%4, count = compressed_size)]
    // weird, should be aligned not pad_after. e.g. compr_size = 1 -> pad_after = 3... but it's not!
    compressed_data: Vec<u8>,
}

#[derive(Debug, BinRead)]
#[br(little,import{remaining_size: u32})]
pub struct CanMessage2 {
    pub header: ObjectHeader,
    pub channel: u16,
    pub flags: u8,
    pub dlc: u8,
    pub id: u32,
    #[br(count = remaining_size - ((std::mem::size_of::<ObjectHeader>() as u32)+(2+1+1+4+4+1+1+2)))]
    pub data: Vec<u8>,
    pub frame_length_ns: u32,
    pub bit_count: u8,
    _reserved1: u8,
    _reserved2: u16,
}

pub struct LogContainerIter {
    cursor: std::io::Cursor<Vec<u8>>,
}

impl LogContainerIter {
    fn new(data: Vec<u8>) -> LogContainerIter {
        LogContainerIter {
            cursor: std::io::Cursor::new(data),
        }
    }
    fn remaining_data(self) -> Vec<u8> {
        let pos = self.cursor.position() as usize;
        let data = self.cursor.into_inner();
        assert!(pos <= data.len(), "pos={} data.len()={}", pos, data.len());
        if pos < data.len() {
            data[pos..].to_vec()
        } else {
            vec![]
        }
    }
}

impl Iterator for LogContainerIter {
    type Item = Object;
    fn next(&mut self) -> Option<Self::Item> {
        match Object::read(&mut self.cursor) {
            Ok(obj) => Some(obj),
            Err(e) => {
                if e.is_eof() {
                    None
                } else {
                    match e {
                        binrw::Error::BadMagic { pos, .. } => {
                            println!("LogContainerIter: BadMagic, skipping 1 byte at pos={}", pos);
                            //self.skipped += 1;
                            self.cursor.seek(std::io::SeekFrom::Current(1)).unwrap();
                            self.next() // todo remove recursion!
                        }
                        _ => {
                            // println!("Error: {:?}", e);
                            None
                        }
                    }
                }
            }
        }
    }
}

impl LogContainer {
    pub fn into_iter(self, prev_data: &[u8]) -> LogContainerIter {
        match self.compression_method {
            0 => {
                if prev_data.is_empty() {
                    LogContainerIter::new(self.compressed_data)
                } else {
                    let mut data = Vec::with_capacity(prev_data.len() + self.compressed_data.len());
                    data.extend_from_slice(prev_data);
                    data.extend_from_slice(self.compressed_data.as_slice());
                    LogContainerIter::new(data)
                }
            }
            2 => {
                // zlib
                let options = DeflateOptions::default()
                    .set_limit(self.uncompressed_size as usize)
                    .set_size_hint(self.uncompressed_size as usize);
                let mut decoder =
                    DeflateDecoder::new_with_options(self.compressed_data.as_slice(), options);
                match decoder.decode_zlib() {
                    Ok(data) => {
                        if prev_data.is_empty() {
                            LogContainerIter::new(data)
                        } else {
                            let mut con_data = Vec::with_capacity(prev_data.len() + data.len());
                            con_data.extend_from_slice(prev_data);
                            con_data.extend_from_slice(data.as_slice());
                            LogContainerIter::new(con_data)
                        }
                    }
                    Err(e) => {
                        panic!("Error: {:?}", e);
                    }
                }
            }
            _ => {
                panic!("Unknown compression method");
            }
        }
    }
}

impl<R: BufRead> BlfFile<R> {
    pub fn is_compressed(&self) -> bool {
        self.file_stats.file_size != self.file_stats.uncompressed_size
    }
}

impl<R: BufRead + std::io::Seek> BlfFile<R> {
    pub fn from_reader(mut reader: R) -> Result<BlfFile<R>, std::io::Error> {
        // check header from the file whether it contains the magic number for blf files:
        // let _buf = reader.fill_buf()?;

        /*
        if buf.len() < 4 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "File is too short"));
        }
        let magic = &buf[0..4];
        if magic != b"LOGG" {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "File is not a BLF file"));
        }
        reader.consume(4);*/

        let file_stats = match BlfFileStats::read(&mut reader) {
            Ok(blf) => blf,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            }
        };

        Ok(BlfFile { reader, file_stats })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        assert_eq!(std::mem::size_of::<BlfFileStats>(), 144);
        //assert_eq!(std::mem::size_of::<Object>(), 12);
        //assert_eq!(std::mem::size_of::<LogContainer>(), 16+4);

        let file = std::fs::File::open("tests/empty.blf").unwrap();
        let reader = std::io::BufReader::new(file);
        let blf = BlfFile::from_reader(reader);
        assert!(blf.is_err());
    }

    #[test]
    fn uncompressed() {
        let file =
            std::fs::File::open("tests/technica/events_from_binlog/test_CanMessage.blf").unwrap();
        let reader = std::io::BufReader::new(file);
        let blf = BlfFile::from_reader(reader);
        assert!(blf.is_ok());
        let blf = blf.unwrap();
        println!("{:?}", blf.file_stats);
        assert_eq!(blf.file_stats.stats_size, 144);
        assert_eq!(blf.file_stats.api_version, 4070100);
        assert_eq!(blf.file_stats.file_size, 420);
        assert_eq!(blf.is_compressed(), false);

        // 2 outer, 4 inner objects

        // we expect the regular ObjectIterator to not return the 2 outer LogContainer objects
        let blf_iter = blf.into_iter();
        assert_eq!(blf_iter.count(), 4);
    }

    #[test]
    fn large() {
        if let Ok(file) = std::fs::File::open("tests/private/001__2024-04-26__18-52-20_1_L001.blf")
        {
            let reader = std::io::BufReader::new(file);

            let blf = BlfFile::from_reader(reader);
            assert!(blf.is_ok());
            let blf = blf.unwrap();
            println!("{:?}", blf.file_stats);
            assert_eq!(blf.file_stats.stats_size, 144);
            assert_eq!(blf.file_stats.api_version, 4090103);
            assert_eq!(blf.file_stats.file_size, 17267752);
            assert_eq!(blf.is_compressed(), true);

            let blf_iter = blf.into_iter();
            assert_eq!(blf_iter.count(), 1933994);

            // re-use the blf (not possible as the iter consumes)
            /*
            let file = std::fs::File::open("tests/private/001__2024-04-26__18-52-20_1_L001.blf").unwrap();
            let reader = std::io::BufReader::new(file);

            let blf = BlfFile::from_reader(reader);
            assert!(blf.is_ok());
            let blf_iter = blf.unwrap().into_iter();
            for (idx, obj) in blf_iter.enumerate() {
                println!("({})={:?}", idx+1, obj);
            }
            */
        }
    }
}
