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
            match iter.next() {
                Some(obj) => return Some(obj),
                None => {}
            }
        }
        if self.cur_cont_iter.is_some() {
            // if we reach here, the cur_cont_iter returned None
            let cont_iter = self.cur_cont_iter.take().unwrap();
            self.prev_cont_data = cont_iter.remaining_data();
        }

        match Object::read(&mut self.blf.reader) {
            Ok(obj) => {
                let mut unprocessed =
                    if obj.object_size > (std::mem::size_of::<Object>() + 4) as u32 {
                        obj.object_size - (std::mem::size_of::<Object>() + 4) as u32
                    } else {
                        0
                    };
                let to_skip = match obj.object_type {
                    10 => {
                        match LogContainer::read_args(
                            &mut self.blf.reader,
                            LogContainerBinReadArgs {
                                object_size: unprocessed,
                            },
                        ) {
                            Ok(obj) => {
                                self.cur_cont_iter = Some(obj.into_iter(&self.prev_cont_data));
                                0
                            }
                            Err(e) => {
                                println!("ObjectIterator Error: {:?}", e);
                                1
                            }
                        }
                    }
                    _ => {
                        println!(
                            "ObjectIterator: unknown object type {}, unprocessed={}",
                            obj.object_type, unprocessed
                        );
                        if [65, 72, 6, 7, 8, 9, 90, 96, 92].contains(&obj.object_type) {
                            unprocessed += unprocessed % 4; // if unprocessed %4 >0 {4-(unprocessed % 4)}else{0}; // align to 4 bytes (weird here again)
                        }
                        //unprocessed += if unprocessed %4 >0 {4-(unprocessed % 4)}else{0}; // align to 4 bytes (weird here again)
                        unprocessed
                    }
                };
                if to_skip > 0 {
                    println!("ObjectIterator: skipping {}", to_skip);
                    let old_pos = self.blf.reader.stream_position().unwrap();
                    self.blf
                        .reader
                        .seek(std::io::SeekFrom::Current(to_skip as i64))
                        .unwrap();
                    let new_pos = self.blf.reader.stream_position().unwrap();
                    assert_eq!(new_pos - old_pos, unprocessed as u64);
                }
                if self.cur_cont_iter.is_none() {
                    return Some(obj);
                }

                if let Some(iter) = &mut self.cur_cont_iter {
                    match iter.next() {
                        Some(obj) => return Some(obj),
                        None => {}
                    }
                }
                // if we reach here, the cur_cont_iter returned None
                let cont_iter = self.cur_cont_iter.take().unwrap();
                self.prev_cont_data = cont_iter.remaining_data();
                return self.next(); // todo remove recursion
            }
            Err(e) => {
                if e.is_eof() {
                    return None;
                } else {
                    match e {
                        binrw::Error::BadMagic { pos, .. } => {
                            println!("ObjectIterator: BadMagic, skipping 1 byte at pos={}", pos);
                            self.skipped += 1;
                            self.blf.reader.seek(std::io::SeekFrom::Current(1)).unwrap();
                            return self.next(); // todo remove recursion!
                        }
                        _ => {
                            println!("Error: {:?}", e);
                            return None;
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

#[derive(Debug, BinRead)]
#[br(little, magic = b"LOBJ")]
pub struct Object {
    pub header_size: u16,
    pub header_version: u16,
    pub object_size: u32,
    pub object_type: u32,
}

#[derive(Debug, BinRead)]
#[br(little,import{object_size: u32})]
struct LogContainer {
    // object_type == 10
    #[br(calc = object_size - (2 + 6 + 4 + 4))]
    compressed_size: u32,
    compression_method: u16,
    unknown: [u8; 6],
    uncompressed_size: u32,
    unknown2: u32, //[u8;4], // 0xffffff or 0x1a6
    #[br(pad_after=compressed_size%4, count = compressed_size)]
    // weird, should be aligned not pad_after. e.g. compr_size = 1 -> pad_after = 3... but it's not!
    compressed_data: Vec<u8>,
}

struct LogContainerIter {
    data_len: usize,
    cursor: std::io::Cursor<Vec<u8>>,
}

impl LogContainerIter {
    fn new(data: Vec<u8>) -> LogContainerIter {
        LogContainerIter {
            data_len: data.len(),
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
        let init_pos = self.cursor.position();
        match Object::read(&mut self.cursor) {
            Ok(obj) => {
                let mut unprocessed =
                    if obj.object_size > (std::mem::size_of::<Object>() + 4) as u32 {
                        obj.object_size - (std::mem::size_of::<Object>() + 4) as u32
                    } else {
                        0
                    };
                let to_skip = match obj.object_type {
                    _ => {
                        /*println!(
                            "LogContainerIter: unknown object type {}, unprocessed={}",
                            obj.object_type, unprocessed
                        );*/
                        if [65, 72, 6, 7, 8, 9, 90, 96, 92].contains(&obj.object_type) {
                            unprocessed += unprocessed % 4; // if unprocessed %4 >0 {4-(unprocessed % 4)}else{0}; // align to 4 bytes (weird here again)
                        }
                        //unprocessed += if unprocessed %4 >0 {4-(unprocessed % 4)}else{0}; // align to 4 bytes (weird here again)
                        unprocessed
                    }
                };
                if to_skip > 0 {
                    let old_pos = self.cursor.position();
                    if old_pos + to_skip as u64 > self.data_len as u64 {
                        //println!("LogContainerIter: skipping {} > data_len", to_skip);
                        // need to seek back and return the rem. data properly as this obj is not fully avail
                        self.cursor
                            .seek(std::io::SeekFrom::Start(init_pos))
                            .unwrap();
                        return None;
                    }
                    //println!("LogContainerIter: skipping {}", to_skip);
                    self.cursor
                        .seek(std::io::SeekFrom::Current(to_skip as i64))
                        .unwrap();
                }
                Some(obj)
            }
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
                            println!("Error: {:?}", e);
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
                let options = DeflateOptions::default().set_limit(self.uncompressed_size as usize).set_size_hint(self.uncompressed_size as usize);
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

    /*
    pub fn iterate_objects(&self, prev_data: &[u8]) -> std::io::Result<(u64, usize, Option<Vec<u8>>)> {
        let process_data = |data: &[u8]| {
            let mut nr_objects = 0usize;
            println!(
                " container data.len={:?}, unknown={:?}, unknown2={:?}",
                data.len(),
                self.unknown,
                self.unknown2
            );
            assert_eq!(
                data.len() - prev_data.len(),
                self.uncompressed_size as usize
            );
            let mut processed = 0;
            let mut cursor = std::io::Cursor::new(data);
            match iterate_objects(&mut cursor) {
                Ok((amount, nr_objects_processed)) => {
                    nr_objects += nr_objects_processed;
                    processed += amount;
                }
                Err(e) => {
                    println!(
                        "  container Error: {:?} at pos={}, data={:x?} prev_data={:x?}",
                        e,
                        cursor.position(),
                        &data[..80],
                        &prev_data
                    );
                }
            }
            let rem_data = if cursor.position() < data.len() as u64 {
                let rem_data = &data[cursor.position() as usize..];
                println!("  container remaining data.len()={}", &rem_data.len());
                Some(rem_data.to_vec())
            } else {
                None
            };
            Ok((processed, nr_objects, rem_data))
        };

        let res = match self.compression_method {
            0 => {
                if prev_data.is_empty() {
                    process_data(self.compressed_data.as_slice())
                } else {
                    let mut data = Vec::with_capacity(prev_data.len() + self.compressed_data.len());
                    data.extend_from_slice(prev_data);
                    data.extend_from_slice(self.compressed_data.as_slice());
                    process_data(data.as_slice())
                }
            }
            2 => {
                // zlib
                let options = DeflateOptions::default(); // .set_limit(self.uncompressed_size as usize).set_size_hint(self.uncompressed_size as usize);
                let mut decoder =
                    DeflateDecoder::new_with_options(self.compressed_data.as_slice(), options);
                match decoder.decode_zlib() {
                    Ok(data) => {
                        if prev_data.is_empty() {
                            process_data(data.as_slice())
                        } else {
                            let mut con_data = Vec::with_capacity(prev_data.len() + data.len());
                            con_data.extend_from_slice(prev_data);
                            con_data.extend_from_slice(data.as_slice());
                            process_data(con_data.as_slice())
                        }
                    }
                    Err(e) => Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    )),
                }
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unknown compression method",
            )),
        };
        println!(
            "  container processed={:?}",
            res.as_ref()
                .map(|(processed, nr_objects, rem)| (processed, nr_objects, rem.as_ref().map(|r| r.len())))
        );
        res
        //Ok(())
    }*/
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

    /*pub fn iterate_objects(&mut self) -> std::io::Result<(u64, usize)> {
        self.reader
            .seek(std::io::SeekFrom::Start(self.file_stats.stats_size as u64))?;
        iterate_objects(&mut self.reader)
    }*/
}
/*
fn iterate_objects<R: BufRead + std::io::Seek>(reader: &mut R) -> std::io::Result<(u64, usize)> {
    let start_pos = reader.stream_position()?;
    let mut prev_data = Vec::new();
    let mut skipped = 0;
    let mut nr_objects = 0usize;
    loop {
        let object = match Object::read(reader) {
            Ok(obj) => obj,
            Err(e) => {
                if e.is_eof() {
                    break;
                } else {
                    match e {
                        binrw::Error::BadMagic { pos, .. } => {
                            if skipped == 0 || pos != skipped ||true{
                                println!(
                                    "BadMagic, skipping 1 byte at pos={}, skipped={}",
                                    pos, skipped
                                );
                            }
                            skipped += 1;
                            reader.seek(std::io::SeekFrom::Current(1))?;
                            continue;
                        }
                        _ => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                e.to_string(),
                            ));
                        }
                    }
                }
            }
        };
        nr_objects += 1;
        // println!("{:?}", object);
        let mut unprocessed = if object.object_size > (std::mem::size_of::<Object>() + 4) as u32 {
            object.object_size - (std::mem::size_of::<Object>() + 4) as u32
        } else {
            0
        };
        let to_skip = match object.object_type {
            10 => {
                let container = match LogContainer::read_args(
                    reader,
                    LogContainerBinReadArgs {
                        object_size: unprocessed,
                    },
                ) {
                    Ok(obj) => obj,
                    Err(e) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            e.to_string(),
                        ))
                    }
                };
                println!(
                    "container compressed_size={}, uncompressed_size={}",
                    container.compressed_size, container.uncompressed_size
                );
                assert_eq!(
                    container.compressed_size,
                    container.compressed_data.len() as u32
                );
                let (processed, _nr_objects_processed, rem_data) = container.iterate_objects(&prev_data)?;
                //nr_objects += nr_objects_processed;
                if rem_data.is_some() && processed > 0 {
                    prev_data = rem_data.unwrap();
                } else {
                    prev_data.clear();
                }
                0 // LogContainer reads already all data
            }
            /*4 => {
                // CAN stats
                assert_eq!(unprocessed, 16 + 2 + 2 + 4 + 4 + 4 + 4 + 4 + 4 + 4);
                // flags(4), clientIndex(2), objectVerion(2), objectTimeStamp(8)
                // channel(2), busload(2), standard(4), extended(4), remote(4), remoteExt(4), error(4), overload(4), reserved(4)
                unprocessed
            }*/
            86 => {
                // CAN message 2
                let old_pos = reader.stream_position()?;
                reader.seek(std::io::SeekFrom::Current(unprocessed as i64))?;
                let new_pos = reader.stream_position()?;
                assert_eq!(new_pos - old_pos, unprocessed as u64);
                0
            }
            115| 31 |4|73=> {
                // to skip/ignore
                let old_pos = reader.stream_position()?;
                reader.seek(std::io::SeekFrom::Current(unprocessed as i64))?;
                let new_pos = reader.stream_position()?;
                assert_eq!(new_pos - old_pos, unprocessed as u64);
                0
            }
            _ => {
                println!(
                    "unknown object type {}, unprocessed={}",
                    object.object_type, unprocessed
                );
                if [65, 72, 6,7,8,9,90, 96,92 ].contains(&object.object_type) {
                    unprocessed += unprocessed % 4; // if unprocessed %4 >0 {4-(unprocessed % 4)}else{0}; // align to 4 bytes (weird here again)
                }
                //unprocessed += if unprocessed %4 >0 {4-(unprocessed % 4)}else{0}; // align to 4 bytes (weird here again)
                unprocessed
            }
        };
        if to_skip > 0 {
            println!("skipping {}", to_skip);
            let old_pos = reader.stream_position()?;
            reader.seek(std::io::SeekFrom::Current(to_skip as i64))?; // todo this can (and does) skip beyond the end!
            let new_pos = reader.stream_position()?;
            assert_eq!(new_pos - old_pos, unprocessed as u64);
        }
    }
    if skipped > 1 {
        println!("BadMagic, skipped total {} bytes", skipped);
    }
    let end_pos = reader.stream_position()?;
    Ok((end_pos - start_pos, nr_objects))
}
*/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        assert_eq!(std::mem::size_of::<BlfFileStats>(), 144);
        assert_eq!(std::mem::size_of::<Object>(), 12);
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
        if let Ok(file) = std::fs::File::open("tests/private/001__2024-04-26__18-52-20_1_L001.blf"){
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
        let file = std::fs::File::open("tests/private/001__2024-04-26__18-52-20_1_L001.blf").unwrap();
        let reader = std::io::BufReader::new(file);

        let blf = BlfFile::from_reader(reader);
        assert!(blf.is_ok());
        let blf_iter = blf.into_iter();
        for (_idx, _obj) in blf_iter.enumerate() {
            //println!("({})={:?}", idx+1, obj);
        }
    }
    }
}
