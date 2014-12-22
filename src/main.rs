use std::io::BufferedReader;
use std::error::Error;

static FTEXT    : u8 = 0b00000001;
static FHCRC    : u8 = 0b00000010;
static FEXTRA   : u8 = 0b00000100;
static FNAME    : u8 = 0b00001000;
static FCOMMENT : u8 = 0b00010000;

struct GzipHeader {
    method: u8,
    flg: u8,
    mtime: u32,
    xfl: u8,
    os: u8,
    fextra_count: uint,
    fname: Option<String>,
    fcomment: Option<String>,
    fhcrc: Option<u16>
}

struct GzipReader<'a> {
    reader: &'a mut (Reader + 'a),
}

impl<'a> GzipReader<'a> {
    fn new(reader: &'a mut Reader) -> GzipReader<'a> {
        GzipReader { reader: reader }
    }

    fn handle_fextra(&mut self) -> Result<uint, String> {
        let mut xlen = match self.reader.read_le_u16() {
            Err(e) => return Err(e.description().into_string()),
            Ok(v) => v
        };
        let mut fextra_count = 0;
        while xlen > 0 {
            if xlen < 4 {
                return Err("malformed FEXTRA".into_string());
            }

            // two bytes for subfield id
            match self.reader.read_byte() {
                Err(e) => return Err(e.description().into_string()),
                Ok(_) => ()
            };
            match self.reader.read_byte() {
                Err(e) => return Err(e.description().into_string()),
                Ok(_) => ()
            };

            let len = match self.reader.read_le_u16() {
                Err(e) => return Err(e.description().into_string()),
                Ok(b) => b
            };
            xlen = xlen - 4;
            if xlen < len {
                return Err("malformed FEXTRA".into_string());
            }

            // subfield itself
            match self.reader.read_exact(len.to_uint().unwrap()) {
                Err(e) => return Err(e.description().into_string()),
                Ok(_) => ()
            };

            xlen = xlen - len;
            fextra_count = fextra_count + 1;
        }
        Ok(fextra_count)
    }

    fn read_gzip_header(&mut self) -> Result<GzipHeader, String> {
        let m1_res     = self.reader.read_byte();
        let m2_res     = self.reader.read_byte();
        let method_res = self.reader.read_byte();
        let flg_res    = self.reader.read_byte();
        let mtime_res  = self.reader.read_le_u32();
        let xfl_res    = self.reader.read_byte();
        let os_res     = self.reader.read_byte();

        if m1_res.is_err() || m2_res.is_err() ||
            method_res.is_err() ||
            flg_res.is_err() ||
            mtime_res.is_err() ||
            xfl_res.is_err() ||
            os_res.is_err()
        {
            return Err("malformed gzip header".into_string());
        }

        let m1     = m1_res.unwrap();
        let m2     = m2_res.unwrap();
        let method = method_res.unwrap();
        let flg    = flg_res.unwrap();
        let mtime  = mtime_res.unwrap();
        let xfl    = xfl_res.unwrap();
        let os     = os_res.unwrap();

        if m1 != 0x1f_u8 || m2 != 0x8b_u8 {
            return Err("magic mismatch".into_string())
        }

        if flg & FTEXT != 0 {
            // FTEXT set.
        }

        let fextra_count =
            if flg & FEXTRA != 0 {
                try!(self.handle_fextra())
            } else {
                0
            };

        let fname =
            if flg & FNAME != 0 {
                Some(try!(read_c_utf8_str(&mut self.reader)))
            } else {
                None
            };

        let fcomment =
            if flg & FCOMMENT != 0 {
                Some(try!(read_c_utf8_str(&mut self.reader)))
            } else {
                None
            };

        let fhcrc =
            if flg & FHCRC != 0 {
                match self.reader.read_le_u16() {
                    Err(e) => return Err(e.description().into_string()),
                    Ok(v) => Some(v)
                }
            } else {
                None
            };

        Ok(GzipHeader {
            method: method,
            flg: flg,
            mtime: mtime,
            xfl: xfl,
            os: os,
            fextra_count: fextra_count,
            fname: fname,
            fcomment: fcomment,
            fhcrc: fhcrc
        })
    }

}

fn read_c_utf8_str(reader: &mut Reader) -> Result<String, String> {
    let mut chars: Vec<u8> = Vec::new();
    loop {
        let c = reader.read_byte();
        match c {
            Ok(0x00_u8) => break,
            Err(e) => return Err(e.description().into_string()),
            _ => ()
        }
        chars.push(c.unwrap());
    }

    match String::from_utf8(chars) {
        Ok(s) => Ok(s),
        Err(_) => Err("expected utf8 string".into_string())
    }
}

fn main() {
    let mut reader = BufferedReader::new(std::io::stdio::stdin());
    let mut gzip_reader = GzipReader::new(&mut reader);

    let header = match gzip_reader.read_gzip_header() {
        Err(e) => panic!("reading gzip header failed: {}", e),
        Ok(h) => h
    };

    println!("gzip header: method 0x{:x}, flg 0x{:x}, mtime {}, xfl 0x{:x}, os 0x{:x}, fextra_count 0x{:x}, fname {}, fcomment {}, fhcrc {}",
             header.method,
             header.flg,
             header.mtime,
             header.xfl,
             header.os,
             header.fextra_count,
             header.fname,
             header.fcomment,
             header.fhcrc);
}
