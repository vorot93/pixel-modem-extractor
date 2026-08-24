use std::io::{Result, Write};

pub(crate) struct JsonWriter<W> {
    sink: W,
    depth: usize,
    empty_container: bool,
}

impl<W: Write> JsonWriter<W> {
    pub(crate) fn new(sink: W) -> Self {
        JsonWriter {
            sink,
            depth: 0,
            empty_container: false,
        }
    }

    pub(crate) fn open_object(&mut self) -> Result<()> {
        self.sink.write_all(b"{")?;
        self.depth += 1;
        self.empty_container = true;
        Ok(())
    }

    pub(crate) fn close_object(&mut self) -> Result<()> {
        self.depth -= 1;
        self.close(b"}")
    }

    pub(crate) fn open_array(&mut self) -> Result<()> {
        self.sink.write_all(b"[")?;
        self.depth += 1;
        self.empty_container = true;
        Ok(())
    }

    pub(crate) fn close_array(&mut self) -> Result<()> {
        self.depth -= 1;
        self.close(b"]")
    }

    pub(crate) fn key(&mut self, first: bool, name: &str) -> Result<()> {
        self.empty_container = false;
        if !first {
            self.sink.write_all(b",")?;
        }
        self.sink.write_all(b"\n")?;
        self.indent()?;
        self.sink.write_all(b"\"")?;
        self.escaped(name)?;
        self.sink.write_all(b"\": ")
    }

    pub(crate) fn element(&mut self, first: bool) -> Result<()> {
        self.empty_container = false;
        if !first {
            self.sink.write_all(b",")?;
        }
        self.sink.write_all(b"\n")?;
        self.indent()
    }

    pub(crate) fn string_value(&mut self, value: &str) -> Result<()> {
        self.sink.write_all(b"\"")?;
        self.escaped(value)?;
        self.sink.write_all(b"\"")
    }

    pub(crate) fn u64_value(&mut self, value: u64) -> Result<()> {
        self.sink.write_all(value.to_string().as_bytes())
    }

    pub(crate) fn u32_hex_value(&mut self, value: u32) -> Result<()> {
        self.sink.write_all(format!("\"0x{value:08x}\"").as_bytes())
    }

    pub(crate) fn hex_value(&mut self, digest: &[u8; 32]) -> Result<()> {
        self.sink.write_all(b"\"")?;
        self.sink
            .write_all(crate::manifest::blake3_fixed(*digest).as_bytes())?;
        self.sink.write_all(b"\"")
    }

    pub(crate) fn bool_value(&mut self, value: bool) -> Result<()> {
        self.sink.write_all(if value { b"true" } else { b"false" })
    }

    pub(crate) fn null_value(&mut self) -> Result<()> {
        self.sink.write_all(b"null")
    }

    pub(crate) fn into_inner(self) -> W {
        self.sink
    }

    fn close(&mut self, bracket: &[u8]) -> Result<()> {
        let empty = self.empty_container;
        self.empty_container = false;
        if empty {
            self.sink.write_all(bracket)
        } else {
            self.sink.write_all(b"\n")?;
            self.indent()?;
            self.sink.write_all(bracket)
        }
    }

    fn indent(&mut self) -> Result<()> {
        for _ in 0..self.depth {
            self.sink.write_all(b"  ")?;
        }
        Ok(())
    }

    fn escaped(&mut self, value: &str) -> Result<()> {
        for byte in value.bytes() {
            match byte {
                b'"' => self.sink.write_all(b"\\\"")?,
                b'\\' => self.sink.write_all(b"\\\\")?,
                b'\n' => self.sink.write_all(b"\\n")?,
                b'\t' => self.sink.write_all(b"\\t")?,
                0x00..=0x1f => self.sink.write_all(format!("\\u{byte:04x}").as_bytes())?,
                _ => self.sink.write_all(&[byte])?,
            }
        }
        Ok(())
    }
}
