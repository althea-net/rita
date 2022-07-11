use crate::KernelInterfaceError as Error;
use std::fmt::Write as _;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;

pub fn get_lines(filename: &str) -> Result<Vec<String>, Error> {
    let f = File::open(filename)?;
    let file = BufReader::new(&f);
    let mut out_lines = Vec::new();
    for line in file.lines() {
        match line {
            Ok(val) => out_lines.push(val),
            Err(_) => break,
        }
    }

    Ok(out_lines)
}

pub fn write_out(filename: &str, content: Vec<String>) -> Result<(), Error> {
    // overwrite the old version
    let mut file = File::create(filename)?;
    let mut final_output = String::new();
    for item in content {
        writeln!(final_output, "{}", item).unwrap();
    }
    file.write_all(final_output.as_bytes())?;
    Ok(())
}
