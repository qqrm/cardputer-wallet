use std::io::{Read, Write};

use shared::error::SharedError;

use crate::commands::set_time;

pub fn run<P>(port: &mut P) -> Result<(), SharedError>
where
    P: Read + Write + ?Sized,
{
    set_time::run_get_time(port)
}
