use shared::error::SharedError;

use crate::commands::DeviceTransport;
use crate::commands::set_time;

pub fn run<P>(port: &mut P) -> Result<(), SharedError>
where
    P: DeviceTransport + ?Sized,
{
    set_time::run_get_time(port)
}
