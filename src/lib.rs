pub mod cli;
pub mod hash;
pub mod output;
pub mod pax;
pub mod process;

pub const DEFAULT_BUFFER_SIZE: usize = 2 * 1024 * 1024;
pub const MIN_BUFFER_SIZE: usize = 512;
