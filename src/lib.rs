//! Multiwii Serial Protocol (MSP) traffic decoder and structures
//!
//! Incomplete. Includes some structures from Cleanflight and Betaflight.
#![no_std]

extern crate alloc;
extern crate packed_struct;
extern crate crc_any;
extern crate serde_derive;

extern crate serde;

mod commands;
mod packet;
pub mod structs;

pub use commands::*;
pub use packet::*;
