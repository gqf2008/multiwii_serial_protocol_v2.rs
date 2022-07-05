use super::Command;
use alloc::vec::Vec;
use core::mem;
use core::mem::size_of;
use crc_any::CRCu8;

/// Packet parsing error
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ParseError {
    OutputBufferSizeMismatch,
    CrcMismatch { expected: u8, calculated: u8 },
    InvalidData,
    InvalidHeader1,
    InvalidHeader2,
    InvalidDirection,
    InvalidDataLength,
}

/// Packet's desired destination
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Direction {
    /// Network byte '<'
    Request,
    /// Network byte '>'
    Response,
    /// Network byte '!'
    Unsupported,
}

impl Direction {
    pub fn to_byte(&self) -> u8 {
        let b = match *self {
            Direction::Request => '<',
            Direction::Response => '>',
            Direction::Unsupported => '!',
        };
        b as u8
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    pub cmd: Command,
    pub code: u16,
    pub direction: Direction,
    pub data: Vec<u8>,
}

impl Packet {
    pub fn new(cmd: Command) -> Self {
        Self {
            cmd,
            code: cmd as u16,
            direction: Direction::Response,
            data: Vec::new(),
        }
    }
    pub fn new_code(code: u16) -> Self {
        Self {
            cmd: Command::Unknown,
            code: code,
            direction: Direction::Response,
            data: Vec::new(),
        }
    }
    pub fn with_direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    pub fn append_data(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
enum State {
    Header1,
    Header2,
    Direction,
    FlagV2,
    DataLength,
    DataLengthV2,
    Command,
    CommandV2,
    Data,
    DataV2,
    Crc,
}

#[derive(Copy, Clone, PartialEq, Debug)]
enum Version {
    V1,
    V2,
}

#[derive(Debug)]
/// Parser that can find packets from a raw byte stream
pub struct Parser {
    state: State,
    packet_version: Version,
    packet_direction: Direction,
    packet_cmd: u16,
    packet_data_length_remaining: usize,
    packet_data: Vec<u8>,
    packet_crc: u8,
    packet_crc_v2: CRCu8,
}

impl Parser {
    /// Create a new parser
    pub fn new() -> Parser {
        Self {
            state: State::Header1,
            packet_version: Version::V1,
            packet_direction: Direction::Request,
            packet_data_length_remaining: 0,
            packet_cmd: 0,
            packet_data: Vec::new(),
            packet_crc: 0,
            packet_crc_v2: CRCu8::crc8dvb_s2(),
        }
    }

    /// Are we waiting for the header of a brand new packet?
    pub fn state_is_between_packets(&self) -> bool {
        self.state == State::Header1
    }

    /// Parse the next input byte. Returns a valid packet whenever a full packet is received, otherwise
    /// restarts the state of the parser.
    pub fn parse(&mut self, input: u8) -> Result<Option<Packet>, ParseError> {
        match self.state {
            State::Header1 => {
                if input == b'$' {
                    self.state = State::Header2;
                } else {
                    self.reset();
                }
            }

            State::Header2 => {
                self.packet_version = match input as char {
                    'M' => Version::V1,
                    'X' => Version::V2,
                    _ => {
                        self.reset();
                        return Err(ParseError::InvalidHeader2);
                    }
                };

                self.state = State::Direction;
            }

            State::Direction => {
                match input {
                    60 => self.packet_direction = Direction::Request, // '>'
                    62 => self.packet_direction = Direction::Response, // '<'
                    33 => self.packet_direction = Direction::Unsupported, // '!' error
                    _ => {
                        self.reset();
                        return Err(ParseError::InvalidDirection);
                    }
                }

                self.state = match self.packet_version {
                    Version::V1 => State::DataLength,
                    Version::V2 => State::FlagV2,
                };
            }

            State::FlagV2 => {
                // uint8, flag, usage to be defined (set to zero)
                self.state = State::CommandV2;
                self.packet_data = Vec::with_capacity(2);
                self.packet_crc_v2.digest(&[input]);
            }

            State::CommandV2 => {
                self.packet_data.push(input);

                if self.packet_data.len() == 2 {
                    let mut s = [0u8; size_of::<u16>()];
                    s.copy_from_slice(&self.packet_data);
                    self.packet_cmd = u16::from_le_bytes(s);

                    self.packet_crc_v2.digest(&self.packet_data);
                    self.packet_data.clear();
                    self.state = State::DataLengthV2;
                }
            }

            State::DataLengthV2 => {
                self.packet_data.push(input);

                if self.packet_data.len() == 2 {
                    let mut s = [0u8; size_of::<u16>()];
                    s.copy_from_slice(&self.packet_data);
                    self.packet_data_length_remaining = u16::from_le_bytes(s).into();
                    self.packet_crc_v2.digest(&self.packet_data);
                    self.packet_data =
                        Vec::with_capacity(self.packet_data_length_remaining as usize);

                    if self.packet_data_length_remaining == 0 {
                        self.state = State::Crc;
                    } else {
                        self.state = State::DataV2;
                    }
                }
            }

            State::DataV2 => {
                self.packet_data.push(input);
                self.packet_data_length_remaining -= 1;

                if self.packet_data_length_remaining == 0 {
                    self.state = State::Crc;
                }
            }

            State::DataLength => {
                self.packet_data_length_remaining = input as usize;
                self.state = State::Command;
                self.packet_crc ^= input;
                self.packet_data = Vec::with_capacity(input as usize);
            }

            State::Command => {
                self.packet_cmd = input as u16;

                if self.packet_data_length_remaining == 0 {
                    self.state = State::Crc;
                } else {
                    self.state = State::Data;
                }

                self.packet_crc ^= input;
            }

            State::Data => {
                self.packet_data.push(input);
                self.packet_data_length_remaining -= 1;

                self.packet_crc ^= input;

                if self.packet_data_length_remaining == 0 {
                    self.state = State::Crc;
                }
            }

            State::Crc => {
                if self.packet_version == Version::V2 {
                    self.packet_crc_v2.digest(&self.packet_data);
                    self.packet_crc = self.packet_crc_v2.get_crc();
                }

                let packet_crc = self.packet_crc;
                if input != packet_crc {
                    self.reset();
                    return Err(ParseError::CrcMismatch {
                        expected: input,
                        calculated: packet_crc,
                    });
                }

                let mut n = Vec::new();
                mem::swap(&mut self.packet_data, &mut n);

                let packet = Packet {
                    cmd: Command::from(self.packet_cmd),
                    code: self.packet_cmd,
                    direction: self.packet_direction,
                    data: n,
                };

                self.reset();

                return Ok(Some(packet));
            }
        }

        Ok(None)
    }

    pub fn reset(&mut self) {
        self.state = State::Header1;
        self.packet_direction = Direction::Request;
        self.packet_data_length_remaining = 0;
        self.packet_cmd = 0;
        self.packet_data.clear();
        self.packet_crc = 0;
        self.packet_crc_v2.reset();
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Packet {
    /// Number of bytes that this packet requires to be packed
    pub fn packet_size_bytes(&self) -> usize {
        6 + self.data.len()
    }

    /// Number of bytes that this packet requires to be packed
    pub fn packet_size_bytes_v2(&self) -> usize {
        9 + self.data.len()
    }

    /// Serialize to network bytes
    pub fn serialize(&self, output: &mut [u8]) -> Result<(), ParseError> {
        let l = output.len();

        if l != self.packet_size_bytes() {
            return Err(ParseError::OutputBufferSizeMismatch);
        }

        output[0] = b'$';
        output[1] = b'M';
        output[2] = self.direction.to_byte();
        output[3] = self.data.len() as u8;
        output[4] = self.code as u8;

        output[5..l - 1].copy_from_slice(&self.data);

        let mut crc = output[3] ^ output[4];
        for b in &*self.data {
            crc ^= *b;
        }
        output[l - 1] = crc;

        Ok(())
    }

    /// Serialize to network bytes
    pub fn serialize_v2(&self, output: &mut [u8]) -> Result<(), ParseError> {
        let l = output.len();

        if l != self.packet_size_bytes_v2() {
            return Err(ParseError::OutputBufferSizeMismatch);
        }

        output[0] = b'$';
        output[1] = b'X';
        output[2] = self.direction.to_byte();
        output[3] = 0;
        output[4..6].copy_from_slice(&self.code.to_le_bytes());
        output[6..8].copy_from_slice(&(self.data.len() as u16).to_le_bytes());

        output[8..l - 1].copy_from_slice(&self.data);

        let mut crc = CRCu8::crc8dvb_s2();
        crc.digest(&output[3..l - 1]);
        output[l - 1] = crc.get_crc();

        Ok(())
    }
}
