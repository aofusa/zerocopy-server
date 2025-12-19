//! # HTTP/2 フレーム処理 (RFC 7540 Section 4, 6)
//!
//! HTTP/2 フレームのエンコードとデコードを提供します。

pub mod types;
pub mod encoder;
pub mod decoder;

pub use types::{FrameType, FrameHeader, Frame, FrameFlags};
pub use encoder::FrameEncoder;
pub use decoder::FrameDecoder;
