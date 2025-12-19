//! # UDP ソケット (HTTP/3 用)
//!
//! monoio io_uring と統合した高パフォーマンス UDP ソケットを提供します。
//! GSO (Generic Segmentation Offload) と GRO (Generic Receive Offload) をサポート。

pub mod socket;

pub use socket::QuicUdpSocket;
