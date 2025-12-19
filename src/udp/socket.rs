//! # QUIC 用 UDP ソケット
//!
//! monoio と統合した UDP ソケット実装。
//! Linux GSO/GRO をサポートして高スループットを実現。

use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;

use monoio::net::udp::UdpSocket;

/// GSO セグメントサイズ
const GSO_SEGMENT_SIZE: usize = 1200;

/// 受信バッファサイズ
const RECV_BUFFER_SIZE: usize = 65536;

/// QUIC 用 UDP ソケット
pub struct QuicUdpSocket {
    /// 内部 UDP ソケット
    socket: UdpSocket,
    /// GSO 有効化フラグ
    gso_enabled: bool,
    /// GRO 有効化フラグ
    gro_enabled: bool,
    /// ローカルアドレス
    local_addr: SocketAddr,
}

impl QuicUdpSocket {
    /// 新しいソケットをバインド
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        let local_addr = socket.local_addr()?;

        let mut instance = Self {
            socket,
            gso_enabled: false,
            gro_enabled: false,
            local_addr,
        };

        // GSO/GRO を設定
        instance.configure_gso_gro()?;

        Ok(instance)
    }

    /// GSO/GRO を設定
    fn configure_gso_gro(&mut self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;

            let fd = self.socket.as_raw_fd();

            // UDP_SEGMENT (GSO) を有効化
            let gso_size: libc::c_int = GSO_SEGMENT_SIZE as libc::c_int;
            let result = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_UDP,
                    libc::UDP_SEGMENT,
                    &gso_size as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            self.gso_enabled = result == 0;

            // UDP_GRO を有効化
            let gro_enabled: libc::c_int = 1;
            let result = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_UDP,
                    libc::UDP_GRO,
                    &gro_enabled as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            self.gro_enabled = result == 0;

            // 受信バッファサイズを増加
            let recv_buf_size: libc::c_int = 2 * 1024 * 1024; // 2MB
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &recv_buf_size as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }

            // 送信バッファサイズを増加
            let send_buf_size: libc::c_int = 2 * 1024 * 1024; // 2MB
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &send_buf_size as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        Ok(())
    }

    /// パケットを受信
    pub async fn recv_from(&self, buf: Vec<u8>) -> (io::Result<(usize, SocketAddr)>, Vec<u8>) {
        self.socket.recv_from(buf).await
    }

    /// パケットを送信
    pub async fn send_to(&self, buf: Vec<u8>, target: SocketAddr) -> (io::Result<usize>, Vec<u8>) {
        self.socket.send_to(buf, target).await
    }

    /// 複数パケットを GSO で送信 (Linux のみ)
    #[cfg(target_os = "linux")]
    pub async fn send_gso(&self, packets: &[&[u8]], target: SocketAddr) -> io::Result<usize> {
        if !self.gso_enabled || packets.is_empty() {
            // GSO 無効または空の場合は個別送信
            let mut total = 0;
            for packet in packets {
                let buf = packet.to_vec();
                let (result, _) = self.socket.send_to(buf, target).await;
                total += result?;
            }
            return Ok(total);
        }

        // パケットを結合
        let mut combined = Vec::with_capacity(packets.iter().map(|p| p.len()).sum());
        for packet in packets {
            combined.extend_from_slice(packet);
        }

        let (result, _) = self.socket.send_to(combined, target).await;
        result
    }

    /// GSO が有効かどうか
    pub fn gso_enabled(&self) -> bool {
        self.gso_enabled
    }

    /// GRO が有効かどうか
    pub fn gro_enabled(&self) -> bool {
        self.gro_enabled
    }

    /// ローカルアドレスを取得
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// 内部ソケットへの参照を取得
    pub fn inner(&self) -> &UdpSocket {
        &self.socket
    }
}

/// 受信バッファを作成
pub fn create_recv_buffer() -> Vec<u8> {
    vec![0u8; RECV_BUFFER_SIZE]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    // 非同期テストは monoio ランタイムが必要
}
