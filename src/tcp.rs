use std::io;

use tun_tap::Iface;

pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}

pub struct Connection {
    pub state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
}

/// State of Send Sequence Space (RFC 793 S3.2 Figure 4)
///
/// ```
///           1         2          3          4
///      ----------|----------|----------|----------
///             SND.UNA    SND.NXT    SND.UNA
///                                  +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
///
/// The send window is the portion of the sequence space labeled 3
/// ```

struct SendSequenceSpace {
    /// send unacknowledged
    una: usize,
    /// send next
    nxt: usize,
    /// send window
    wnd: usize,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wil1: usize,
    /// segment acknowledged number used for last window update
    wil2: usize,
    /// initial send sequence number
    iss: usize,
}

/// State of Receive Sequence Space (RFC 793 S3.2 Figure 5)
/// ```
///                1          2          3
///            ----------|----------|----------
///                   RCV.NXT    RCV.NXT
///                             +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
///
/// The receive window is the portion of the sequence space labeled 2
/// ```
struct RecvSequenceSpace {
    /// receive next
    nxt: usize,
    /// receive window
    wnd: usize,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: usize,
}

impl Default for Connection {
    fn default() -> Self {
        // State::Closed
        Connection {
            state: State::Listen,
        }
    }
}

impl Connection {
    pub fn on_packet(
        &mut self,
        nic: &mut Iface,
        ip_header: &etherparse::Ipv4HeaderSlice,
        tcp_header: &etherparse::TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        match self.state {
            State::Closed => {
                return Ok(0);
            }
            State::Listen => {
                // expect syn
                if !tcp_header.syn() {
                    return Ok(0);
                }

                // need to establish a connection
                // send syn, ack
                let mut syn_ack = etherparse::TcpHeader::new(
                    tcp_header.destination_port(),
                    tcp_header.source_port(),
                    // TODO
                    // sequence number
                    0,
                    // window size
                    0,
                );
                syn_ack.syn = true;
                syn_ack.ack = true;
                let mut ip = etherparse::Ipv4Header::new(
                    syn_ack.header_len(),
                    64,
                    // 0x06 means TCP, 0x01 means ICMP
                    6,
                    ip_header.destination_addr().octets(),
                    ip_header.source_addr().octets(),
                );

                let mut unwritten = &mut buf[..];
                ip.write(&mut unwritten);
                syn_ack.write(&mut unwritten);
                let unwritten_len = unwritten.len();
                nic.send(&buf[..unwritten_len]);
            }
            State::SynRcvd => {}
            State::Estab => {}
        }
        eprintln!(
            "{}:{} -> {}:{} {}b of tcp",
            ip_header.source_addr(),
            tcp_header.source_port(),
            ip_header.destination_addr(),
            tcp_header.destination_port(),
            data.len()
        );
        Ok(0)
    }
}
