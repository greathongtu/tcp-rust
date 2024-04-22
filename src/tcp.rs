use std::io;

use tun_tap::Iface;

#[derive(Debug)]
pub enum State {
    // Closed,
    // Listen,
    SynRcvd,
    Estab,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRcvd => false,
            State::Estab => true,
        }
    }
}

pub struct Connection {
    pub state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
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
    una: u32,
    /// next sequence number to send
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wil1: usize,
    /// segment acknowledged number used for last window update
    wil2: usize,
    /// initial send sequence number
    iss: u32,
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
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept(
        nic: &mut Iface,
        ip_header: etherparse::Ipv4HeaderSlice,
        tcp_header: etherparse::TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];
        // expect syn
        if !tcp_header.syn() {
            return Ok(None);
        }

        let iss = 0;
        let wnd = 10;
        let mut c = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
                wnd: 10,
                up: false,
                wil1: 0,
                wil2: 0,
            },
            recv: RecvSequenceSpace {
                irs: tcp_header.sequence_number(),
                nxt: tcp_header.sequence_number() + 1,
                wnd: tcp_header.window_size(),
                up: false,
            },
            ip: etherparse::Ipv4Header::new(
                0,
                64,
                // 0x06 means TCP, 0x01 means ICMP
                6,
                ip_header.destination_addr().octets(),
                ip_header.source_addr().octets(),
            ),
            tcp: etherparse::TcpHeader::new(
                tcp_header.destination_port(),
                tcp_header.source_port(),
                // TODO
                // sequence number
                iss,
                // window size
                wnd,
            ),
        };

        // need to establish a connection
        // send syn, ack

        c.tcp.acknowledgment_number = c.recv.nxt;
        c.tcp.syn = true;
        c.tcp.ack = true;
        c.write(nic, &[])?;
        Ok(Some(c))
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;
        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() as usize + self.ip.header_len() as usize + payload.len(),
        );
        self.ip.set_payload_len(size);

        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &[])
            .expect("failed to compute checksum");

        use std::io::Write;
        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten);
        self.tcp.write(&mut unwritten);
        let payload_bytes = unwritten.write(payload)?;
        let unwritten_len = unwritten.len();
        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }
        nic.send(&buf[..buf.len() - unwritten_len])?;
        Ok(payload_bytes)
    }

    fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcp.rst = true;

        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, &[])?;
        Ok(())
    }
    pub fn on_packet(
        &mut self,
        nic: &mut Iface,
        ip_header: etherparse::Ipv4HeaderSlice,
        tcp_header: etherparse::TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<()> {
        // first, check that sequence numbers are valid (RFC 793 S3.3)
        let ackn = tcp_header.acknowledgment_number();
        if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
            if !self.state.is_synchronized() {
                // need to send RST
                self.send_rst(nic);
            }
            return Ok(());
        }

        // valid segment check
        let seqn = tcp_header.sequence_number();
        let mut slen = data.len() as u32;
        if tcp_header.fin() {
            slen += 1;
        };
        if tcp_header.syn() {
            slen += 1;
        };
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        if slen == 0 {
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    return Ok(());
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                return Ok(());
            }
        } else {
            if self.recv.wnd == 0 {
                return Ok(());
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn + slen - 1, wend)
            {
                return Ok(());
            }
        }

        match self.state {
            State::SynRcvd => {
                // expect their ack for our sent syn
                if !tcp_header.ack() {
                    return Ok(());
                }
                self.state = State::Estab;
            }
            State::Estab => {
                unimplemented!();
            }
        }
    }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    use std::cmp::Ordering;
    match start.cmp(&x) {
        Ordering::Equal => {
            return false;
        }
        Ordering::Less => {
            if end >= start && end <= x {
                return false;
            }
        }
        Ordering::Greater => {
            if end >= x && end < start {
            } else {
                return false;
            }
        }
    }
    true
}
