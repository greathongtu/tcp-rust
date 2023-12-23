use std::io;

use tun_tap::Iface;

pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}

impl Default for State {
    fn default() -> Self {
        // State::Closed
        State::Listen
    }
}

impl State {
    pub fn on_packet(
        &mut self,
        nic: &mut Iface,
        ip_header: &etherparse::Ipv4HeaderSlice,
        tcp_header: &etherparse::TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        match *self {
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
                    0,
                    0,
                );
                syn_ack.syn = true;
                syn_ack.ack = true;
                let mut ip = etherparse::Ipv4Header::new(
                    syn_ack.header_len(),
                    64,
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
