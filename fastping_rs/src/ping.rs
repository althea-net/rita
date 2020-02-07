use std::net::{IpAddr};
use rand::random;
use pnet::packet::icmp::{IcmpTypes};
use pnet::transport::TransportSender;
use pnet::packet::icmp::{echo_request};
use pnet::packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet};
use pnet::util;
use pnet_macros_support::types::*;
use pnet::packet::Packet;
use std::time::{Duration, Instant};
use std::collections::BTreeMap;
use std::sync::mpsc::{ Sender, Receiver};
use std::sync::{Arc, Mutex, RwLock};
use ::PingResult;

fn send_echo(tx: &mut TransportSender, addr: IpAddr) -> Result<usize, std::io::Error> {
    // Allocate enough space for a new packet
    let mut vec: Vec<u8> = vec![0; 16];


    // Use echo_request so we can set the identifier and sequence number
    let mut echo_packet = echo_request::MutableEchoRequestPacket::new(&mut vec[..]).unwrap();
    echo_packet.set_sequence_number(random::<u16>());
    echo_packet.set_identifier(random::<u16>());
    echo_packet.set_icmp_type(IcmpTypes::EchoRequest);

    let csum = icmp_checksum(&echo_packet);
    echo_packet.set_checksum(csum);

    tx.send_to(echo_packet, addr)
}

fn send_echov6(tx: &mut TransportSender, addr: IpAddr) -> Result<usize, std::io::Error> {
    // Allocate enough space for a new packet
    let mut vec: Vec<u8> = vec![0; 16];


    // Use echo_request so we can set the identifier and sequence number
    let mut echo_packet = MutableIcmpv6Packet::new(&mut vec[..]).unwrap();
    echo_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);

    let csum = icmpv6_checksum(&echo_packet);
    echo_packet.set_checksum(csum);

    tx.send_to(echo_packet, addr)
}

pub fn send_pings(timer: Arc<RwLock<Instant>>,
          stop: Arc<Mutex<bool>>,
          results_sender: Sender<PingResult>,
          thread_rx: Arc<Mutex<Receiver<PingResult>>>,
          tx: Arc<Mutex<TransportSender>>,
          txv6: Arc<Mutex<TransportSender>>,
          addrs: Arc<Mutex<BTreeMap<IpAddr, bool>>>,
          max_rtt: Arc<Duration>,
      ) {
      loop {
          for (addr, seen) in addrs.lock().unwrap().iter_mut() {
              match if addr.is_ipv4() {
                  send_echo(&mut tx.lock().unwrap(), *addr)
              } else if addr.is_ipv6() {
                  send_echov6(&mut txv6.lock().unwrap(), *addr)
              } else {
                  Ok(0)
              } {
                  Err(e) => error!("Failed to send ping to {:?}: {}", *addr, e),
                  _ => {}
              }
              *seen = false;
          }
          {
              // start the timer
              let mut timer = timer.write().unwrap();
              *timer = Instant::now();
          }
          loop {
              // use recv_timeout so we don't cause a CPU to needlessly spin
              match thread_rx.lock().unwrap().recv_timeout(Duration::from_millis(100)) {
                  Ok(result) => {
                      match result {
                          PingResult::Receive{addr, rtt: _} => {
                              // Update the address to the ping response being received
                              if let Some(seen) = addrs.lock().unwrap().get_mut(&addr) {
                                  *seen = true;
                                  // Send the ping result over the client channel
                                  match results_sender.send(result) {
                                      Ok(_) => {},
                                      Err(e) => {
                                          if !*stop.lock().unwrap() {
                                              error!("Error sending ping result on channel: {}", e)
                                          }
                                      }
                                  }
                              }
                          }
                          _ => {}
                      }
                  },
                  Err(_) => {
                      // Check we haven't exceeded the max rtt
                      let start_time = timer.read().unwrap();
                      if Instant::now().duration_since(*start_time) > *max_rtt {
                          break
                      }
                  }
              }
          }
          // check for addresses which haven't replied
          for (addr, seen) in addrs.lock().unwrap().iter() {
              if *seen == false {
                  // Send the ping Idle over the client channel
                  match results_sender.send(PingResult::Idle{addr: *addr}) {
                      Ok(_) => {},
                      Err(e) => {
                          if !*stop.lock().unwrap() {
                              error!("Error sending ping Idle result on channel: {}", e)
                          }
                      }
                  }
              }
          }
          // check if we've received the stop signal
          if *stop.lock().unwrap() {
              return
          }
      }
  }


fn icmp_checksum(packet: &echo_request::MutableEchoRequestPacket) -> u16be {
    util::checksum(packet.packet(), 1)
}

fn icmpv6_checksum(packet: &MutableIcmpv6Packet) -> u16be {
    util::checksum(packet.packet(), 1)
}
