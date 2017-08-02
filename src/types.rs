extern crate bigint;

pub type Bytes32 = [u8; 32];
pub type Address = [u8; 20];
pub type Uint256 = u64;
pub type Int256 = i64;
pub type Signature = [u8; 65];
pub type PrivateKey = [u8; 64];

#[derive(Copy, Clone)]
pub enum Participant {
  Zero = 0,
  One = 1
}

impl Participant {
  pub fn get_me(&self) -> usize {
    match self {
        Zero => 0,
        One => 1,
    }
  }
  pub fn get_them(&self) -> usize {
    match self {
        One => 0,
        Zero => 1,
    }
  }
}

pub struct Channel {
  pub channel_id: Bytes32,
  pub addresses: [Address; 2],
  pub ended: bool,
  pub closed: bool,
  pub balances: [Uint256; 2],
  pub total_balance: Uint256,
  pub hashlocks: Vec<Hashlock>,
  pub sequence_number: Uint256,
  pub participant: Participant
}

impl Channel {
  pub fn new (
    channel_id: Bytes32,
    addresses: [Address; 2],
    balances: [Uint256; 2],
    participant: Participant,
  ) -> Channel {
    Channel {
      channel_id,
      addresses,
      balances,
      participant,
      total_balance: balances[0] + balances[1],

      sequence_number: 0,
      closed: false,
      ended: false,
      hashlocks: Vec::new(),
    }
  }

  pub fn get_my_address (&self) -> Address {
    self.addresses[self.participant.get_me()]
  }
  pub fn get_their_address (&self) -> Address {
    self.addresses[self.participant.get_them()]
  }
  pub fn get_my_balance (&self) -> Uint256 {
    self.balances[self.participant.get_me()]
  }
  pub fn get_their_balance (&self) -> Uint256 {
    self.balances[self.participant.get_them()]
  }
}

pub struct Hashlock {
  pub hash: Bytes32,
  pub amount: Int256,
}

pub struct NewChannelTx {
  pub channel_id: Bytes32,
  pub settling_period: Uint256,
  pub addresses: [Address; 2],
  pub balances: [Uint256; 2],
  pub signatures: [Option<Signature>; 2]
}

impl NewChannelTx {
  pub fn get_fingerprint (&self) -> Bytes32 {
    [0; 32]
  }
}

pub struct Account {
  pub address: Address,
  pub private_key: PrivateKey,
  pub balance: Uint256,
}

pub struct Counterparty {
  pub address: Address,
  pub url: String,
}

impl Counterparty {
  
}

pub struct Fullnode {
  pub address: Address,
  pub url: String,
}