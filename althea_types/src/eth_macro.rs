

macro_rules! impl_eth {
    ($ads:ident[ $x:ty; $y:expr]) => (
	#[derive(Copy, Clone)]
	pub struct $ads(pub [$x; $y]);

	impl Hash for $ads {
    		fn hash<H: Hasher>(&self, state: &mut H) {
        	self.0.hash(state);
    	     }
        }
        impl PartialEq for $ads {
    		fn eq(&self, other: &$ads) -> bool {
        	self.0[..] == other.0[..]
       }
     }

    impl Eq for $ads {}

    impl Deref for $ads {
       type Target = [$x; $y as usize];

      fn deref(&self) -> &[$x; $y as usize] {
        &self.0
    }
   }

	impl FromStr for $ads {
	    type Err = hex::FromHexError;

	    fn from_str(s: &str) -> Result<Self, Self::Err> {
		hex::decode(&s[2..]).map(|v| {
		    let mut arr = [0u8; $y];
		    arr.clone_from_slice(&v);
		    $ads(arr)
		})
	    }
	}


	impl fmt::Debug for $ads {
    		fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
       		 write!(f, "{} {}",stringify!($ads), self.to_string())
    		}
	}

	impl fmt::Display for $ads {
    		fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        	write!(f, "0x{}", hex::encode(self.0.as_ref()))
    		}
	}

	impl Serialize for $ads {
	    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		serializer.serialize_str(&self.to_string())
	    }
	}

	impl<'de> Deserialize<'de> for $ads {
	    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		let s = String::deserialize(deserializer)?;
		s.parse().map_err(serde::de::Error::custom)
	    }
	}

  );
 
}

