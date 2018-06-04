# Rita exit daemon's HTTP endpoints
This file documents the facilities available on the Althea exit server daemon
via HTTP.

## Port `registration_port`
The endpoints below are served on the port configured using the
`registration_port` config value.

### `/rtt`
Measure the round trip time to the exit.

* **Method**: `GET`
* **URL Params**: `None`
* **Data Params**: `None`
* **Success Response**:
  - **Code**: 200 OK
  - **Contents**:
```javascript
// Note: Both exit_rx and exit_tx are a JSON-serialized representation of Rust's
// std::time::SystemTime.
{
  "exit_rx": {
  "secs_since_epoch":1527106071, // Integer; timestamp seconds at request arrival
  "nanos_since_epoch":609010634  // Integer; timestamp nanos at request arrival
  },
  "exit_tx": {
  "secs_since_epoch": 1527106071, // Integer; timestamp seconds at response departure
  "nanos_since_epoch":609011002   // Integer; timestamp nanos at response departure
  }
}
```
* **Error Response**: `n/a`
* **Sample call**:
```sh
$ curl <exit_ip>:<exit_registration_port>/rtt
{"exit_rx":{"secs_since_epoch":1527106071,"nanos_since_epoch":609010634},"exit_tx":{"secs_since_epoch":1527106071,"nanos_since_epoch":609011002}}
```
