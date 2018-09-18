# Router dashboard API

This file documents the dashboard API found in Rita client.

## /info

- URL: `<rita ip>:<rita_dashboard_port>/info`
- Method: `GET`
- URL Params: `None`
- Data Params: `None`
- Success Response:
  - Code: 200 OK
  - Contents:

```
{
    "balance":-1029470595
    "version": "v0.1.1"
}
```

- Error Response: `500 Server Error`

- Sample Call:

`curl 127.0.0.1:4877/info`

## /neighbors

- URL: `<rita ip>:<rita_dashboard_port>/neighbors`
- Method: `GET`
- URL Params: `None`
- Data Params: `None`
- Success Response:
  - Code: 200 OK
  - Contents:

```
[
   {
      "nickname": "fd00::2",
      "route_metric_to_exit": 0,
      "total_debt": 0,
      "current_debt": 0,
      "link_cost": 0,
      "price_to_exit": 0
   },
   {
      "nickname": "fd00::7",
      "route_metric_to_exit": 0,
      "total_debt": 0,
      "current_debt": 0,
      "link_cost": 0,
      "price_to_exit": 0
   }
]
```

- Error Response: `500 Server Error`

- Sample Call:

`curl 127.0.0.1:4877/neighbors`

## /exits

- URL: `<rita ip>:<rita_dashboard_port>/exits'
- Comment: Gets all the configured exits
- Method: `GET`
- URL Params: `None`
- Data Params: `None`
- Success Response:
  - Code: 200 OK
  - Contents:

```
[
   {
      "nickname": "apac",
      "exit_settings": {
        "id": {
          "eth_address": "0x0101010101010101010101010101010101010101",
          "mesh_ip": "fd96::1337:e4f",
          "wg_public_key": "1kKSpzdhI4kfqeMqch9I1bXqOUXeKN7EQBecVzW60ys="
        },
        "message": "In Singapore",
        "registration_port": 4875,
        "state": "New"
      }
      "is_selected": true,
      "have_route": true,
      "is_reachable": true,
      "is_tunnel_working": true,
   },
]
```

- Error Response: `500 Server Error`

- Sample Call:

`curl 127.0.0.1:4877/exits`

## /exits/{nickname}/reset

- URL: `<rita ip>:<rita_dashboard_port>/exits/{nickname}/reset'
- Comment: Resets the exit named `nickname`
- Method: `POST`
- URL Params: `nickname`, string
- Data Params: `None`
- Success Response:
  - Code: 200 OK
  - Contents: `{}`
- Error Response: `400 Bad Request`
- Error Contents:

```json
{
  "error": "<description>"
}
```

- Sample Call:

`curl -XPOST 127.0.0.1:4877/exits/borked/reset`

## /exits/{nickname}/select

- URL: `<rita ip>:<rita_dashboard_port>/exits/{nickname}/select'
- Comment: Sets the exit named `nickname` as the current exit
- Method: `POST`
- URL Params: `nickname`, string
- Data Params: `None`
- Success Response:
  - Code: 200 OK
  - Contents: `{}`
- Error Response: `400 Bad Request`
- Error Contents:

```json
{
  "error": "<description>"
}
```

- Sample Call:

`curl -XPOST 127.0.0.1:4877/exits/borked/reset`

## /exits/{nickname}/register

- URL: `<rita ip>:<rita_dashboard_port>/exits/{nickname}/register'
- Comment: Asks exit `{nickname}` to be registered
- Method: `POST`
- URL Params: `nickname`, string
- Data Params: `None`
- Success Response:
  - Code: 200 OK
  - Contents: `{}`
- Error Response: `400 Bad Request`
- Error Contents:

```json
{
  "error": "<description>",
  "rust_error": "<stringified_rust_error>"
}
```

- Sample Call:

`curl -XPOST 127.0.0.1:4877/exits/borked/register`

## /exits/{nickname}/verify/{code}

- URL: `<rita ip>:<rita_dashboard_port>/exits/{nickname}/verify/{code}'
- Comment: After registering and receiving a verification code, asks exit
  `{nickname}` for verification using `{code}`
- Method: `POST`
- URL Params:
  - `nickname`, string
  - `code`, string
- Data Params: `None`
- Success Response:
  - Code: 200 OK
  - Contents: `{}`
- Error Response: `400 Bad Request`
- Error Contents:

```json
{
  "error": "<description>",
  "rust_error": "<stringified_rust_error>"
}
```

- Sample Call:

`curl -XPOST 127.0.0.1:4877/exits/borked/register`

## /settings

- URL: `<rita ip>:<rita_dashboard_port>/settings`
- Comment: `pub enum ExitState { New, GotInfo, Pending, Registered, Denied, Disabled, }`
- Method: `GET`
- URL Params: `None`
- Data Params: `None`
- Success Response:
  - Code: 200 OK
  - Contents:

```
{
  "exit_client": {
    "current_exit": null,
    "exits": {
      "apac": {
        "id": {
          "eth_address": "0x0101010101010101010101010101010101010101",
          "mesh_ip": "fd96::1337:e4f",
          "wg_public_key": "1kKSpzdhI4kfqeMqch9I1bXqOUXeKN7EQBecVzW60ys="
        },
        "message": "In Singapore",
        "registration_port": 4875,
        "state": "New"
      },
      "aus": {
        "id": {
          "eth_address": "0x0101010101010101010101010101010101010101",
          "mesh_ip": "fd96::1337:e5f",
          "wg_public_key": "z3aS2DNWWrbpMYZra2BuoV4gjcVTHVxinKAi4H8t7m8="
        },
        "message": "Althea testing exit in Australia",
        "registration_port": 4875,
        "state": "New"
      },
      "canada_east": {
        "id": {
          "eth_address": "0x0101010101010101010101010101010101010101",
          "mesh_ip": "fd96::1337:e3f",
          "wg_public_key": "sA76hy4X2nPhccGJeBClVUzZ6bntGrUD0GjBJDjVYBE="
        },
        "message": "Althea production Canada Exit",
        "registration_port": 4875,
        "state": "New"
      },
      "test": {
        "id": {
          "eth_address": "0x0101010101010101010101010101010101010101",
          "mesh_ip": "fd96::1337:e1f",
          "wg_public_key": "hw2rXXaIOfbcOXbvejB3AyuoSAb3QhPXjC5MwxRqkls="
        },
        "message": "The Althea testing exit. Unstable!",
        "registration_port": 4875,
        "state": "New"
      },
      "us_west": {
        "id": {
          "eth_address": "0x0101010101010101010101010101010101010101",
          "mesh_ip": "fd96::1337:e2f",
          "wg_public_key": "jkIodvXKgij/rAEQXFEPJpls6ooxXJEC5XlWA1uUPUg="
        },
        "message": "The Althea Production US exit",
        "registration_port": 4875,
        "state": "New"
      }
    },
    "reg_details": {
      "email": "placeholder@domain.com",
      "zip_code": "1234"
    },
    "wg_listen_port": 59999
  },
  "exit_tunnel_settings": {
    "lan_nics": [
      "lan"
    ]
  },
  "network": {
    "babel_port": 6872,
    "bounty_ip": "fd96::1337:e1f",
    "bounty_port": 8888,
    "default_route": [],
    "manual_peers": [
      "test.altheamesh.com",
      "apac.altheamesh.com",
      "exit.altheamesh.com",
      "apac.altheamesh.com",
      "aus.altheamesh.com"
    ],
    "own_ip": "fde6:99d5:d181:3951:efb:6f36:e2c:762e",
    "peer_interfaces": [
      "eth0.5",
      "wlan1",
      "eth0.4",
      "eth0.3",
      "wlan0"
    ],
    "rita_dashboard_port": <rita_dashboard_port>,
    "rita_hello_port": 4876,
    "wg_private_key": "GPMeguCa8hJOjQVHjvFEYQRd/IqIWUkTpJ8wEVgEwW8=",
    "wg_private_key_path": "/tmp/priv",
    "wg_public_key": "xwQPrcV6idkdXNVQL4dSbcqGDRUsKMG4bcf2RUajk3M=",
    "wg_start_port": 60000
  },
  "payment": {
    "buffer_period": 3,
    "close_fraction": "100",
    "close_threshold": "-1000000000",
    "eth_address": "0x0101010101010101010101010101010101010101",
    "pay_threshold": "0"
  }
}
```

- Error Response: `500 Server Error`

- Sample Call:

`curl 127.0.0.1:4877/settings`

## /settings

- URL: `<rita ip>:<rita_dashboard_port>/settings`
- Comment: `pub enum ExitState { New, GotInfo, Pending, Registered, Denied, Disabled, }`
- Method: `POST`
- URL Params: `Content-Type: application/json`
- Data Params: `Partial JSON settings to be changed`
- Success Response:
  - Code: 200 OK
  - Contents:

```
{
    "response": "New settings applied"
}
```

- Error Response: `500 Server Error`

- Sample Call:

`curl -XPOST 127.0.0.1:<rita_dashboard_port>/settings -H 'Content-Type: application/json' -i -d '{"exit_client": {"current_exit": "SELECTEDEXIT"}}'`
}

---

## /wifi_settings/ssid

- URL: `<rita ip>:<rita_dashboard_port>/wifi_settings/ssid`
- Method: `POST`
- URL Params: `Content-Type: application/json`
- Data Params: `Radio to change the ssid of and ssid`
- Success Response:
  - Code: `200 OK`
  - Contents:

```json
{}
```

- Error Response:
  - Code: `400 Bad Request`
  - Contents:

```json
{
  "error": "<human-readable description>"
}
```

- Sample Call:

`curl -XPOST 127.0.0.1:<rita_dashboard_port>/wifi_settings/ssid -H 'Content-Type: application/json' -i -d '{"radio":"radio0", "ssid": "this is a freeform ssid"}'`

---

## /wifi_settings/pass

- URL: `<rita ip>:<rita_dashboard_port>/wifi_settings/pass`
- Method: `POST`
- URL Params: `Content-Type: application/json`
- Data Params: `Radio to change the password of and password`
- Success Response:
  - Code: 200 OK
  - Contents:

```
{}
```

- Error Response:
  - Code: `400 Bad Request`
  - Contents:

```json
{
  "error": "<human-readable description>"
}
```

- Sample Call:

`curl -XPOST 127.0.0.1:<rita_dashboard_port>/wifi_settings/pass -H 'Content-Type: application/json' -i -d '{"radio":"radio0", "pass": "this is a freeform password"}'`

---

## /wipe

**This endpoint works only on development builds and is meant only for development purposes**

- URL: `<rita ip>:<rita_dashboard_port>/wipe`
- Method: `POST`
- URL Params: `None`
- Data Params: `None`
- Success Response:
  - Code: 204 NO CONTENT
  - Contents: `None`
- Error Response: `500 Server Error`
- Sample Call:

`curl -XPOST 127.0.0.1:<rita_dashboard_port>/wipe`

---

## /database

**This endpoint worsk only on development builds and is meant only for development purposes**

Calling HTTP `DELETE` request on this endpoint causes all tables to be wiped out of data.

- URL: `<rita ip>:<rita_dashboard_port>/wipe`
- Method: `DELETE`
- URL Params: `None`
- Data Params: `None`
- Success Response:
  - Code: 204 NO CONTENT
  - Contents: `None`
- Error Response: `500 Server Error`
- Sample Call:

`curl -XDELETE 127.0.0.1:<rita_dashboard_port>/database`

--

## /debts

Calling HTTP `GET` request on this endpoint returns a list of debts. Each element of the resulting list contains a dictionary with two keys: `identity` with a dictionary with identity-related information, and `payment_details` key with a value of payments related informations.

- URL: `<rita ip>:<rita_dashboard_port>/debts`
- Method: `GET`
- URL Params: `None`
- Data Params: `None`
- Success Response:
  - Code: 200 OK
  - Contents: `JSON` structured message. See below for an example format.
- Error Response: `500 Server Error`
- Sample Call

`curl 127.0..1:<rita_dashboard_port>/debts`

Format:

```json
[
  {
    "identity": {
      "mesh_ip": "a:b:c:d:e:f:g:h",
      "eth_address": "0x0101010101010101010101010101010101010101",
      "wg_public_key": "pubkey"
    }
    "payment_details": {
      "total_payment_received": "0x0",
      "total_payment_sent": "0x0",
      "debt": "0",
      "incoming_payments": "0"
    }
  },
  ...
]
```

---

## /dao_list

Calling HTTP `GET` request on this endpoint returns a list of EthAddresses for a configured subnet DAO. If no DAO is configured it will return an empty list.

- URL: `<rita ip>:<rita_dashboard_port>/dao_list`
- Method: `GET`
- URL Params: `None`
- Data Params: `None`
- Success Response:
  - Code: 200 OK
  - Contents: `JSON` structured message. See below for an example format.
- Error Response: `500 Server Error`
- Sample Call

`curl 127.0..1:<rita_dashboard_port>/dao_list`

Format:

```json
[
  "0xf7402c9b6ee98acb1b7d131607108d1f15b552cd",
  ...
]
```

---

## /dao_list/add/{address}

Calling HTTP `POST` request on this endpoint adds the provided address to the configured list of
SubnetDAO's

- URL: `<rita ip>:<rita_dashboard_port>/dao_list/add/{address}`
- Method: `POST`
- URL Params: `None`
- Data Params: `None`
- Success Response:
  - Code: 200 OK
  - Contents: `JSON` structured message. See below for an example format.
- Error Response: `500 Server Error`
- Sample Call

`curl 127.0..1:<rita_dashboard_port>/dao_list/add/0xf7402c9b6ee98acb1b7d131607108d1f15b552cd`

Format:

```json
[]
```

---

## /dao_list/remove/{address}

Calling HTTP `POST` request on this endpoint removes the provided address from the configured list of
SubnetDAO's

- URL: `<rita ip>:<rita_dashboard_port>/dao_list/remove/{address}`
- Method: `POST`
- URL Params: `None`
- Data Params: `None`
- Success Response:
  - Code: 200 OK
  - Contents: `JSON` structured message. See below for an example format.
- Error Response: `500 Server Error`
- Sample Call

`curl 127.0..1:<rita_dashboard_port>/dao_list/remove/0xf7402c9b6ee98acb1b7d131607108d1f15b552cd`

Format:

```json
[]
```

---
