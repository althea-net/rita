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
    "balance": -1029470595,
    "device": "mynet-n750",
    "version": "v0.1.1"
}
```

- Error Response: `500 Server Error`

- Sample Call:

`curl 127.0.0.1:4877/info`

---

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

---

## /exits

- URL: `<rita ip>:<rita_dashboard_port>/exits'
- Comment: Merges a supplied exit list with the existing list; existing entries
  are overwritten
- Method: `POST`
- URL Params: `None`
- Data Params: A JSON object containing the exits we want to add, e.g.:
```json
{
	"exit_other": {
		"auto_register": false,
		"description": "",
		"general_details": {
			"description": "EDITEDITjust a normal althea exit",
			"exit_price": 50,
			"netmask": 24,
			"server_internal_ip": "172.168.1.254",
			"wg_exit_port": 59999

		},
		"id": {
			"eth_address": "0x0101010101010101010101010101010101010101",
			"mesh_ip": "fd00::5",
			"wg_public_key": "KaTbsJ0Hur4D7Tcb+nc8ofs7n8tKL+wWG3H38KFCwlE="

		},
		"message": "Got info successfully",
		"registration_port": 4875,
		"state": "GotInfo"

	},
	"exit_yet_another": {
		"auto_register": false,
		"description": "",
		"general_details": {
			"description": "EDITEDITjust a normal althea exit",
			"exit_price": 50,
			"netmask": 24,
                        "verif_mode": "Email"
			"server_internal_ip": "172.168.1.254",
			"wg_exit_port": 59999

		},
		"id": {
			"eth_address": "0x0101010101010101010101010101010101010101",
			"mesh_ip": "fd00::5",
			"wg_public_key": "KaTbsJ0Hur4D7Tcb+nc8ofs7n8tKL+wWG3H38KFCwlE="

		},
		"message": "Got info successfully",
		"registration_port": 4875,
		"state": "GotInfo"

	}
}
```
- Success Response:
  - Code: 200 OK
  - Contents: The complete current exit list containing the result of adding the
    desired exits; the format is identical to the data param
- Error Response: `400 Server Error`

- Sample Call:

`curl 127.0.0.1:4877/exits -XPOST -H "Content-Type: application/json" -d
$(exit_list_of_format_listed_above)`

---

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

---
## /exits/sync

- URL: `<rita ip>:<rita_dashboard_port>/exits/sync'
- Comment: Adds exits from under `url` remote HTTP host to exit list;
  conflicting entries are overwritten by remote list contents
- Method: `GET`
- URL Params: `None`
- Data Params:
```
{
  "url": "https://wherever.the/json/list/is.json"
}
```
- Success Response:
  - Code: 200 OK
  - Contents: Updated exit list (see POST `/exits` for example)
- Error Response: `400 Bad Request` for unparsable response JSON, `500 Internal Server
  Error` when the request itself fails for whatever reason
- Error Contents:
  - `400 Bad Request` when the JSON is unparsable
```json
{
  "error": "<description>"
}
```
  - `500 Internal Server Error` when the request fails
```json
{
  "error": "<description>",
  "rust_error": "<stringified_rust_error>"
}```

- Sample Call:

`curl 127.0.0.1:4877/exits/borked/reset -H "Content-Type:
application/json" -d '\{"url": "https://somewhere.safe"\}'
"'`

---

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

---

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

---

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

---

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

---

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
    "mesh_ip": "fde6:99d5:d181:3951:efb:6f36:e2c:762e",
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

## /wifi_settings

- URL: `<rita ip>:<rita_dashboard_port>/wifi_settings`
- Method: `POST`
- URL Params: `Content-Type: application/json`
- Data Params: `Partial JSON settings to be changed`
- Success Response:
  - Code: 200 OK
  - Contents:

```
{}
```

- Error Response: `500 Server Error`
- Sample Call:
  `curl -XPOST 127.0.0.1:<rita_dashboard_port>/settings -H 'Content-Type: application/json' -i -d '{"default_radio0": {"ssid": "NetworkName"}}'`

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

---

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

## /interfaces

Calling HTTP `GET` request on this endpoint provides a list of availabile ports and their current functions

- URL: `<rita ip>:<rita_dashboard_port>/interfaces`
- Method: `POST`
- URL Params: `None`
- Data Params: `None`
- Success Response:
  - Code: 200 OK
  - Contents: `JSON` structured message. See below for an example format.
- Error Response: `500 Server Error`
- Sample Call

`curl 127.0.0.1:<rita_dashboard_port>/interfaces'

Format:

```json
[
  {
    "eth0.3": "LAN",
    "eth0.4": "Mesh",
    "eth1": "Mesh"
  }
]
```

---

## /interfaces

Calling HTTP `POST` request on this endpoint with a json object specifying an interface and a mode
will transform that interface to the specified mode. The provided interface must be available from
the `GET` version of this same endpoint.

- URL: `<rita ip>:<rita_dashboard_port>/interfaces`
- Method: `POST`
- URL Params: `None`
- Data Params: `None`
- Success Response:
  - Code: 200 OK
  - Contents: `JSON` structured message. See below for an example format.
- Error Response: `500 Server Error`
- Sample Call

`curl 127.0.0.1:<rita_dashboard_port>/interfaces -H 'Content-Type: application/json' -i -d '{"interface":"wlan0", "mode":"LAN"}'`

Format:

```json
[]
```

---

## /mesh_ip POST

- URL: `<rita ip>:<rita_dashboard_port>/mesh_ip`
- Method: `POST`
- URL Params: `None`
- Contents:

```json
{
  "mesh_ip": "<new_ipv6_mesh_ip>"
}
```

- Success Response:
  - This endpoint requires Rita to restart and therefore should give an empty
    response
- Error Response: `500 Server Error`
- Sample Call:

`curl 127.0..1:<rita_dashboard_port>/mesh_ip -H 'Content-Type: application/json' -i -d '{"mesh_ip":"fd00::1"}'`

---

## /remote_logging/enabled/{bool}

Enables or disables remote logging, if enabled on next boot
the router will send logs to the configured exit over syslog port 514

This endpoint will restart the router so no response
is expected, an error response indicates that there's
somthing wrong with the input data.

- URL: `<rita ip>:<rita_dashboard_port>/logging/enabled/{bool}'
- Method: `POST`
- URL Params: 'enabled'
- Data Params: `None`
- Success Response:
  - Code: None
  - Contents: `{}`
- Error Response: `400 Bad Request`
- Error Contents:

```json
{
  "error": "<description>"
}
```

- Sample Call:

`curl -XPOST 127.0.0.1:4877/remote_logging/enabled/true`

---

## /remote_logging/level/{level_name}

Sets the level of remote logging.
Supported level names
ERROR
WARN
INFO
DEBUG
TRACE

Do not use anything above WARN for everyday use!
The amount of output will actually consume nontrival bandwidth when passing logs
to the remote server.

This endpoint will restart the router so no response
is expected, an error response indicates that there's
somthing wrong with the input data.

- URL: `<rita ip>:<rita_dashboard_port>/logging/level/{level_namename}'
- Method: `POST`
- URL Params: level
- Data Params: `None`
- Success Response:
  - Code: None
  - Contents: `{}`
- Error Response: `400 Bad Request`
- Error Contents:

```json
{
  "error": "<description>"
}
```

- Sample Call:

`curl -XPOST 127.0.0.1:4877/remote_logging/level/3`

---

## /local_fee

- URL: `<rita ip>:<rita_dashboard_port>/local_fee`
- Method: `GET`
- URL Params: `None`
- Success Response:
```json
{
"local_fee": <current_fee>
}
```
- Error Response: `500 Server Error`
- Sample Call:

`curl 127.0.0.1:4877/local_fee`

---

## /local_fee/{fee}

- URL: `<rita ip>:<rita_dashboard_port>/local_fee/{fee}`
- Method: `POST`
- URL Params: `fee` - a u32 value representing the new local fee to set
- Success Response:
```json
{}
```
**Note:** You'll get a status 200 OK JSON with a `warning` key if you set the
fee value to 0 (which means essentially advertising your bandwidth as free).
- Error Response: `500 Server Error`
- Sample Call:

`curl -XPOST 127.0.0.1:4877/local_fee/5`

---

## /metric_factor

- URL: `<rita ip>:<rita_dashboard_port>/metric_factor`
- Method: `GET`
- URL Params: `None`
- Success Response:
```json
{
"metric_factor": <current_factor>
}
```
- Error Response: `500 Server Error`
- Sample Call:

`curl 127.0.0.1:4877/metric_factor`

---

## /metric_factor/{factor}

- URL: `<rita ip>:<rita_dashboard_port>/metric_factor/{factor}`
- Method: `POST`
- URL Params: `factor` - a u32 value representing the new metric factor to set
  (every 1000 means 1.0, i.e. metric_factor of 1337 effectively means 1.337 in
Babel)
- Success Response:
```json
{}
```
**Note:** You'll get a status 200 OK JSON with a `warning` key if you set the
factor value to 0 (which means essentially advertising your bandwidth as free).
- Error Response: `500 Server Error`
- Sample Call:

`curl -XPOST 127.0.0.1:4877/metric_factor/5`
