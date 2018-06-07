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

---

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
- Method: `GET`
- URL Params: `None`
- Data Params: `None`
- Success Response:
  - Code: 200 OK
  - Contents:

```
[
   {
      "section_name":"default_radio0",
      "network":"lan",
      "mesh":false,
      "ssid":"AltheaHome",
      "encryption":"psk2+tkip+aes",
      "key":"ChangeMe",
      "device":{
         "section_name":"radio0",
         "type":"mac80211",
         "channel":"36",
         "path":"pci0000:00/0000:00:00.0",
         "htmode":"VHT80",
         "hwmode":"11a",
         "disabled":"0",
         "radio_type":"5ghz"
      }
   },
   {
      "section_name":"default_radio1",
      "network":"lan",
      "mesh":false,
      "ssid":"AltheaHome",
      "encryption":"psk2+tkip+aes",
      "key":"ChangeMe",
      "device":{
         "section_name":"radio1",
         "type":"mac80211",
         "channel":"11",
         "path":"platform/qca953x_wmac",
         "htmode":"HT20",
         "hwmode":"11ng",
         "disabled":"0",
         "radio_type":"2ghz"
      }
   }
]
```

- Error Response: `500 Server Error`

- Sample Call:

`curl 127.0.0.1:4877/wifi_settings`

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
