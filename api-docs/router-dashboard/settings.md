# Router dashboard API

## URL

`192.168.1.1:4877/settings`

## Method

GET

## Success Response

### Code

200

### Content

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
    "rita_dashboard_port": 4877,
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

## Error Responses

None?

## Sample Call

`curl 192.168.2.1:4877/settings`
