# Router dashboard API

## URL

`<rita ip>:4877/wifi_settings`

## Method

GET

## Success Response

### Code

200

### Content

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

## Error Responses

None?

## Sample Call

`curl 127.0.0.1:4877/wifi_config`
