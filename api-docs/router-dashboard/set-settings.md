# Router dashboard API

## URL

`<rita ip>:4877/settings`

## Method

POST

## Success Response

### Code

200

### Content

```
{
    "response": "New settings applied"
}

```

## Error Responses

None?

## Sample Call

`curl -XPOST 127.0.0.1:4877/settings -H 'Content-Type: application/json' -i -d '{"section_name":"default_radio0","network":"lan","mesh":false,"ssid":"AltheaHome","encryption":"psk2+tkip+aes","key":"ChangeMe","device":{"section_name":"radio0","type":"mac80211","channel":"36","path":"pci0000:00/0000:00:00.0","htmode":"VHT80","hwmode":"11a","disabled":"0","radio_type":"5ghz"}}'`