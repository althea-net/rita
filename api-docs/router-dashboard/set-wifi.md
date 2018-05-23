# Router dashboard API

## URL

`<rita ip>:4877/wifi_settings`

## Method

POST

## Success Response

### Code

200

### Content

```
{}
```

## Error Responses

None?

## Sample Call

`curl -XPOST 127.0.0.1:4877/settings -H 'Content-Type: application/json' -i -d '{"exit_client": {"current_exit": "exit_a"}}'`