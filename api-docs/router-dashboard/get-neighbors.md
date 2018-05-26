# Router dashboard API

## URL

`<rita ip>:4877/neighbors`

## Method

GET

## Success Response

### Code

200

### Content

```
[
   	{
   		"nickname": "fd00::2",
   		"route_metric_to_exit": 0,
   		"total_debt": 0,
   		"current_debt": 0,
         "link_cost": 0
   	},
   	{
   		"nickname": "fd00::7",
   		"route_metric_to_exit": 0,
   		"total_debt": 0,
   		"current_debt": 0,
         "link_cost": 0
   	}
]
```

## Error Responses

None?

## Sample Call

`curl 127.0.0.1:4877/neighbors`
