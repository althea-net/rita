![](exit-signup-chart.png "exit signup flow diagram")

# Dashboard requests required

(numbers correspond to numbers in brackets in msc diagram)
1. `curl -XPOST -H "Content-Type: application/json" 192.168.10.1:4877/settings -d '{"exit_client": {"exits": {"borked": {"state": "Registering"}}}}'`
2. `curl -XPOST -H "Content-Type: application/json" 192.168.10.1:4877/settings -d '{"exit_client": {"exits": {"borked": {"email_code": "679320"}}}}'`

```msc
msc {
  hscale = "2";

  frontend,rita,exit,useremail;

  rita->exit [ label = "GET /exit_info" ] ;
  rita<-exit [ label = "ExitDetails" ] ;

  ---  [ label = "until frontend gets here" ];

  frontend->rita [ label = "GET /settings" ] ;
  frontend<-rita [ label = "Exit list" ] ;

  frontend=>rita [ label = "POST /settings(change GotInfo to Registering) (1)" ];

  rita->exit [ label = "POST /setup" ] ;
  rita<-exit [ label = "Pending" ] ;

  exit->useremail [ label = "one time code" ] ;

  frontend->rita [ label = "GET /settings" ] ;
  frontend<-rita [ label = "Exit list (state pending)" ] ;

  ---  [ label = "when user checks email" ];

  frontend<-useremail [ label = "one time code" ] ;

  frontend->rita [ label = "POST /settings(Add one time code) (2)" ] ;

  rita->exit [ label = "POST /setup" ] ;
  rita<-exit [ label = "Registered" ] ;

  frontend->rita [ label = "GET /settings" ] ;
  frontend<-rita [ label = "Exit list (state registered)" ] ;

  ---  [ label = "every 5 seconds" ];

    rita->exit [ label = "POST /status" ] ;
    rita<-exit [ label = "state: Registered/New/GotInfo" ] ;
}
```