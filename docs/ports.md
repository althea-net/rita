**note everything is for incoming traffic**

# Exit

## Open to mesh
- network/rita_contact_port (default 4874)
- exit_network/exit_registration_port (default 4875)
- exit_network/wg_listen_port (default 59999)

## Open to external
- rita_hello_port (default 4876)
- wg_start_port+ (default 60000+)

## Open to LAN
- rita_dashboard_port (default 4877)

# Client/gateway

## Open to mesh
- network/rita_contact_port (default 4874)
- exit_client/wg_listen_port (default 59999)

## Open to external
- network/rita_hello_port (default 4876)
- network/wg_start_port+ (default 60000+)

## Open to LAN
- network/rita_dashboard_port (default 4877)