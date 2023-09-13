use althea_kernel_interface::{file_io::write_out, KernelInterfaceError};

// this is where the generated config files are saved and loaded from.
pub const CONFIG_FILE_PATH: &str = "/rita_config.toml";
pub const EXIT_CONFIG_PATH: &str = "/exit_config.toml";

pub fn generate_rita_config_file(path: String) -> Result<(), KernelInterfaceError> {
    let mut lines: Vec<String> = Vec::new();

    let payment = "
    [payment]\n
    pay_threshold = \"10000000000000\"\n
    close_threshold = \"-10000000000000\"\n
    close_fraction = \"100\"\n
    buffer_period = 3\n
    eth_address = \"0x0101010101010101010101010101010101010101\"\n"
        .to_string();
    lines.push(payment);

    let network = "
    [network]\n
    mesh_ip = \"fd00::1\"\n
    discovery_ip = \"ff02::1:8\"\n
    babel_port = 6872\n
    rita_hello_port = 4876\n
    rita_contact_port = 4874\n
    rita_dashboard_port = 4877\n
    rita_tick_interval = 5\n
    wg_private_key_path = \"/tmp/priv\"\n
    wg_start_port = 60000\n
    tunnel_timeout_seconds = 900\n
    peer_interfaces = []\n
    manual_peers = []\n
    default_route = []\n"
        .to_string();
    lines.push(network);

    let dao = "
    [dao]\n
    dao_enforcement = false\n
    cache_timeout_seconds = 600\n
    node_list = []\n
    dao_addresses = []\n"
        .to_string();
    lines.push(dao);

    let exit = "
    [exit_client]\n
    wg_listen_port = 59999\n
    lan_nics = [\"lo\"]\n"
        .to_string();
    lines.push(exit);

    let contact_info = "
    [exit_client.contact_info.number.national]\n
    value = 7040000000\n
    zeros = 0\n
    [exit_client.contact_info.number.code]\n
    source = \"plus\"\n
    value = 1\n
    "
    .to_string();
    lines.push(contact_info);

    let log = "
    [log]\n
    enabled = true\n"
        .to_string();
    lines.push(log);

    write_out(&path, lines)
}

pub fn generate_exit_config_file(path: String) -> Result<(), KernelInterfaceError> {
    let mut lines: Vec<String> = Vec::new();
    let desc = "
    db_uri = \"postgres://postgres@localhost/test\"\n
    client_registration_url = \"https://7.7.7.1:40400/register_router\"\n
    workers = 1\n
    description = \"just a normal althea exit\"\n"
        .to_string();
    lines.push(desc);

    let payment = "
    [payment]\n
    pay_threshold = \"10000000000000\"\n
    close_threshold = \"-10000000000000\"\n
    close_fraction = \"100\"\n
    buffer_period = 3\n
    eth_address = \"0xbe398dc24de37c73cec974d688018e58f94d6e0a\"\n
    eth_private_key = \"0x05d97734fc8d75ecae60e1be43f57322365b9b73614a7cf5ec7bc98d12373cb6\"\n"
        .to_string();
    lines.push(payment);

    let network = "
    [network]\n
    mesh_ip = \"fd00::1\"\n
    discovery_ip = \"ff02::1:8\"\n
    babel_port = 6872\n
    rita_hello_port = 4876\n
    rita_contact_port = 4874\n
    rita_dashboard_port = 4877\n
    rita_tick_interval = 5\n
    wg_public_key = \"bvM10HW73yePrxdtCQQ4U20W5ogogdiZtUihrPc/oGY=\"\n
    wg_private_key = \"OGzbcm6czrjOEAViK7ZzlWM8mtjCxp7UPbuLS/dATV4=\"\n
    wg_private_key_path = \"/tmp/priv\"\n
    wg_start_port = 60000\n
    peer_interfaces = []\n
    tunnel_timeout_seconds = 900\n
    manual_peers = []\n
    external_nic = \"veth-5-8\"\n
    default_route = []\n"
        .to_string();
    lines.push(network);

    let exit_network = "
    [exit_network]\n
    wg_tunnel_port = 59999\n
    wg_v2_tunnel_port = 59998\n
    exit_hello_port = 4875\n
    exit_price = 50\n
    own_internal_ip = \"172.168.1.254\"\n
    exit_start_ip = \"172.168.1.100\"\n
    netmask = 24\n
    subnet = \"fd00::1337/40\"\n
    entry_timeout = 7776000\n
    wg_public_key = \"H/ABwzXk834OwGYU8CZGfFxNZOd+BAJEaVDHiEiWWhU=\"\n
    wg_private_key = \"ALxcZm2r58gY0sB4vIfnjShc86qBoVK3f32H9VrwqWU=\"\n
    wg_private_key_path = \"/tmp/exit-priv\"\n
    registered_users_contract_addr = \"0xb9b674D720F96995ca033ec347df080d500c2230\"\n
    pass = \"Some pass here\"\n"
        .to_string();
    lines.push(exit_network);

    let cluster = "
    [[exit_network.cluster_exits]]\n
    mesh_ip = \"fd00::5\"\n
    eth_address = \"0xbe398dc24de37c73cec974d688018e58f94d6e0a\"\n
    wg_public_key = \"bvM10HW73yePrxdtCQQ4U20W5ogogdiZtUihrPc/oGY=\"\n
    althea_address = \"althea11lrsu892mqx2mndyvjufrh2ux56tyfxl2e3eht3\"\n"
        .to_string();
    lines.push(cluster);

    let dao = "
    [dao]\n
    dao_enforcement = false\n
    cache_timeout_seconds = 600\n
    node_list = []\n
    dao_addresses = []\n"
        .to_string();
    lines.push(dao);

    let verif = "
    [verif_settings]\n
    type = \"Email\"\n

    [verif_settings.contents]\n
    test = true\n
    email_cooldown=60\n
    test_dir = \"mail\"\n
    from_address = \"email-verif@example.com\"\n
    balance_notification_interval = 600\n
    notify_low_balance = true\n"
        .to_string();
    lines.push(verif);

    let log = "
    [log]\n
    enabled = true\n"
        .to_string();
    lines.push(log);

    write_out(&path, lines)
}
