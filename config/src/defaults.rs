pub fn server_hostname() -> url::Host {
    url::Host::Domain(String::from("localhost"))
}

pub fn server_address() -> std::net::IpAddr {
    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
}

pub const fn server_port() -> u16 {
    6001
}

pub const fn server_port_tls() -> u16 {
    6002
}

pub fn base_directories() -> xdg::BaseDirectories {
    xdg::BaseDirectories::with_prefix("houseflow").unwrap()
}

pub fn config_home() -> std::path::PathBuf {
    base_directories().get_config_home()
}

pub fn data_home() -> std::path::PathBuf {
    base_directories().get_data_home()
}

pub fn clerk_path() -> std::path::PathBuf {
    data_home().join("clerk.sled")
}
