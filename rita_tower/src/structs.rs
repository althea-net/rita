use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoleSpecificCheckin {
    RitaTower,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RitaTowerInfo {
    pub connected_enbs: f32,
    pub connected_ues: f32,
    pub attached_ues: f32,
    #[serde(default)]
    pub mme_start_time: Duration,
    #[serde(default)]
    pub sgwc_start_time: Duration,
    #[serde(default)]
    pub sgwu_start_time: Duration,
    #[serde(default)]
    pub smf_start_time: Duration,
    #[serde(default)]
    pub upf_start_time: Duration,
}
