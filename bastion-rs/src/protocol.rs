use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConnectionRequest {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub request_id: String, // Unique ID for this request
    pub app_name: String,
    pub app_path: String,
    pub app_category: String,
    pub dest_ip: String,
    pub dest_port: u16,
    pub protocol: String,
    #[serde(default)]
    pub learning_mode: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum GuiCommand {
    #[serde(rename = "gui_response")]
    Response(#[allow(dead_code)] GuiResponse),
    #[serde(rename = "cancel_popup")]
    CancelPopup(CancelRequest),
    #[serde(rename = "add_rule")]
    AddRule(AddRuleRequest),
    #[serde(rename = "delete_rule")]
    DeleteRule(DeleteRuleRequest),
    #[serde(rename = "list_rules")]
    ListRules,
    #[serde(rename = "clear_cache")]
    ClearCache(ClearCacheRequest),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CancelRequest {
    pub request_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GuiNotification {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub request_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClearCacheRequest {
    pub cache_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AddRuleRequest {
    pub app_path: String,
    pub app_name: String,
    pub port: u16,
    pub allow: bool,
    pub all_ports: bool,
    #[serde(default)]
    pub dest_ip: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeleteRuleRequest {
    pub key: String, 
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct GuiResponse {
    pub request_id: String, // Correlate with request
    pub allow: bool,
    #[serde(default)]
    pub permanent: bool,
    #[serde(default)]
    pub all_ports: bool,
    #[serde(default)] 
    pub duration: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StatsUpdate {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub stats: StatsData,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StatsData {
    pub total_connections: u64,
    pub allowed_connections: u64,
    pub blocked_connections: u64,
    pub learning_mode: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RuleDeletedResponse {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub key: String,
    pub success: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RulesListResponse {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub rules: serde_json::Value,
}
