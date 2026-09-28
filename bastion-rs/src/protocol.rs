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
    #[serde(rename = "usb_response")]
    UsbResponse(UsbResponse),
    #[serde(rename = "list_usb_rules")]
    ListUsbRules,
    #[serde(rename = "delete_usb_rule")]
    DeleteUsbRule(DeleteRuleRequest),
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

/// Daemon -> GUI: ask the user whether a newly attached USB device may be used.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UsbRequest {
    #[serde(rename = "type")]
    pub msg_type: String, // "usb_request"
    pub nonce: String,
    pub device: UsbDevicePrompt,
    /// How long the daemon waits for an answer before blocking the device.
    #[serde(default)]
    pub timeout_secs: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UsbDevicePrompt {
    pub vendor_id: String,
    pub product_id: String,
    pub vendor_name: String,
    pub product_name: String,
    pub device_class: u8,
    pub is_high_risk: bool,
    #[serde(default)]
    pub serial: Option<String>,
    pub bus_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UsbRulesListResponse {
    #[serde(rename = "type")]
    pub msg_type: String, // "usb_rules_list"
    pub enabled: bool,
    pub rules: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UsbRuleDeletedResponse {
    #[serde(rename = "type")]
    pub msg_type: String, // "usb_rule_deleted"
    pub key: String,
    pub success: bool,
}

/// GUI -> daemon: the user's decision for a `usb_request`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UsbResponse {
    /// Consumed as the enum tag when parsed via `GuiCommand`, hence the default.
    #[serde(rename = "type", default = "usb_response_type")]
    pub msg_type: String,
    pub nonce: String,
    pub allow: bool,
    /// "device", "model" or "vendor"
    #[serde(default = "default_usb_scope")]
    pub scope: String,
    #[serde(default)]
    pub permanent: bool,
}

fn usb_response_type() -> String {
    "usb_response".to_string()
}

fn default_usb_scope() -> String {
    "model".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usb_admin_commands_parse() {
        assert!(matches!(
            serde_json::from_str::<GuiCommand>(r#"{"type":"list_usb_rules"}"#).unwrap(),
            GuiCommand::ListUsbRules
        ));
        match serde_json::from_str::<GuiCommand>(r#"{"type":"delete_usb_rule","key":"046d:*:*"}"#).unwrap() {
            GuiCommand::DeleteUsbRule(d) => assert_eq!(d.key, "046d:*:*"),
            other => panic!("unexpected {:?}", other),
        }
    }

    #[test]
    fn usb_response_parses_through_gui_command() {
        let line = r#"{"type":"usb_response","nonce":"abc","allow":true,"scope":"device","permanent":true}"#;
        match serde_json::from_str::<GuiCommand>(line).unwrap() {
            GuiCommand::UsbResponse(r) => {
                assert_eq!(r.nonce, "abc");
                assert!(r.allow && r.permanent);
                assert_eq!(r.scope, "device");
            }
            other => panic!("unexpected {:?}", other),
        }
    }
}
