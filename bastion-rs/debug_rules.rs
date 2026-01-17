use std::collections::HashMap;

fn main() {
    let mut rules: HashMap<(String, u16), bool> = HashMap::new();
    
    // Simulate loading rules from the file format
    let keys = vec![
        "@name:IPC:CSteamEngin:27018",
        "@name:IPC:CSteamEngin:*",
        "@name:steam:*",
    ];
    
    for key in keys {
        if let Some(colon_pos) = key.rfind(':') {
            let app_path = &key[..colon_pos];
            let port_str = &key[colon_pos + 1..];
            let port = if port_str == "*" { 0 } else { port_str.parse::<u16>().unwrap() };
            println!("Loaded: path='{}', port={}", app_path, port);
            rules.insert((app_path.to_string(), port), true);
        }
    }
    
    // Test scenarios
    let test_cases = vec![
        ("IPC:CSteamEngin", 27018),
        ("IPC:CSteamEngin", 9999),
        ("steam", 443),
    ];
    
    for (app_name, port) in test_cases {
        let name_based_key = format!("@name:{}", app_name);
        println!("\nTesting: name={}, port={}", app_name, port);
        
        let mut found = false;
        if let Some(&allow) = rules.get(&(name_based_key.clone(), port)) {
            println!("  Exact match: {}", allow);
            found = true;
        }
        if let Some(&allow) = rules.get(&(name_based_key, 0)) {
            println!("  Wildcard match: {}", allow);
            found = true;
        }
        
        if !found {
            println!("  No match found!");
        }
    }
}
