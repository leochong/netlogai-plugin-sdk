#include "security_plugin.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace netlogai::plugins::examples {

SecurityPlugin::SecurityPlugin()
    : is_initialized_(false), is_running_(false),
      brute_force_threshold_(5), suspicious_activity_threshold_(10),
      auth_failure_window_(std::chrono::minutes(15)) {}

PluginCapability SecurityPlugin::get_capabilities() const {
    return PluginCapability::LOG_ANALYSIS |
           PluginCapability::REAL_TIME_MONITORING |
           PluginCapability::ALERTING |
           PluginCapability::CONFIGURATION;
}

bool SecurityPlugin::initialize(const PluginContext& context) {
    if (is_initialized_) {
        return true;
    }

    context_ = context;

    // Load threat signatures and malicious IP database
    load_threat_signatures();
    load_malicious_ip_database();

    is_initialized_ = true;
    return true;
}

bool SecurityPlugin::configure(const std::map<std::string, std::string>& config) {
    config_ = config;

    // Parse configuration values
    auto threshold_it = config.find("brute_force_threshold");
    if (threshold_it != config.end()) {
        brute_force_threshold_ = std::stoi(threshold_it->second);
    }

    auto window_it = config.find("auth_failure_window_minutes");
    if (window_it != config.end()) {
        auth_failure_window_ = std::chrono::minutes(std::stoi(window_it->second));
    }

    auto suspicious_it = config.find("suspicious_activity_threshold");
    if (suspicious_it != config.end()) {
        suspicious_activity_threshold_ = std::stoi(suspicious_it->second);
    }

    return true;
}

bool SecurityPlugin::start() {
    if (!is_initialized_) {
        return false;
    }

    is_running_ = true;
    return true;
}

bool SecurityPlugin::stop() {
    is_running_ = false;
    return true;
}

void SecurityPlugin::cleanup() {
    detected_events_.clear();
    auth_failures_.clear();
    is_running_ = false;
    is_initialized_ = false;
}

PluginResult SecurityPlugin::process_log_entries(const std::vector<LogEntry>& entries) {
    if (!is_running_) {
        return {false, "Security plugin not running", {}, {}, {}, {}, 0};
    }

    auto start_time = std::chrono::steady_clock::now();

    // Perform comprehensive security analysis
    auto threats = detect_threats(entries);
    auto auth_analysis = analyze_authentication_failures(entries);

    auto end_time = std::chrono::steady_clock::now();
    auto execution_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    // Combine results
    std::map<std::string, std::string> result_data;
    result_data["threats_detected"] = std::to_string(detected_events_.size());
    result_data["auth_failures_analyzed"] = std::to_string(auth_failures_.size());
    result_data["risk_score"] = std::to_string(calculate_risk_score(detected_events_));

    // Generate summary report
    std::string summary = generate_security_report(detected_events_);

    return {
        true,
        summary,
        result_data,
        {},  // warnings
        {},  // errors
        execution_time,
        0    // memory usage (would be calculated in real implementation)
    };
}

PluginResult SecurityPlugin::detect_threats(const std::vector<LogEntry>& entries) {
    detected_events_.clear();

    for (const auto& entry : entries) {
        // Check against threat signatures
        for (const auto& signature : threat_signatures_) {
            std::smatch match;
            if (std::regex_search(entry.message, match, signature.pattern)) {
                SecurityEvent event = create_security_event(
                    signature.name,
                    entry,
                    signature.severity,
                    signature.description
                );

                // Extract additional information from regex groups
                for (size_t i = 1; i < match.size(); ++i) {
                    event.evidence.push_back("Matched: " + match[i].str());
                }

                detected_events_.push_back(event);
            }
        }

        // Check for suspicious IP addresses
        std::regex ip_regex(R"(\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b)");
        std::smatch ip_match;
        std::string::const_iterator start(entry.message.cbegin());
        while (std::regex_search(start, entry.message.cend(), ip_match, ip_regex)) {
            std::string ip = ip_match[1];
            if (is_suspicious_ip(ip)) {
                SecurityEvent event = create_security_event(
                    "suspicious_ip",
                    entry,
                    7, // High severity
                    "Communication with known malicious IP address: " + ip
                );
                event.source_ip = ip;
                detected_events_.push_back(event);
            }
            start = ip_match.suffix().first;
        }
    }

    // Analyze for additional threat patterns
    auto login_threats = analyze_login_attempts(entries);
    auto network_threats = analyze_network_anomalies(entries);
    auto privilege_threats = analyze_privilege_escalation(entries);

    detected_events_.insert(detected_events_.end(), login_threats.begin(), login_threats.end());
    detected_events_.insert(detected_events_.end(), network_threats.begin(), network_threats.end());
    detected_events_.insert(detected_events_.end(), privilege_threats.begin(), privilege_threats.end());

    std::map<std::string, std::string> result_data;
    result_data["threats_found"] = std::to_string(detected_events_.size());
    result_data["risk_score"] = std::to_string(calculate_risk_score(detected_events_));

    return {
        true,
        "Detected " + std::to_string(detected_events_.size()) + " potential threats",
        result_data,
        {}, {}, {}, 0
    };
}

PluginResult SecurityPlugin::analyze_authentication_failures(const std::vector<LogEntry>& entries) {
    auto now = std::chrono::system_clock::now();

    // Clean up old auth failure records
    for (auto it = auth_failures_.begin(); it != auth_failures_.end();) {
        if (now - it->second.last_attempt > auth_failure_window_) {
            it = auth_failures_.erase(it);
        } else {
            ++it;
        }
    }

    // Analyze authentication events
    std::vector<SecurityEvent> auth_events;
    std::regex auth_failure_regex(R"((Authentication|Login|Auth).*(?:fail|invalid|denied|reject).*(?:user|from)\s+(\S+).*(?:from|@)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))", std::regex_constants::icase);

    for (const auto& entry : entries) {
        std::smatch match;
        if (std::regex_search(entry.message, match, auth_failure_regex)) {
            std::string username = match[2];
            std::string source_ip = match[3];
            std::string key = source_ip + ":" + username;

            if (auth_failures_.find(key) == auth_failures_.end()) {
                AuthFailurePattern pattern;
                pattern.source_ip = source_ip;
                pattern.username = username;
                pattern.failure_count = 1;
                pattern.first_attempt = entry.timestamp;
                pattern.last_attempt = entry.timestamp;
                pattern.is_brute_force = false;
                auth_failures_[key] = pattern;
            } else {
                auth_failures_[key].failure_count++;
                auth_failures_[key].last_attempt = entry.timestamp;

                if (auth_failures_[key].failure_count >= brute_force_threshold_ &&
                    !auth_failures_[key].is_brute_force) {
                    auth_failures_[key].is_brute_force = true;

                    // Create brute force security event
                    SecurityEvent event = create_security_event(
                        "brute_force_attack",
                        entry,
                        8, // High severity
                        "Brute force attack detected from " + source_ip +
                        " targeting user " + username +
                        " (" + std::to_string(auth_failures_[key].failure_count) + " attempts)"
                    );
                    event.source_ip = source_ip;
                    auth_events.push_back(event);
                }
            }
        }
    }

    detected_events_.insert(detected_events_.end(), auth_events.begin(), auth_events.end());

    std::map<std::string, std::string> result_data;
    result_data["auth_failures"] = std::to_string(auth_failures_.size());
    result_data["brute_force_attempts"] = std::to_string(auth_events.size());

    return {
        true,
        "Analyzed " + std::to_string(auth_failures_.size()) + " authentication patterns",
        result_data,
        {}, {}, {}, 0
    };
}

std::vector<SecurityPlugin::SecurityEvent> SecurityPlugin::analyze_login_attempts(
    const std::vector<LogEntry>& entries) {

    std::vector<SecurityEvent> events;

    // Look for unusual login patterns
    std::regex unusual_time_regex(R"(successful.*login.*at\s+(\d{2}:\d{2}))", std::regex_constants::icase);
    std::regex multiple_locations_regex(R"(login.*from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))", std::regex_constants::icase);

    for (const auto& entry : entries) {
        // Check for logins during unusual hours (outside 6 AM - 10 PM)
        std::smatch time_match;
        if (std::regex_search(entry.message, time_match, unusual_time_regex)) {
            auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
            auto* tm = std::localtime(&time_t);

            if (tm->tm_hour < 6 || tm->tm_hour > 22) {
                SecurityEvent event = create_security_event(
                    "unusual_login_time",
                    entry,
                    5, // Medium severity
                    "Login attempt during unusual hours: " + time_match[1].str()
                );
                events.push_back(event);
            }
        }
    }

    return events;
}

std::vector<SecurityPlugin::SecurityEvent> SecurityPlugin::analyze_network_anomalies(
    const std::vector<LogEntry>& entries) {

    std::vector<SecurityEvent> events;

    // Look for port scanning, unusual traffic patterns, etc.
    std::regex port_scan_regex(R"(connection.*attempt.*port\s+(\d+).*(?:refused|denied|blocked))", std::regex_constants::icase);
    std::regex dos_regex(R"((?:flood|storm|excessive).*(?:packets|requests|connections))", std::regex_constants::icase);

    for (const auto& entry : entries) {
        std::smatch match;

        // Port scanning detection
        if (std::regex_search(entry.message, match, port_scan_regex)) {
            SecurityEvent event = create_security_event(
                "port_scan",
                entry,
                6, // Medium-high severity
                "Potential port scanning activity on port " + match[1].str()
            );
            events.push_back(event);
        }

        // DoS/DDoS detection
        if (std::regex_search(entry.message, match, dos_regex)) {
            SecurityEvent event = create_security_event(
                "dos_attack",
                entry,
                8, // High severity
                "Potential DoS/DDoS attack detected"
            );
            events.push_back(event);
        }
    }

    return events;
}

std::vector<SecurityPlugin::SecurityEvent> SecurityPlugin::analyze_privilege_escalation(
    const std::vector<LogEntry>& entries) {

    std::vector<SecurityEvent> events;

    std::regex privilege_regex(R"((?:sudo|su|privilege|admin|root).*(?:escalation|elevation|granted|failed))", std::regex_constants::icase);
    std::regex config_change_regex(R"(configuration.*(?:changed|modified|updated).*by\s+(\w+))", std::regex_constants::icase);

    for (const auto& entry : entries) {
        std::smatch match;

        if (std::regex_search(entry.message, match, privilege_regex)) {
            SecurityEvent event = create_security_event(
                "privilege_escalation",
                entry,
                7, // High severity
                "Privilege escalation attempt detected"
            );
            events.push_back(event);
        }

        if (std::regex_search(entry.message, match, config_change_regex)) {
            SecurityEvent event = create_security_event(
                "unauthorized_config_change",
                entry,
                6, // Medium-high severity
                "Configuration change by user: " + match[1].str()
            );
            events.push_back(event);
        }
    }

    return events;
}

void SecurityPlugin::load_threat_signatures() {
    threat_signatures_ = {
        {
            "sql_injection",
            "SQL injection attempt detected",
            std::regex(R"((?:union|select|insert|update|delete|drop).*(?:\s|'|"|;))", std::regex_constants::icase),
            8,
            "web_security",
            {"sql", "injection", "database"}
        },
        {
            "xss_attack",
            "Cross-site scripting attempt detected",
            std::regex(R"(<script.*>|javascript:|onerror=|onload=)", std::regex_constants::icase),
            7,
            "web_security",
            {"xss", "script", "injection"}
        },
        {
            "malware_communication",
            "Potential malware communication detected",
            std::regex(R"((?:bot|c2|command.*control|beacon))", std::regex_constants::icase),
            9,
            "malware",
            {"botnet", "c2", "malware"}
        },
        {
            "data_exfiltration",
            "Potential data exfiltration detected",
            std::regex(R"((?:upload|download|transfer).*(?:large|unusual|massive|bulk).*(?:data|file))", std::regex_constants::icase),
            8,
            "data_loss",
            {"exfiltration", "data", "transfer"}
        }
    };
}

void SecurityPlugin::load_malicious_ip_database() {
    // In a real implementation, this would load from threat intelligence feeds
    known_malicious_ips_ = {
        "192.168.1.100", // Example malicious IP
        "10.0.0.50",     // Example suspicious IP
        "172.16.0.25"    // Example compromised IP
    };

    suspicious_patterns_ = {
        "tor_exit_node",
        "vpn_provider",
        "proxy_service",
        "botnet_member"
    };
}

bool SecurityPlugin::is_suspicious_ip(const std::string& ip) const {
    return known_malicious_ips_.find(ip) != known_malicious_ips_.end();
}

SecurityPlugin::SecurityEvent SecurityPlugin::create_security_event(
    const std::string& threat_type,
    const LogEntry& entry,
    uint32_t severity,
    const std::string& description) {

    SecurityEvent event;
    event.event_id = "sec_" + std::to_string(std::hash<std::string>{}(entry.id + threat_type));
    event.timestamp = entry.timestamp;
    event.threat_type = threat_type;
    event.source_device = entry.device_name;
    event.severity = severity;
    event.description = description;
    event.evidence.push_back("Original log: " + entry.message);

    return event;
}

std::string SecurityPlugin::generate_security_report(const std::vector<SecurityEvent>& events) {
    if (events.empty()) {
        return "No security threats detected.";
    }

    std::ostringstream report;
    report << "Security Analysis Report\n";
    report << "========================\n";
    report << "Total threats detected: " << events.size() << "\n";
    report << "Risk score: " << calculate_risk_score(events) << "/100\n\n";

    // Group events by severity
    std::unordered_map<uint32_t, std::vector<const SecurityEvent*>> severity_groups;
    for (const auto& event : events) {
        severity_groups[event.severity].push_back(&event);
    }

    // Report high severity events first
    for (auto severity = 10u; severity >= 1u; --severity) {
        auto it = severity_groups.find(severity);
        if (it != severity_groups.end() && !it->second.empty()) {
            report << "Severity " << severity << " Events (" << it->second.size() << "):\n";
            for (const auto* event : it->second) {
                report << "  - " << format_security_event(*event) << "\n";
            }
            report << "\n";
        }
        if (severity == 1) break; // Prevent underflow
    }

    return report.str();
}

std::string SecurityPlugin::format_security_event(const SecurityEvent& event) {
    std::ostringstream formatted;
    auto time_t = std::chrono::system_clock::to_time_t(event.timestamp);
    formatted << std::put_time(std::localtime(&time_t), "%H:%M:%S");
    formatted << " [" << event.source_device << "] ";
    formatted << event.threat_type << ": " << event.description;

    return formatted.str();
}

uint32_t SecurityPlugin::calculate_risk_score(const std::vector<SecurityEvent>& events) {
    if (events.empty()) return 0;

    uint32_t total_score = 0;
    for (const auto& event : events) {
        total_score += event.severity;
    }

    // Normalize to 0-100 scale
    uint32_t max_possible = events.size() * 10;
    return std::min(100u, (total_score * 100) / max_possible);
}

PluginResult SecurityPlugin::analyze_device(const NetworkDevice& device) {
    std::map<std::string, std::string> result_data;
    result_data["device_name"] = device.name;
    result_data["device_type"] = device.device_type;
    result_data["security_status"] = device.is_online ? "monitored" : "offline";

    return {
        true,
        "Device security analysis for " + device.name,
        result_data,
        {}, {}, {}, 0
    };
}

PluginResult SecurityPlugin::execute_command(const std::string& command,
                                           const std::map<std::string, std::string>& parameters) {
    if (command == "threat_report") {
        std::string report = generate_security_report(detected_events_);
        return {true, report, {{"report_type", "threat_analysis"}}, {}, {}, {}, 0};
    }

    if (command == "reset_detections") {
        detected_events_.clear();
        auth_failures_.clear();
        return {true, "Security detections reset", {}, {}, {}, {}, 0};
    }

    return {false, "Unknown command: " + command, {}, {}, {"Unknown command"}, {}, 0};
}

PluginResult SecurityPlugin::process_real_time_entry(const LogEntry& entry) {
    std::vector<LogEntry> single_entry = {entry};
    return process_log_entries(single_entry);
}

std::vector<std::string> SecurityPlugin::get_supported_commands() const {
    return {"threat_report", "reset_detections"};
}

std::map<std::string, std::string> SecurityPlugin::get_configuration_schema() const {
    return {
        {"brute_force_threshold", "Number of failed attempts to trigger brute force alert (default: 5)"},
        {"auth_failure_window_minutes", "Time window for authentication failure analysis (default: 15)"},
        {"suspicious_activity_threshold", "Threshold for suspicious activity alerts (default: 10)"}
    };
}

std::string SecurityPlugin::get_status() const {
    if (!is_initialized_) return "not_initialized";
    if (!is_running_) return "stopped";
    return "running";
}

PluginResult SecurityPlugin::scan_for_vulnerabilities(const NetworkDevice& device) {
    // Simplified vulnerability scanning
    std::vector<std::string> vulnerabilities;

    // Check for common misconfigurations
    if (device.device_type.find("cisco") != std::string::npos) {
        vulnerabilities.push_back("Check SNMP community strings");
        vulnerabilities.push_back("Verify SSH configuration");
    }

    std::map<std::string, std::string> result_data;
    result_data["device_id"] = device.id;
    result_data["vulnerabilities_found"] = std::to_string(vulnerabilities.size());

    std::string message = "Vulnerability scan completed for " + device.name;
    if (!vulnerabilities.empty()) {
        message += " - " + std::to_string(vulnerabilities.size()) + " issues found";
    }

    return {true, message, result_data, {}, {}, {}, 0};
}

std::vector<std::string> SecurityPlugin::get_threat_signatures() const {
    std::vector<std::string> signatures;
    for (const auto& sig : threat_signatures_) {
        signatures.push_back(sig.name);
    }
    return signatures;
}

} // namespace netlogai::plugins::examples

// Plugin export macros
NETLOGAI_PLUGIN_CREATE(netlogai::plugins::examples::SecurityPlugin)
NETLOGAI_PLUGIN_DESTROY()