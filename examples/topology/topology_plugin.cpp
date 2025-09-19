#include "topology_plugin.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <regex>
#include <queue>

namespace netlogai::plugins::examples {

TopologyPlugin::TopologyPlugin()
    : is_initialized_(false), is_running_(false),
      device_timeout_(std::chrono::minutes(30)),
      auto_discovery_enabled_(true),
      passive_discovery_enabled_(true) {

    discovery_protocols_ = {"CDP", "LLDP", "OSPF", "BGP", "ARP"};
    scan_ranges_ = {"192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24"};
}

PluginCapability TopologyPlugin::get_capabilities() const {
    return PluginCapability::LOG_ANALYSIS |
           PluginCapability::DEVICE_INTERACTION |
           PluginCapability::VISUALIZATION |
           PluginCapability::CONFIGURATION;
}

bool TopologyPlugin::initialize(const PluginContext& context) {
    if (is_initialized_) {
        return true;
    }

    context_ = context;
    topology_map_.last_updated = std::chrono::system_clock::now();
    is_initialized_ = true;
    return true;
}

bool TopologyPlugin::configure(const std::map<std::string, std::string>& config) {
    config_ = config;

    // Parse configuration
    auto timeout_it = config.find("device_timeout_minutes");
    if (timeout_it != config.end()) {
        device_timeout_ = std::chrono::minutes(std::stoi(timeout_it->second));
    }

    auto auto_discovery_it = config.find("auto_discovery");
    if (auto_discovery_it != config.end()) {
        auto_discovery_enabled_ = (auto_discovery_it->second == "true" || auto_discovery_it->second == "1");
    }

    auto passive_it = config.find("passive_discovery");
    if (passive_it != config.end()) {
        passive_discovery_enabled_ = (passive_it->second == "true" || passive_it->second == "1");
    }

    return true;
}

bool TopologyPlugin::start() {
    if (!is_initialized_) {
        return false;
    }

    is_running_ = true;

    if (auto_discovery_enabled_) {
        // Start background discovery
        discover_network_devices();
    }

    return true;
}

bool TopologyPlugin::stop() {
    is_running_ = false;
    return true;
}

void TopologyPlugin::cleanup() {
    topology_map_.nodes.clear();
    topology_map_.connections.clear();
    topology_map_.subnets.clear();
    topology_map_.routing_table.clear();
    discovered_devices_.clear();
    device_last_seen_.clear();
    is_running_ = false;
    is_initialized_ = false;
}

PluginResult TopologyPlugin::process_log_entries(const std::vector<LogEntry>& entries) {
    if (!is_running_) {
        return {false, "Topology plugin not running", {}, {}, {}, {}, 0};
    }

    auto start_time = std::chrono::steady_clock::now();

    // Parse topology information from log entries
    for (const auto& entry : entries) {
        parse_cdp_neighbor(entry);
        parse_lldp_neighbor(entry);
        parse_ospf_neighbor(entry);
        parse_bgp_neighbor(entry);
        parse_arp_entry(entry);
        parse_routing_table(entry);
        parse_interface_status(entry);

        // Update last seen timestamp
        device_last_seen_[entry.device_name] = entry.timestamp;
    }

    // Discover devices from logs if passive discovery is enabled
    if (passive_discovery_enabled_) {
        auto log_discovered = discover_via_logs(entries);
        for (const auto& device : log_discovered) {
            // Add to discovered devices if not already present
            auto it = std::find_if(discovered_devices_.begin(), discovered_devices_.end(),
                [&device](const NetworkDevice& existing) {
                    return existing.id == device.id || existing.hostname == device.hostname;
                });

            if (it == discovered_devices_.end()) {
                discovered_devices_.push_back(device);
            }
        }
    }

    // Update topology map
    build_connection_graph();
    determine_device_hierarchy();
    group_devices_by_subnet();

    // Cleanup stale data
    cleanup_stale_devices();
    cleanup_stale_connections();

    topology_map_.last_updated = std::chrono::system_clock::now();
    topology_map_.total_devices = static_cast<uint32_t>(topology_map_.nodes.size());
    topology_map_.active_connections = static_cast<uint32_t>(
        std::count_if(topology_map_.connections.begin(), topology_map_.connections.end(),
            [](const NetworkConnection& conn) { return conn.is_active; })
    );

    auto end_time = std::chrono::steady_clock::now();
    auto execution_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    std::map<std::string, std::string> result_data;
    result_data["devices_discovered"] = std::to_string(topology_map_.total_devices);
    result_data["active_connections"] = std::to_string(topology_map_.active_connections);
    result_data["subnets_identified"] = std::to_string(topology_map_.subnets.size());

    return {
        true,
        "Topology analysis completed - " + std::to_string(topology_map_.total_devices) + " devices, " +
        std::to_string(topology_map_.active_connections) + " connections",
        result_data,
        {}, {}, execution_time, 0
    };
}

PluginResult TopologyPlugin::discover_network_devices() {
    discovered_devices_.clear();

    // Discover via different methods
    auto snmp_devices = discover_via_snmp("public"); // Default community
    auto ping_devices = discover_via_ping_sweep("192.168.1.0/24");

    // Combine results
    discovered_devices_.insert(discovered_devices_.end(), snmp_devices.begin(), snmp_devices.end());
    discovered_devices_.insert(discovered_devices_.end(), ping_devices.begin(), ping_devices.end());

    // Remove duplicates based on IP address
    std::sort(discovered_devices_.begin(), discovered_devices_.end(),
        [](const NetworkDevice& a, const NetworkDevice& b) {
            return a.management_ip < b.management_ip;
        });

    discovered_devices_.erase(
        std::unique(discovered_devices_.begin(), discovered_devices_.end(),
            [](const NetworkDevice& a, const NetworkDevice& b) {
                return a.management_ip == b.management_ip;
            }),
        discovered_devices_.end()
    );

    std::map<std::string, std::string> result_data;
    result_data["devices_found"] = std::to_string(discovered_devices_.size());

    return {
        true,
        "Network discovery completed - found " + std::to_string(discovered_devices_.size()) + " devices",
        result_data,
        {}, {}, {}, 0
    };
}

std::vector<NetworkDevice> TopologyPlugin::discover_via_logs(const std::vector<LogEntry>& entries) {
    std::vector<NetworkDevice> devices;
    std::unordered_set<std::string> seen_devices;

    for (const auto& entry : entries) {
        if (seen_devices.find(entry.device_name) == seen_devices.end()) {
            NetworkDevice device;
            device.id = "log_" + entry.device_name;
            device.name = entry.device_name;
            device.hostname = entry.device_name;
            device.device_type = "unknown";
            device.is_online = true;
            device.last_seen = entry.timestamp;

            // Try to extract management IP from metadata
            auto ip_it = entry.metadata.find("source_ip");
            if (ip_it != entry.metadata.end()) {
                device.management_ip = ip_it->second;
            }

            devices.push_back(device);
            seen_devices.insert(entry.device_name);
        }
    }

    return devices;
}

void TopologyPlugin::parse_cdp_neighbor(const LogEntry& entry) {
    // Parse CDP (Cisco Discovery Protocol) neighbor information
    std::regex cdp_regex(
        R"(CDP.*neighbor\s+([^\s]+).*on\s+port\s+([A-Za-z0-9\/]+).*Platform:\s*([^\,\n]+))",
        std::regex_constants::icase
    );

    std::smatch match;
    if (std::regex_search(entry.message, match, cdp_regex)) {
        std::string neighbor_name = match[1];
        std::string local_interface = match[2];
        std::string platform = match[3];

        NetworkConnection connection = create_connection(
            entry.device_name,
            local_interface,
            neighbor_name,
            "unknown", // Remote interface not specified in this pattern
            "CDP"
        );

        topology_map_.connections.push_back(connection);

        // Create or update topology nodes
        if (topology_map_.nodes.find(entry.device_name) == topology_map_.nodes.end()) {
            TopologyNode node;
            node.device.id = entry.device_name;
            node.device.name = entry.device_name;
            node.device.device_type = "router"; // Assume router for CDP
            node.last_seen = entry.timestamp;
            node.is_reachable = true;
            topology_map_.nodes[entry.device_name] = node;
        }

        // Add neighbor to connections
        topology_map_.nodes[entry.device_name].connected_devices.push_back(neighbor_name);
        topology_map_.nodes[entry.device_name].neighbor_interfaces[neighbor_name] = local_interface;
    }
}

void TopologyPlugin::parse_lldp_neighbor(const LogEntry& entry) {
    // Parse LLDP (Link Layer Discovery Protocol) neighbor information
    std::regex lldp_regex(
        R"(LLDP.*neighbor\s+([^\s]+).*interface\s+([A-Za-z0-9\/]+).*System\s+Name:\s*([^\,\n]+))",
        std::regex_constants::icase
    );

    std::smatch match;
    if (std::regex_search(entry.message, match, lldp_regex)) {
        std::string neighbor_id = match[1];
        std::string local_interface = match[2];
        std::string system_name = match[3];

        NetworkConnection connection = create_connection(
            entry.device_name,
            local_interface,
            system_name,
            "unknown",
            "LLDP"
        );

        topology_map_.connections.push_back(connection);
    }
}

void TopologyPlugin::parse_ospf_neighbor(const LogEntry& entry) {
    // Parse OSPF neighbor information
    std::regex ospf_regex(
        R"(OSPF.*neighbor\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*state\s+changed\s+to\s+(Full|Down).*interface\s+([A-Za-z0-9\/]+))",
        std::regex_constants::icase
    );

    std::smatch match;
    if (std::regex_search(entry.message, match, ospf_regex)) {
        std::string neighbor_ip = match[1];
        std::string state = match[2];
        std::string interface = match[3];

        NetworkConnection connection = create_connection(
            entry.device_name,
            interface,
            neighbor_ip,
            "unknown",
            "OSPF"
        );
        connection.is_active = (state == "Full");

        topology_map_.connections.push_back(connection);
    }
}

void TopologyPlugin::parse_bgp_neighbor(const LogEntry& entry) {
    // Parse BGP neighbor information
    std::regex bgp_regex(
        R"(BGP.*neighbor\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*state\s+changed\s+to\s+(Established|Idle))",
        std::regex_constants::icase
    );

    std::smatch match;
    if (std::regex_search(entry.message, match, bgp_regex)) {
        std::string neighbor_ip = match[1];
        std::string state = match[2];

        NetworkConnection connection = create_connection(
            entry.device_name,
            "bgp",
            neighbor_ip,
            "bgp",
            "BGP"
        );
        connection.is_active = (state == "Established");

        topology_map_.connections.push_back(connection);
    }
}

void TopologyPlugin::parse_arp_entry(const LogEntry& entry) {
    // Parse ARP table entries to discover directly connected devices
    std::regex arp_regex(
        R"(ARP.*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}.*([A-Za-z0-9\/]+))",
        std::regex_constants::icase
    );

    std::smatch match;
    if (std::regex_search(entry.message, match, arp_regex)) {
        std::string ip_address = match[1];
        std::string interface = match[3];

        // Create a connection based on ARP entry
        NetworkConnection connection = create_connection(
            entry.device_name,
            interface,
            ip_address,
            "unknown",
            "ARP"
        );

        topology_map_.connections.push_back(connection);
    }
}

void TopologyPlugin::parse_routing_table(const LogEntry& entry) {
    // Parse routing table entries
    std::regex route_regex(
        R"(route.*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+).*via\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*([A-Za-z0-9\/]+))",
        std::regex_constants::icase
    );

    std::smatch match;
    if (std::regex_search(entry.message, match, route_regex)) {
        std::string destination = match[1];
        std::string next_hop = match[2];
        std::string interface = match[3];

        RoutingEntry route_entry;
        route_entry.destination_network = destination;
        route_entry.next_hop = next_hop;
        route_entry.interface = interface;
        route_entry.protocol = "static"; // Default, could be parsed
        route_entry.source_device = entry.device_name;
        route_entry.learned_at = entry.timestamp;
        route_entry.metric = 1; // Default metric

        topology_map_.routing_table.push_back(route_entry);
    }
}

void TopologyPlugin::parse_interface_status(const LogEntry& entry) {
    // Parse interface status changes
    std::regex interface_regex(
        R"(Interface\s+([A-Za-z0-9\/]+).*(?:up|down|changed state))",
        std::regex_constants::icase
    );

    std::smatch match;
    if (std::regex_search(entry.message, match, interface_regex)) {
        std::string interface_name = match[1];

        // Update device information with interface details
        if (topology_map_.nodes.find(entry.device_name) != topology_map_.nodes.end()) {
            auto& node = topology_map_.nodes[entry.device_name];

            // Add interface to the device if not already present
            auto& interfaces = node.device.interfaces;
            if (std::find(interfaces.begin(), interfaces.end(), interface_name) == interfaces.end()) {
                interfaces.push_back(interface_name);
            }
        }
    }
}

TopologyPlugin::NetworkConnection TopologyPlugin::create_connection(
    const std::string& source_device,
    const std::string& source_interface,
    const std::string& dest_device,
    const std::string& dest_interface,
    const std::string& protocol) {

    NetworkConnection connection;
    connection.source_device = source_device;
    connection.source_interface = source_interface;
    connection.destination_device = dest_device;
    connection.destination_interface = dest_interface;
    connection.connection_type = "direct";
    connection.protocol = protocol;
    connection.discovered_at = std::chrono::system_clock::now();
    connection.is_active = true;
    connection.cost = 1;

    return connection;
}

void TopologyPlugin::build_connection_graph() {
    // Build bidirectional connections and update node relationships
    for (const auto& connection : topology_map_.connections) {
        // Ensure both devices exist in the topology map
        if (topology_map_.nodes.find(connection.source_device) == topology_map_.nodes.end()) {
            TopologyNode node;
            node.device.id = connection.source_device;
            node.device.name = connection.source_device;
            node.device.hostname = connection.source_device;
            node.device.is_online = true;
            node.device.last_seen = connection.discovered_at;
            node.is_reachable = true;
            node.last_seen = connection.discovered_at;
            topology_map_.nodes[connection.source_device] = node;
        }

        if (topology_map_.nodes.find(connection.destination_device) == topology_map_.nodes.end()) {
            TopologyNode node;
            node.device.id = connection.destination_device;
            node.device.name = connection.destination_device;
            node.device.hostname = connection.destination_device;
            node.device.is_online = true;
            node.device.last_seen = connection.discovered_at;
            node.is_reachable = true;
            node.last_seen = connection.discovered_at;
            topology_map_.nodes[connection.destination_device] = node;
        }

        // Add connections to both nodes
        auto& source_node = topology_map_.nodes[connection.source_device];
        auto& dest_node = topology_map_.nodes[connection.destination_device];

        // Add to connected devices list if not already present
        if (std::find(source_node.connected_devices.begin(), source_node.connected_devices.end(),
                     connection.destination_device) == source_node.connected_devices.end()) {
            source_node.connected_devices.push_back(connection.destination_device);
        }

        if (std::find(dest_node.connected_devices.begin(), dest_node.connected_devices.end(),
                     connection.source_device) == dest_node.connected_devices.end()) {
            dest_node.connected_devices.push_back(connection.source_device);
        }
    }
}

void TopologyPlugin::determine_device_hierarchy() {
    // Classify device types and determine hierarchy levels
    for (auto& [device_id, node] : topology_map_.nodes) {
        // Classify device type based on connections and naming patterns
        node.node_type = classify_device_type(node.device);
        node.hierarchy_level = determine_hierarchy_level(node.node_type, node.connected_devices);
    }
}

std::string TopologyPlugin::classify_device_type(const NetworkDevice& device) const {
    std::string name_lower = device.name;
    std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);

    if (name_lower.find("router") != std::string::npos ||
        name_lower.find("rtr") != std::string::npos) {
        return "router";
    } else if (name_lower.find("switch") != std::string::npos ||
               name_lower.find("sw") != std::string::npos) {
        return "switch";
    } else if (name_lower.find("firewall") != std::string::npos ||
               name_lower.find("fw") != std::string::npos) {
        return "firewall";
    } else if (name_lower.find("load") != std::string::npos &&
               name_lower.find("balancer") != std::string::npos) {
        return "load_balancer";
    } else if (name_lower.find("host") != std::string::npos ||
               name_lower.find("server") != std::string::npos) {
        return "host";
    }

    return "unknown";
}

uint32_t TopologyPlugin::determine_hierarchy_level(const std::string& device_type,
                                                  const std::vector<std::string>& connections) const {
    // Determine hierarchy level based on device type and number of connections
    if (device_type == "host" || device_type == "server") {
        return 3; // Host/end-device level
    }

    size_t connection_count = connections.size();

    if (device_type == "router") {
        if (connection_count >= 8) {
            return 0; // Core router
        } else if (connection_count >= 4) {
            return 1; // Distribution router
        } else {
            return 2; // Access router
        }
    } else if (device_type == "switch") {
        if (connection_count >= 12) {
            return 1; // Distribution switch
        } else {
            return 2; // Access switch
        }
    } else if (device_type == "firewall") {
        return 1; // Distribution level
    }

    return 2; // Default to access level
}

PluginResult TopologyPlugin::generate_topology_diagram() {
    std::string ascii_diagram = generate_ascii_topology();
    std::string graphviz_diagram = generate_graphviz_topology();

    std::map<std::string, std::string> result_data;
    result_data["ascii_diagram"] = ascii_diagram;
    result_data["graphviz_diagram"] = graphviz_diagram;
    result_data["nodes_count"] = std::to_string(topology_map_.nodes.size());
    result_data["connections_count"] = std::to_string(topology_map_.connections.size());

    return {
        true,
        "Topology diagram generated",
        result_data,
        {}, {}, {}, 0
    };
}

std::string TopologyPlugin::generate_ascii_topology() const {
    std::ostringstream diagram;

    diagram << "Network Topology Diagram\n";
    diagram << std::string(40, '=') << "\n\n";

    // Group devices by hierarchy level
    std::unordered_map<uint32_t, std::vector<const TopologyNode*>> hierarchy_groups;
    for (const auto& [device_id, node] : topology_map_.nodes) {
        hierarchy_groups[node.hierarchy_level].push_back(&node);
    }

    // Display by hierarchy level
    std::vector<std::string> level_names = {"Core", "Distribution", "Access", "Host"};

    for (uint32_t level = 0; level < 4; ++level) {
        auto it = hierarchy_groups.find(level);
        if (it == hierarchy_groups.end() || it->second.empty()) {
            continue;
        }

        diagram << level_names[level] << " Layer:\n";
        diagram << std::string(level_names[level].length() + 7, '-') << "\n";

        for (const auto* node : it->second) {
            diagram << "  [" << node->device.name << "] (" << node->node_type << ")\n";

            // Show connections
            for (const auto& connected : node->connected_devices) {
                diagram << "    └─ " << connected << "\n";
            }
        }
        diagram << "\n";
    }

    // Show connection summary
    diagram << "Connections Summary:\n";
    diagram << std::string(20, '-') << "\n";

    std::unordered_map<std::string, int> protocol_counts;
    for (const auto& conn : topology_map_.connections) {
        protocol_counts[conn.protocol]++;
    }

    for (const auto& [protocol, count] : protocol_counts) {
        diagram << "  " << protocol << ": " << count << " connections\n";
    }

    return diagram.str();
}

std::string TopologyPlugin::generate_graphviz_topology() const {
    std::ostringstream dot;

    dot << "digraph NetworkTopology {\n";
    dot << "  rankdir=TB;\n";
    dot << "  node [shape=box, style=rounded];\n\n";

    // Add nodes
    for (const auto& [device_id, node] : topology_map_.nodes) {
        std::string color;
        switch (node.hierarchy_level) {
            case 0: color = "red"; break;      // Core
            case 1: color = "orange"; break;   // Distribution
            case 2: color = "yellow"; break;   // Access
            case 3: color = "lightblue"; break; // Host
            default: color = "gray"; break;
        }

        dot << "  \"" << node.device.name << "\" [label=\""
            << format_node_label(node) << "\", color=" << color << "];\n";
    }

    dot << "\n";

    // Add connections
    for (const auto& conn : topology_map_.connections) {
        if (conn.is_active) {
            dot << "  \"" << conn.source_device << "\" -> \""
                << conn.destination_device << "\" [label=\""
                << format_connection_label(conn) << "\"];\n";
        }
    }

    dot << "}\n";

    return dot.str();
}

std::string TopologyPlugin::format_node_label(const TopologyNode& node) const {
    std::ostringstream label;
    label << node.device.name << "\\n(" << node.node_type << ")";
    if (!node.device.management_ip.empty()) {
        label << "\\n" << node.device.management_ip;
    }
    return label.str();
}

std::string TopologyPlugin::format_connection_label(const NetworkConnection& connection) const {
    std::ostringstream label;
    if (!connection.source_interface.empty() && connection.source_interface != "unknown") {
        label << connection.source_interface;
    }
    if (!connection.protocol.empty()) {
        label << "(" << connection.protocol << ")";
    }
    return label.str();
}

void TopologyPlugin::cleanup_stale_devices() {
    auto cutoff_time = std::chrono::system_clock::now() - device_timeout_;

    // Remove stale nodes
    for (auto it = topology_map_.nodes.begin(); it != topology_map_.nodes.end();) {
        if (it->second.last_seen < cutoff_time) {
            it = topology_map_.nodes.erase(it);
        } else {
            ++it;
        }
    }
}

void TopologyPlugin::cleanup_stale_connections() {
    auto cutoff_time = std::chrono::system_clock::now() - device_timeout_;

    topology_map_.connections.erase(
        std::remove_if(topology_map_.connections.begin(), topology_map_.connections.end(),
            [cutoff_time](const NetworkConnection& conn) {
                return conn.discovered_at < cutoff_time;
            }),
        topology_map_.connections.end()
    );
}

std::vector<NetworkDevice> TopologyPlugin::get_discovered_devices() const {
    return discovered_devices_;
}

PluginResult TopologyPlugin::map_device_connections(const std::vector<NetworkDevice>& devices) {
    // Update topology with provided devices
    for (const auto& device : devices) {
        TopologyNode node;
        node.device = device;
        node.node_type = classify_device_type(device);
        node.hierarchy_level = determine_hierarchy_level(node.node_type, node.connected_devices);
        node.last_seen = std::chrono::system_clock::now();
        node.is_reachable = device.is_online;

        topology_map_.nodes[device.id] = node;
    }

    build_connection_graph();

    std::map<std::string, std::string> result_data;
    result_data["devices_mapped"] = std::to_string(devices.size());

    return {
        true,
        "Device connections mapped for " + std::to_string(devices.size()) + " devices",
        result_data,
        {}, {}, {}, 0
    };
}

std::vector<NetworkDevice> TopologyPlugin::discover_via_snmp(const std::string& community) {
    // Simplified SNMP discovery simulation
    std::vector<NetworkDevice> devices;

    // In a real implementation, this would use SNMP libraries to discover devices
    // For demonstration, we'll create some example devices
    NetworkDevice router;
    router.id = "snmp_router_1";
    router.name = "Core-Router-1";
    router.hostname = "core-rtr-1.example.com";
    router.device_type = "cisco-ios";
    router.management_ip = "192.168.1.1";
    router.is_online = true;
    router.last_seen = std::chrono::system_clock::now();
    router.interfaces = {"GigabitEthernet0/0", "GigabitEthernet0/1", "Serial0/0"};

    devices.push_back(router);

    return devices;
}

std::vector<NetworkDevice> TopologyPlugin::discover_via_ping_sweep(const std::string& network_range) {
    // Simplified ping sweep simulation
    std::vector<NetworkDevice> devices;

    // In a real implementation, this would perform actual ping sweeps
    // For demonstration, we'll create example devices
    NetworkDevice switch1;
    switch1.id = "ping_switch_1";
    switch1.name = "Access-Switch-1";
    switch1.hostname = "access-sw-1.example.com";
    switch1.device_type = "cisco-switch";
    switch1.management_ip = "192.168.1.10";
    switch1.is_online = true;
    switch1.last_seen = std::chrono::system_clock::now();

    devices.push_back(switch1);

    return devices;
}

PluginResult TopologyPlugin::analyze_device(const NetworkDevice& device) {
    std::string device_type = classify_device_type(device);

    std::map<std::string, std::string> result_data;
    result_data["device_type"] = device_type;
    result_data["interfaces_count"] = std::to_string(device.interfaces.size());

    return {
        true,
        "Device analysis completed for " + device.name,
        result_data,
        {}, {}, {}, 0
    };
}

PluginResult TopologyPlugin::execute_command(const std::string& command,
                                           const std::map<std::string, std::string>& parameters) {
    if (command == "topology_diagram") {
        return generate_topology_diagram();
    }

    if (command == "discover_devices") {
        return discover_network_devices();
    }

    if (command == "topology_status") {
        std::map<std::string, std::string> result_data;
        result_data["total_devices"] = std::to_string(topology_map_.total_devices);
        result_data["active_connections"] = std::to_string(topology_map_.active_connections);
        result_data["subnets"] = std::to_string(topology_map_.subnets.size());

        return {true, "Topology status retrieved", result_data, {}, {}, {}, 0};
    }

    return {false, "Unknown command: " + command, {}, {}, {"Unknown command"}, {}, 0};
}

std::vector<std::string> TopologyPlugin::get_supported_commands() const {
    return {"topology_diagram", "discover_devices", "topology_status"};
}

std::map<std::string, std::string> TopologyPlugin::get_configuration_schema() const {
    return {
        {"device_timeout_minutes", "Timeout for device activity in minutes (default: 30)"},
        {"auto_discovery", "Enable automatic device discovery (default: true)"},
        {"passive_discovery", "Enable passive discovery from logs (default: true)"}
    };
}

std::string TopologyPlugin::get_status() const {
    if (!is_initialized_) return "not_initialized";
    if (!is_running_) return "stopped";
    return "running";
}

void TopologyPlugin::group_devices_by_subnet() {
    // Group network devices by their subnet/VLAN membership
    // This is a basic implementation that analyzes IP addresses

    for (const auto& [device_id, topology_node] : topology_map_.nodes) {
        const auto& device = topology_node.device;
        std::string subnet = extract_subnet_from_ip(device.management_ip);

        // Find or create subnet group
        NetworkSubnet* subnet_info = nullptr;
        for (auto& subnet_entry : topology_map_.subnets) {
            if (subnet_entry.network_address == subnet) {
                subnet_info = &subnet_entry;
                break;
            }
        }

        if (!subnet_info) {
            NetworkSubnet new_subnet;
            new_subnet.network_address = subnet;
            new_subnet.prefix_length = 24; // Default /24 assumption
            new_subnet.vlan_id = "0"; // Default VLAN
            topology_map_.subnets.push_back(new_subnet);
            subnet_info = &topology_map_.subnets.back();
        }

        // Add device to subnet if not already present
        bool device_exists = false;
        for (const auto& existing_device_id : subnet_info->devices) {
            if (existing_device_id == device.name) {
                device_exists = true;
                break;
            }
        }

        if (!device_exists) {
            subnet_info->devices.push_back(device.name);
        }
    }
}

std::string TopologyPlugin::extract_subnet_from_ip(const std::string& ip_address) {
    // Simple subnet extraction - assumes /24 networks
    size_t last_dot = ip_address.find_last_of('.');
    if (last_dot != std::string::npos) {
        return ip_address.substr(0, last_dot) + ".0";
    }
    return ip_address; // Return as-is if parsing fails
}

} // namespace netlogai::plugins::examples

// Plugin export macros
NETLOGAI_PLUGIN_CREATE(netlogai::plugins::examples::TopologyPlugin)
NETLOGAI_PLUGIN_DESTROY()