#pragma once

#include "plugins/plugin_interface.hpp"
#include <unordered_map>
#include <unordered_set>
#include <queue>

namespace netlogai::plugins::examples {

class TopologyPlugin : public ITopologyPlugin {
public:
    TopologyPlugin();
    virtual ~TopologyPlugin() = default;

    // INetLogAIPlugin interface
    std::string get_name() const override { return "NetLogAI Topology Plugin"; }
    std::string get_version() const override { return "1.0.0"; }
    std::string get_description() const override { return "Network topology discovery and mapping"; }
    std::string get_author() const override { return "NetLogAI Team"; }
    std::string get_api_version() const override { return NETLOGAI_PLUGIN_API_VERSION; }
    PluginCapability get_capabilities() const override;

    bool initialize(const PluginContext& context) override;
    bool configure(const std::map<std::string, std::string>& config) override;
    bool start() override;
    bool stop() override;
    void cleanup() override;

    PluginResult process_log_entries(const std::vector<LogEntry>& entries) override;
    PluginResult analyze_device(const NetworkDevice& device) override;
    PluginResult execute_command(const std::string& command,
                               const std::map<std::string, std::string>& parameters) override;

    // ITopologyPlugin interface
    PluginResult discover_network_devices() override;
    PluginResult map_device_connections(const std::vector<NetworkDevice>& devices) override;
    PluginResult generate_topology_diagram() override;
    std::vector<NetworkDevice> get_discovered_devices() const override;

    // Additional methods
    std::vector<std::string> get_supported_commands() const override;
    std::map<std::string, std::string> get_configuration_schema() const override;
    std::string get_status() const override;

private:
    struct NetworkConnection {
        std::string source_device;
        std::string source_interface;
        std::string destination_device;
        std::string destination_interface;
        std::string connection_type; // "direct", "switch", "router", "unknown"
        std::string protocol; // "CDP", "LLDP", "OSPF", "BGP", "ARP"
        std::chrono::system_clock::time_point discovered_at;
        bool is_active;
        uint32_t cost; // Routing cost/metric
        std::map<std::string, std::string> properties;
    };

    struct TopologyNode {
        NetworkDevice device;
        std::vector<std::string> connected_devices;
        std::map<std::string, std::string> neighbor_interfaces;
        std::string node_type; // "router", "switch", "host", "firewall", "load_balancer"
        uint32_t hierarchy_level; // 0=core, 1=distribution, 2=access, 3=host
        std::chrono::system_clock::time_point last_seen;
        bool is_reachable;
    };

    struct NetworkSubnet {
        std::string network_address;
        uint32_t prefix_length;
        std::vector<std::string> devices;
        std::string vlan_id;
        std::string description;
        bool is_management_network;
    };

    struct RoutingEntry {
        std::string destination_network;
        std::string next_hop;
        std::string interface;
        uint32_t metric;
        std::string protocol;
        std::string source_device;
        std::chrono::system_clock::time_point learned_at;
    };

    struct TopologyMap {
        std::unordered_map<std::string, TopologyNode> nodes;
        std::vector<NetworkConnection> connections;
        std::vector<NetworkSubnet> subnets;
        std::vector<RoutingEntry> routing_table;
        std::chrono::system_clock::time_point last_updated;
        uint32_t total_devices;
        uint32_t active_connections;
    };

    // Configuration
    bool is_initialized_;
    bool is_running_;
    PluginContext context_;
    std::map<std::string, std::string> config_;

    // Topology data
    TopologyMap topology_map_;
    std::vector<NetworkDevice> discovered_devices_;
    std::unordered_map<std::string, std::chrono::system_clock::time_point> device_last_seen_;

    // Discovery configuration
    std::vector<std::string> discovery_protocols_;
    std::vector<std::string> scan_ranges_;
    std::chrono::minutes device_timeout_;
    bool auto_discovery_enabled_;
    bool passive_discovery_enabled_;

    // Helper methods for protocol parsing
    void parse_cdp_neighbor(const LogEntry& entry);
    void parse_lldp_neighbor(const LogEntry& entry);
    void parse_ospf_neighbor(const LogEntry& entry);
    void parse_bgp_neighbor(const LogEntry& entry);
    void parse_arp_entry(const LogEntry& entry);
    void parse_routing_table(const LogEntry& entry);
    void parse_interface_status(const LogEntry& entry);

    // Discovery methods
    std::vector<NetworkDevice> discover_via_snmp(const std::string& community);
    std::vector<NetworkDevice> discover_via_ping_sweep(const std::string& network_range);
    std::vector<NetworkDevice> discover_via_logs(const std::vector<LogEntry>& entries);

    // Connection mapping
    void build_connection_graph();
    void determine_device_hierarchy();
    void group_devices_by_subnet();
    NetworkConnection create_connection(const std::string& source_device,
                                       const std::string& source_interface,
                                       const std::string& dest_device,
                                       const std::string& dest_interface,
                                       const std::string& protocol);

    // Device classification
    std::string classify_device_type(const NetworkDevice& device) const;
    uint32_t determine_hierarchy_level(const std::string& device_type,
                                     const std::vector<std::string>& connections) const;
    bool is_core_device(const NetworkDevice& device) const;

    // Topology analysis
    std::vector<std::string> find_path_between_devices(const std::string& source,
                                                     const std::string& destination) const;
    std::vector<std::string> find_redundant_paths(const std::string& source,
                                                 const std::string& destination) const;
    std::vector<NetworkConnection> find_single_points_of_failure() const;

    // Diagram generation
    std::string generate_ascii_topology() const;
    std::string generate_graphviz_topology() const;
    std::string generate_mermaid_topology() const;
    std::string format_node_label(const TopologyNode& node) const;
    std::string format_connection_label(const NetworkConnection& connection) const;

    // Helper functions
    std::string extract_subnet_from_ip(const std::string& ip_address);

    // Maintenance
    void cleanup_stale_devices();
    void cleanup_stale_connections();
    void update_device_status();

    // Utility methods
    std::string extract_ip_address(const std::string& text) const;
    std::string extract_interface_name(const std::string& text) const;
    std::string normalize_device_name(const std::string& name) const;
    bool is_valid_ip_address(const std::string& ip) const;
    std::string calculate_network_address(const std::string& ip, uint32_t prefix_length) const;
};

} // namespace netlogai::plugins::examples