#pragma once

#include "plugin_interface.hpp"
#include <memory>
#include <unordered_map>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <queue>

// Forward declarations
#include <nlohmann/json_fwd.hpp>

namespace netlogai::plugins {

// Plugin security and sandboxing
class PluginSandbox {
public:
    struct SecurityPolicy {
        bool allow_file_system_access = false;
        bool allow_network_access = false;
        bool allow_system_calls = false;
        std::vector<std::string> allowed_directories;
        std::vector<std::string> allowed_network_hosts;
        uint32_t max_memory_mb = 64;
        uint32_t max_execution_time_ms = 30000;
        uint32_t max_file_size_mb = 10;
    };

    PluginSandbox(const SecurityPolicy& policy);
    ~PluginSandbox();

    bool initialize();
    bool apply_restrictions();
    bool monitor_resource_usage();
    void terminate_if_exceeded();

private:
    SecurityPolicy policy_;
    std::atomic<bool> monitoring_active_;
    std::thread monitor_thread_;
    std::atomic<uint32_t> current_memory_usage_;
    std::chrono::steady_clock::time_point start_time_;
};

// Plugin loader for dynamic libraries
class PluginLoader {
public:
    struct LoadedPlugin {
        std::string path;
        void* handle;
        PluginManifest manifest;
        CreatePluginFunc create_func;
        DestroyPluginFunc destroy_func;
        std::unique_ptr<INetLogAIPlugin> instance;
        std::chrono::system_clock::time_point loaded_at;
        bool is_active;
    };

    PluginLoader();
    ~PluginLoader();

    bool load_plugin(const std::string& plugin_path);
    bool unload_plugin(const std::string& plugin_id);
    bool reload_plugin(const std::string& plugin_id);

    std::vector<std::string> scan_plugin_directory(const std::string& directory);
    bool validate_plugin_manifest(const std::string& manifest_path);
    PluginManifest parse_plugin_manifest(const std::string& manifest_path);

    LoadedPlugin* get_loaded_plugin(const std::string& plugin_id);
    std::vector<LoadedPlugin*> get_all_loaded_plugins();
    std::vector<LoadedPlugin*> get_plugins_by_type(PluginType type);

private:
    std::unordered_map<std::string, std::unique_ptr<LoadedPlugin>> loaded_plugins_;
    std::mutex loader_mutex_;

    void* load_dynamic_library(const std::string& path);
    void unload_dynamic_library(void* handle);
    bool extract_plugin_functions(void* handle, CreatePluginFunc& create, DestroyPluginFunc& destroy);

    // Manifest validation helpers
    bool validate_manifest_schema(const nlohmann::json& manifest_json);
    bool validate_parsed_manifest(const PluginManifest& manifest);
    bool validate_version_format(const std::string& version);
    bool validate_plugin_name(const std::string& name);
};

// Plugin execution environment with resource monitoring
class PluginExecutionEnvironment {
public:
    struct ExecutionStats {
        std::chrono::milliseconds total_execution_time{0};
        uint32_t total_memory_used_mb = 0;
        uint32_t successful_executions = 0;
        uint32_t failed_executions = 0;
        std::chrono::system_clock::time_point last_execution;
        std::vector<std::string> recent_errors;
    };

    PluginExecutionEnvironment(const PluginContext& context);
    ~PluginExecutionEnvironment();

    PluginResult execute_plugin_method(INetLogAIPlugin* plugin,
                                     const std::function<PluginResult()>& method);

    bool is_plugin_healthy(const std::string& plugin_id) const;
    ExecutionStats get_execution_stats(const std::string& plugin_id) const;
    void reset_stats(const std::string& plugin_id);

private:
    PluginContext context_;
    std::unordered_map<std::string, ExecutionStats> execution_stats_;
    std::unique_ptr<PluginSandbox> sandbox_;
    std::mutex stats_mutex_;

    void update_stats(const std::string& plugin_id, const PluginResult& result);
    bool check_resource_limits(const std::string& plugin_id) const;
};

// Main plugin manager
class PluginManager {
public:
    struct PluginConfig {
        bool auto_load_plugins = true;
        bool enable_sandbox = true;
        bool enable_hot_reload = false;
        std::vector<std::string> plugin_directories = {"plugins", "third-party/plugins"};
        PluginSandbox::SecurityPolicy default_security_policy;
        uint32_t max_concurrent_plugins = 10;
    };

    PluginManager();
    ~PluginManager();

    bool initialize(const PluginConfig& config);
    void shutdown();

    // Plugin lifecycle management
    bool load_plugin(const std::string& plugin_path);
    bool unload_plugin(const std::string& plugin_id);
    bool reload_plugin(const std::string& plugin_id);
    bool enable_plugin(const std::string& plugin_id);
    bool disable_plugin(const std::string& plugin_id);

    // Plugin discovery and loading
    bool scan_and_load_plugins();
    bool auto_discover_plugins();
    std::vector<std::string> get_available_plugins() const;
    std::vector<std::string> get_loaded_plugins() const;
    std::vector<std::string> get_active_plugins() const;

    // Plugin execution
    std::vector<PluginResult> execute_on_log_entries(const std::vector<LogEntry>& entries,
                                                   PluginType plugin_type = PluginType::CUSTOM);
    PluginResult execute_plugin_command(const std::string& plugin_id,
                                      const std::string& command,
                                      const std::map<std::string, std::string>& parameters);

    // Real-time processing
    void start_real_time_processing();
    void stop_real_time_processing();
    void queue_real_time_entry(const LogEntry& entry);

    // Plugin information and management
    PluginManifest get_plugin_info(const std::string& plugin_id) const;
    std::string get_plugin_status(const std::string& plugin_id) const;
    std::vector<std::string> get_plugin_capabilities(const std::string& plugin_id) const;

    // Configuration management
    bool configure_plugin(const std::string& plugin_id,
                         const std::map<std::string, std::string>& config);
    std::map<std::string, std::string> get_plugin_config(const std::string& plugin_id) const;

    // Event handling
    using PluginEventHandler = std::function<void(const std::string& plugin_id,
                                                 const std::string& event,
                                                 const std::map<std::string, std::string>& data)>;
    void set_event_handler(PluginEventHandler handler);

private:
    PluginConfig config_;
    std::unique_ptr<PluginLoader> loader_;
    std::unordered_map<std::string, std::unique_ptr<PluginExecutionEnvironment>> environments_;

    // Real-time processing
    std::atomic<bool> real_time_active_;
    std::thread real_time_thread_;
    std::queue<LogEntry> real_time_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;

    // Event handling
    PluginEventHandler event_handler_;
    std::mutex manager_mutex_;

    void real_time_processing_loop();
    void process_real_time_entry(const LogEntry& entry);
    void emit_event(const std::string& plugin_id, const std::string& event,
                   const std::map<std::string, std::string>& data = {});

    bool validate_plugin_compatibility(const PluginManifest& manifest) const;
    PluginContext create_plugin_context(const std::string& plugin_id) const;
};

// Plugin registry for managing plugin metadata
class PluginRegistry {
public:
    struct RegistryEntry {
        PluginManifest manifest;
        std::string file_path;
        std::string checksum;
        bool is_verified;
        bool is_enabled;
        std::chrono::system_clock::time_point registered_at;
        std::chrono::system_clock::time_point last_updated;
    };

    PluginRegistry();
    ~PluginRegistry();

    bool register_plugin(const std::string& plugin_path);
    bool unregister_plugin(const std::string& plugin_id);
    bool update_plugin_info(const std::string& plugin_id, const PluginManifest& manifest);

    std::vector<RegistryEntry> get_all_entries() const;
    RegistryEntry* get_entry(const std::string& plugin_id);
    std::vector<RegistryEntry> search_plugins(const std::string& query) const;

    bool save_registry(const std::string& file_path) const;
    bool load_registry(const std::string& file_path);

private:
    std::unordered_map<std::string, RegistryEntry> registry_;
    std::mutex registry_mutex_;

    std::string calculate_file_checksum(const std::string& file_path) const;
    bool verify_plugin_signature(const std::string& plugin_path) const;
};

} // namespace netlogai::plugins