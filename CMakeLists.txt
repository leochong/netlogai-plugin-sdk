cmake_minimum_required(VERSION 3.16)
project(netlogai-plugin-sdk
    VERSION 1.0.0
    DESCRIPTION "NetLogAI Plugin Development Framework"
    LANGUAGES CXX
)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler-specific options
if(MSVC)
    add_compile_options(/W4)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Build options
option(PLUGIN_SDK_BUILD_TESTS "Build unit tests" ON)
option(PLUGIN_SDK_BUILD_EXAMPLES "Build example plugins" ON)
option(PLUGIN_SDK_BUILD_TOOLS "Build development tools" ON)
option(PLUGIN_SDK_BUILD_DOCS "Build documentation" OFF)

# Find dependencies
find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    include(FetchContent)
    FetchContent_Declare(json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    )
    FetchContent_MakeAvailable(json)
endif()

# Optional dependencies
find_package(spdlog QUIET)
if(spdlog_FOUND)
    add_compile_definitions(PLUGIN_SDK_ENABLE_LOGGING=1)
endif()

# Include directories
include_directories(include)

# Plugin SDK core library
set(PLUGIN_SDK_SOURCES
    src/plugin_manager.cpp
    src/plugin_loader.cpp
    src/plugin_registry.cpp
    src/plugin_interface.cpp
    src/security/plugin_sandbox.cpp
    src/security/permission_manager.cpp
    src/utils/plugin_config.cpp
    src/utils/plugin_logger.cpp
    src/utils/plugin_database.cpp
    src/validation/plugin_validator.cpp
    src/validation/api_validator.cpp
)

set(PLUGIN_SDK_HEADERS
    include/netlogai/plugin_sdk.hpp
    include/netlogai/plugin_interface.hpp
    include/netlogai/plugin_types.hpp
    include/netlogai/plugin_manager.hpp
    include/netlogai/plugin_config.hpp
    include/netlogai/security_plugin.hpp
    include/netlogai/performance_plugin.hpp
    include/netlogai/topology_plugin.hpp
    include/netlogai/integration_plugin.hpp
    include/netlogai/plugin_test_framework.hpp
    include/netlogai/utils/plugin_logger.hpp
    include/netlogai/utils/plugin_database.hpp
    include/netlogai/validation/plugin_validator.hpp
    include/netlogai/security/plugin_sandbox.hpp
)

# Create the main SDK library
add_library(plugin-sdk STATIC
    ${PLUGIN_SDK_SOURCES}
    ${PLUGIN_SDK_HEADERS}
)

# Set library properties
set_target_properties(plugin-sdk PROPERTIES
    OUTPUT_NAME "netlogai-plugin-sdk"
    VERSION ${PROJECT_VERSION}
)

# Link libraries
target_link_libraries(plugin-sdk
    PUBLIC
    nlohmann_json::nlohmann_json
)

if(spdlog_FOUND)
    target_link_libraries(plugin-sdk PRIVATE spdlog::spdlog)
endif()

# Include directories for consumers
target_include_directories(plugin-sdk
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Platform-specific settings
if(WIN32)
    target_compile_definitions(plugin-sdk PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(plugin-sdk PRIVATE ws2_32)
endif()

if(UNIX)
    target_link_libraries(plugin-sdk PRIVATE dl pthread)
endif()

# Compile definitions
target_compile_definitions(plugin-sdk
    PRIVATE
    PLUGIN_SDK_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    PLUGIN_SDK_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    PLUGIN_SDK_VERSION_PATCH=${PROJECT_VERSION_PATCH}
)

# Debug configuration
target_compile_definitions(plugin-sdk PRIVATE
    $<$<CONFIG:Debug>:PLUGIN_SDK_DEBUG=1>
    $<$<CONFIG:Debug>:PLUGIN_SDK_ENABLE_VERBOSE_LOGGING=1>
)

# Build development tools
if(PLUGIN_SDK_BUILD_TOOLS)
    add_subdirectory(tools)
endif()

# Build example plugins
if(PLUGIN_SDK_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Build tests
if(PLUGIN_SDK_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Build documentation
if(PLUGIN_SDK_BUILD_DOCS)
    find_package(Doxygen QUIET)
    if(DOXYGEN_FOUND)
        add_subdirectory(docs)
    else()
        message(WARNING "Doxygen not found - documentation will not be built")
    endif()
endif()

# Plugin template system
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/templates/plugin_template.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/templates/plugin_template.hpp"
    @ONLY
)

# Install rules
include(GNUInstallDirs)

install(TARGETS plugin-sdk
    EXPORT plugin-sdk-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp"
)

install(DIRECTORY templates/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/netlogai/plugin-sdk/templates
    FILES_MATCHING PATTERN "*"
)

install(PROGRAMS tools/create-plugin.sh tools/validate-plugin.sh
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES README.md LICENSE
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
)

# Export targets
install(EXPORT plugin-sdk-targets
    FILE plugin-sdk-targets.cmake
    NAMESPACE netlogai::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/plugin-sdk
)

# Create config files
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/plugin-sdk-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/plugin-sdk-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/plugin-sdk-config.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/plugin-sdk
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/plugin-sdk-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/plugin-sdk-config-version.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/plugin-sdk
)

# Plugin macros and utilities
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/PluginMacros.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/PluginMacros.cmake"
    COPYONLY
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/PluginMacros.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/plugin-sdk
)

# CPack configuration
set(CPACK_PACKAGE_NAME "netlogai-plugin-sdk")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_VENDOR "NetLogAI Contributors")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")

if(WIN32)
    set(CPACK_GENERATOR "ZIP")
else()
    set(CPACK_GENERATOR "TGZ;DEB")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "NetLogAI Contributors")
endif()

include(CPack)

# Print configuration summary
message(STATUS "")
message(STATUS "NetLogAI Plugin SDK ${PROJECT_VERSION} Configuration Summary:")
message(STATUS "  C++ Standard: C++${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Build Tests: ${PLUGIN_SDK_BUILD_TESTS}")
message(STATUS "  Build Examples: ${PLUGIN_SDK_BUILD_EXAMPLES}")
message(STATUS "  Build Tools: ${PLUGIN_SDK_BUILD_TOOLS}")
message(STATUS "  Build Documentation: ${PLUGIN_SDK_BUILD_DOCS}")
message(STATUS "  Logging Support: ${spdlog_FOUND}")
message(STATUS "  Install Prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")