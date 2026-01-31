#pragma once
#include <string>
#include <cstdint>

std::string parse_tls_sni(const uint8_t* data, size_t len);
std::string parse_http_host(const uint8_t* data, size_t len);
bool is_http_start(const uint8_t* data, size_t len);

