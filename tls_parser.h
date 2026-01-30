#pragma once
#include <string>
#include <cstdint>
#include <vector>

std::string parse_tls_sni(const uint8_t* data, size_t len);
