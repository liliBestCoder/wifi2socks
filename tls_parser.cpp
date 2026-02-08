#include "tls_parser.h"
#include <vector>
#include <algorithm>
#include <cstring>

// Optimized SNI Parser
std::string parse_tls_sni(const uint8_t* data, size_t len) {
    if (len < 5) return "";
    if (data[0] != 0x16) return ""; // ContentType: Handshake
    
    size_t pos = 5; // Skip Record Header
    
    // Handshake Header: Type(1) + Length(3)
    if (pos + 4 > len) return "";
    if (data[pos] != 0x01) return ""; // Handshake Type: ClientHello
    
    pos += 4; // Skip Handshake Header

    // ClientHello Body
    // Protocol Version (2) + Random (32) = 34
    if (pos + 34 > len) return "";
    pos += 34;

    // Session ID
    if (pos + 1 > len) return "";
    uint8_t session_id_len = data[pos];
    pos += 1;
    if (pos + session_id_len > len) return "";
    pos += session_id_len;

    // Cipher Suites
    if (pos + 2 > len) return "";
    uint16_t cipher_len = (data[pos] << 8) | data[pos+1];
    pos += 2;
    if (pos + cipher_len > len) return "";
    pos += cipher_len;

    // Compression Methods
    if (pos + 1 > len) return "";
    uint8_t comp_len = data[pos];
    pos += 1;
    if (pos + comp_len > len) return "";
    pos += comp_len;

    // Extensions
    if (pos + 2 > len) return "";
    uint16_t ext_len = (data[pos] << 8) | data[pos+1];
    pos += 2;
    
    size_t ext_end = pos + ext_len;
    if (ext_end > len) ext_end = len;

    while (pos + 4 <= ext_end) {
        uint16_t etype = (data[pos] << 8) | data[pos+1];
        uint16_t elen = (data[pos+2] << 8) | data[pos+3];
        pos += 4;

        if (etype == 0x0000) { // server_name extension
            if (pos + 2 > ext_end) break;
            uint16_t list_len = (data[pos] << 8) | data[pos+1];
            pos += 2;
            
            size_t list_end = pos + list_len;
            if (list_end > ext_end) list_end = ext_end;

            while (pos + 3 <= list_end) {
                uint8_t name_type = data[pos];
                uint16_t name_len = (data[pos+1] << 8) | data[pos+2];
                pos += 3;
                
                if (name_type == 0) { // host_name
                    if (pos + name_len <= list_end) {
                        return std::string((const char*)(data + pos), name_len);
                    }
                }
                pos += name_len;
            }
            break; 
        }
        pos += elen;
    }
    return "";
}

bool is_http_start(const uint8_t* data, size_t len) {
    if (len < 4) return false;
    // Check methods (Basic checks)
    if (len >= 4 && memcmp(data, "GET ", 4) == 0) return true;
    if (len >= 5 && memcmp(data, "POST ", 5) == 0) return true;
    if (len >= 5 && memcmp(data, "HEAD ", 5) == 0) return true;
    if (len >= 4 && memcmp(data, "PUT ", 4) == 0) return true;
    if (len >= 7 && memcmp(data, "DELETE ", 7) == 0) return true;
    if (len >= 8 && memcmp(data, "CONNECT ", 8) == 0) return true;
    if (len >= 8 && memcmp(data, "OPTIONS ", 8) == 0) return true;
    if (len >= 6 && memcmp(data, "TRACE ", 6) == 0) return true;
    if (len >= 6 && memcmp(data, "PATCH ", 6) == 0) return true;
    return false;
}

std::string parse_http_host(const uint8_t* data, size_t len) {
    if (!is_http_start(data, len)) return "";
    
    std::string s((const char*)data, (std::min)((size_t)len, (size_t)4096)); // Limit scan
    
    // Case-insensitive search helper
    auto find_case_insensitive = [](const std::string& haystack, const std::string& needle, size_t pos) -> size_t {
        auto it = std::search(
            haystack.begin() + pos, haystack.end(),
            needle.begin(), needle.end(),
            [](char a, char b) { return std::tolower(a) == std::tolower(b); }
        );
        if (it == haystack.end()) return std::string::npos;
        return it - haystack.begin();
    };

    size_t pos = 0;
    while (pos < s.length()) {
        size_t line_end = s.find('\n', pos);
        if (line_end == std::string::npos) break;
        
        // Check this line for "Host:"
        // We look for "Host:" at the start of the line (headers start at beginning of line)
        // But s contains the whole request, so 'pos' is the start of the current line.
        
        size_t colon = s.find(':', pos);
        if (colon != std::string::npos && colon < line_end) {
            std::string key = s.substr(pos, colon - pos);
            
            // Trim trailing whitespace from key (e.g. "Host :")
            size_t key_last = key.find_last_not_of(" \t");
            if (key_last != std::string::npos) {
                key = key.substr(0, key_last + 1);
            }

            if (key.length() == 4 && (key[0] == 'H' || key[0] == 'h') && 
                                     (key[1] == 'o' || key[1] == 'O') &&
                                     (key[2] == 's' || key[2] == 'S') && 
                                     (key[3] == 't' || key[3] == 'T')) {
                
                // Found Host
                std::string val = s.substr(colon + 1, line_end - (colon + 1));
                // Trim whitespace and \r
                size_t first = val.find_first_not_of(" \t");
                if (first == std::string::npos) return ""; // Empty host
                
                size_t last = val.find_last_not_of(" \t\r");
                if (last == std::string::npos || last < first) return "";
                
                return val.substr(first, last - first + 1);
            }
        }
        
        pos = line_end + 1;
        
        // Double \n or \r\n means end of headers
        if (pos < s.length()) {
             if (s[pos] == '\r' || s[pos] == '\n') break; 
        }
    }
    return "";
}