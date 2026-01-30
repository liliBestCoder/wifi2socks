#include "tls_parser.h"

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
