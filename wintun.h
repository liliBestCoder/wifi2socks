#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* WINTUN_ADAPTER_HANDLE;
typedef void* WINTUN_SESSION_HANDLE;
typedef UINT64 WINTUN_LOGGER_CONTEXT;

typedef enum _WINTUN_LOGGER_LEVEL {
    WINTUN_LOG_INFO,
    WINTUN_LOG_WARN,
    WINTUN_LOG_ERR
} WINTUN_LOGGER_LEVEL;

typedef void(*WINTUN_LOGGER_CALLBACK)(
    _In_ WINTUN_LOGGER_LEVEL Level,
    _In_ UINT64 Timestamp,
    _In_z_ LPCWSTR Message
);

typedef void(WINAPI* WINTUN_GET_ADAPTER_LUID_FUNC)(
    _In_ WINTUN_ADAPTER_HANDLE Adapter,
    _Out_ LUID* Luid
);

typedef WINTUN_ADAPTER_HANDLE(WINAPI* WINTUN_CREATE_ADAPTER_FUNC)(
    _In_ LPCWSTR Name,
    _In_ LPCWSTR TunnelType,
    _In_opt_ const GUID* RequestedGUID
);

typedef WINTUN_ADAPTER_HANDLE(WINAPI* WINTUN_OPEN_ADAPTER_FUNC)(
    _In_ LPCWSTR Name
);

typedef void(WINAPI* WINTUN_CLOSE_ADAPTER_FUNC)(
    _In_ WINTUN_ADAPTER_HANDLE Adapter
);

typedef BOOL(WINAPI* WINTUN_DELETE_DRIVER_FUNC)(
    void
);

typedef WINTUN_SESSION_HANDLE(WINAPI* WINTUN_START_SESSION_FUNC)(
    _In_ WINTUN_ADAPTER_HANDLE Adapter,
    _In_ DWORD Capacity
);

typedef void(WINAPI* WINTUN_END_SESSION_FUNC)(
    _In_ WINTUN_SESSION_HANDLE Session
);

typedef HANDLE(WINAPI* WINTUN_GET_READ_WAIT_EVENT_FUNC)(
    _In_ WINTUN_SESSION_HANDLE Session
);

typedef BYTE*(WINAPI* WINTUN_ALLOCATE_SEND_PACKET_FUNC)(
    _In_ WINTUN_SESSION_HANDLE Session,
    _In_ DWORD PacketSize
);

typedef void(WINAPI* WINTUN_SEND_PACKET_FUNC)(
    _In_ WINTUN_SESSION_HANDLE Session,
    _In_ BYTE* Packet
);

typedef BYTE*(WINAPI* WINTUN_RECEIVE_PACKET_FUNC)(
    _In_ WINTUN_SESSION_HANDLE Session,
    _Out_ DWORD* PacketSize
);

typedef void(WINAPI* WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(
    _In_ WINTUN_SESSION_HANDLE Session,
    _In_ const BYTE* Packet
);

#ifdef __cplusplus
}
#endif
