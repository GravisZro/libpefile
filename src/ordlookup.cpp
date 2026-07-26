#include "ordlookup.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace pefile::ordlookup
{
  bool iequals(std::string_view a, std::string_view b)
  {
    if (a.size() != b.size())
      return false;
    for (size_t i = 0; i < a.size(); i++)
      if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
        return false;
    return true;
  }

  const OrdinalMap oleaut32_ords =
  {
    {2, "SysAllocString"},
    {3, "SysAllocStringLen"},
    {4, "SysFreeString"},
    {5, "SysStringLen"},
    {6, "VariantInit"},
    {7, "VariantClear"},
    {8, "VariantCopy"},
    {9, "VariantChangeType"},
    {10, "VariantTimeToDosDateTime"},
    {11, "DosDateTimeToVariantTime"},
    {12, "SystemTimeToVariantTime"},
    {13, "VariantTimeToSystemTime"},
    {14, "SystemTimeToTzSpecificLocalTime"},
    {15, "TzSpecificLocalTimeToSystemTime"},
    {16, "VariantTimeToSystemTime"},
    {17, "LoadTypeLib"},
    {18, "LoadRegTypeLib"},
    {19, "RegisterTypeLib"},
    {20, "UnRegisterTypeLib"},
    {21, "RegisterTypeLibForUser"},
    {22, "UnRegisterTypeLibForUser"},
    {24, "OaBuildVersion"},
    {25, "ClearCustData"},
    {26, "GetRecordInfoFromTypeInfo"},
    {27, "GetRecordInfoFromGuids"},
    {28, "OaEnablePerUserTlbRegistration"},
    {29, "CreateTypeLib"},
    {30, "LoadTypeLib"},
    {31, "LoadRegTypeLib"},
    {32, "RegisterTypeLib"},
    {33, "UnRegisterTypeLib"},
    {34, "CreateTypeLib2"},
    {35, "LoadTypeLibEx"},
    {36, "LHashValOfNameSys"},
    {37, "LHashValOfNameSysA"},
    {38, "LoadTypeLib"},
    {39, "LoadTypeLib"},
    {40, "LoadTypeLib"},
    {41, "LoadTypeLib"},
    {42, "LoadTypeLib"},
    {43, "LoadTypeLib"},
    {44, "LoadTypeLib"},
    {45, "LoadTypeLib"},
    {46, "LoadTypeLib"},
    {47, "LoadTypeLib"},
    {48, "LoadTypeLib"},
    {49, "LoadTypeLib"},
    {50, "LoadTypeLib"},
  };

  const OrdinalMap ws2_32_ords =
  {
    {1, "accept"},
    {2, "bind"},
    {3, "closesocket"},
    {4, "connect"},
    {5, "getpeername"},
    {6, "getsockname"},
    {7, "getsockopt"},
    {8, "htonl"},
    {9, "htons"},
    {10, "ioctlsocket"},
    {11, "inet_addr"},
    {12, "inet_ntoa"},
    {13, "listen"},
    {14, "ntohl"},
    {15, "ntohs"},
    {16, "recv"},
    {17, "recvfrom"},
    {18, "select"},
    {19, "send"},
    {20, "sendto"},
    {21, "setsockopt"},
    {22, "shutdown"},
    {23, "socket"},
    {24, "GetAddrInfoW"},
    {25, "GetAddrInfo"},
    {26, "GetHostname"},
    {27, "GetHostNameW"},
    {31, "WSACleanup"},
    {32, "WSAGetLastError"},
    {33, "WSASetLastError"},
    {34, "WSAStartup"},
    {51, "WSAHtonl"},
    {52, "WSAHtons"},
    {53, "WSARecv"},
    {54, "WSASend"},
    {55, "WSASocketA"},
    {56, "WSASocketW"},
    {57, "WSAEventSelect"},
    {58, "WSAEnumNetworkEvents"},
    {60, "WSAEnumProtocolsA"},
    {61, "WSAEnumProtocolsW"},
    {62, "WSAGetOverlappedResult"},
    {63, "WSAGetQOSByName"},
    {64, "WSAInstallServiceClassA"},
    {65, "WSAInstallServiceClassW"},
    {66, "WSAIoctl"},
    {67, "WSAJoinLeaf"},
    {68, "WSALookupServiceBeginA"},
    {69, "WSALookupServiceBeginW"},
    {70, "WSALookupServiceEnd"},
    {71, "WSALookupServiceNextA"},
    {72, "WSALookupServiceNextW"},
    {73, "WSANSPIoctl"},
    {74, "WSANtohl"},
    {75, "WSANtohs"},
    {76, "WSAProviderConfigChange"},
    {77, "WSARecvDisconnect"},
    {78, "WSARecvFrom"},
    {79, "WSARecvMsg"},
    {80, "WSARemoveServiceClass"},
    {81, "WSAResetAddress"},
    {82, "WSASendDisconnect"},
    {83, "WSASendMsg"},
    {84, "WSASendTo"},
    {85, "WSASetServiceA"},
    {86, "WSASetServiceW"},
    {87, "WSASocketA"},
    {88, "WSASocketW"},
    {89, "WSAAsyncSelect"},
    {90, "WSACancelAsyncRequest"},
    {91, "WSACancelBlockingCall"},
    {92, "WSACloseEvent"},
    {93, "WSACreateEvent"},
    {94, "WSADuplicateSocketA"},
    {95, "WSADuplicateSocketW"},
    {97, "WSAEnumOrdering"},
    {101, "WSAGetLastError"},
    {102, "WSAGetLastError"},
    {103, "WSAGetLastError"},
    {104, "WSAGetLastError"},
    {105, "WSAGetLastError"},
    {106, "WSAGetLastError"},
    {107, "WSAGetLastError"},
    {108, "WSAGetLastError"},
    {109, "WSAGetLastError"},
    {110, "WSAGetLastError"},
    {111, "WSAGetLastError"},
    {112, "WSAGetLastError"},
    {113, "WSAGetLastError"},
    {114, "WSAGetLastError"},
    {115, "WSAGetLastError"},
    {116, "WSAGetLastError"},
    {117, "WSAGetLastError"},
    {151, "WSARecvEx"},
    {152, "WSAGetLastError"},
    {500, "WSARecvEx"},
    {510, "WSARecvEx"},
    {1001, "WSASend"},
    {1002, "WSARecv"},
    {1100, "WSASend"},
    {1101, "WSARecv"},
  };

  const OrdinalMap wsock32_ords =
  {
    {1, "accept"},
    {2, "bind"},
    {3, "closesocket"},
    {4, "connect"},
    {5, "getpeername"},
    {6, "getsockname"},
    {7, "getsockopt"},
    {8, "htonl"},
    {9, "htons"},
    {10, "ioctlsocket"},
    {11, "inet_addr"},
    {12, "inet_ntoa"},
    {13, "listen"},
    {14, "ntohl"},
    {15, "ntohs"},
    {16, "recv"},
    {17, "recvfrom"},
    {18, "select"},
    {19, "send"},
    {20, "sendto"},
    {21, "setsockopt"},
    {22, "shutdown"},
    {23, "socket"},
    {51, "WSAAsyncSelect"},
    {52, "WSACancelBlockingCall"},
    {53, "WSACancelAsyncRequest"},
    {54, "WSAGetLastError"},
    {55, "WSASetLastError"},
    {56, "WSAUnhookBlockingHook"},
    {57, "WSASetBlockingHook"},
    {58, "WSACloseEvent"},
    {59, "WSACreateEvent"},
    {60, "WSAResetAddress"},
    {61, "WSAResetAddress"},
    {62, "WSAResetAddress"},
    {63, "WSAResetAddress"},
    {64, "WSAResetAddress"},
    {65, "WSAResetAddress"},
    {101, "WSAEventSelect"},
    {102, "WSAEnumNetworkEvents"},
    {103, "WSAGetOverlappedResult"},
    {104, "WSAGetQOSByName"},
    {105, "WSARecv"},
    {106, "WSARecvFrom"},
    {107, "WSASend"},
    {108, "WSASendTo"},
    {110, "WSASocketA"},
    {111, "WSASocketW"},
    {112, "WSADuplicateSocketA"},
    {113, "WSADuplicateSocketW"},
    {114, "WSACleanup"},
    {115, "WSAStartup"},
    {116, "WSARecvEx"},
  };

  const OrdinalMap imphash_wsock32_ords =
  {
    {1, "accept"},
    {2, "bind"},
    {3, "closesocket"},
    {4, "connect"},
    {5, "getpeername"},
    {6, "getsockname"},
    {7, "getsockopt"},
    {8, "htonl"},
    {9, "htons"},
    {10, "ioctlsocket"},
    {11, "inet_addr"},
    {12, "inet_ntoa"},
    {13, "listen"},
    {14, "ntohl"},
    {15, "ntohs"},
    {16, "recv"},
    {17, "recvfrom"},
    {18, "select"},
    {19, "send"},
    {20, "sendto"},
    {21, "setsockopt"},
    {22, "shutdown"},
    {23, "socket"},
    {51, "WSAAsyncSelect"},
    {52, "WSACancelBlockingCall"},
    {53, "WSACancelAsyncRequest"},
    {54, "WSAGetLastError"},
    {55, "WSASetLastError"},
    {56, "WSAUnhookBlockingHook"},
    {57, "WSASetBlockingHook"},
    {58, "WSACloseEvent"},
    {59, "WSACreateEvent"},
    {101, "WSAEventSelect"},
    {102, "WSAEnumNetworkEvents"},
    {103, "WSAGetOverlappedResult"},
    {104, "WSAGetQOSByName"},
    {105, "WSARecv"},
    {106, "WSARecvFrom"},
    {107, "WSASend"},
    {108, "WSASendTo"},
    {110, "WSASocketA"},
    {111, "WSASocketW"},
    {112, "WSADuplicateSocketA"},
    {113, "WSADuplicateSocketW"},
    {114, "WSACleanup"},
    {115, "WSAStartup"},
    {116, "WSARecvEx"},
  };

  const OrdinalMap imphash_oleaut32_ords =
  {
    {2, "SysAllocString"},
    {3, "SysAllocStringLen"},
    {4, "SysFreeString"},
    {5, "SysStringLen"},
    {6, "VariantInit"},
    {7, "VariantClear"},
    {8, "VariantCopy"},
    {9, "VariantChangeType"},
    {10, "VariantTimeToDosDateTime"},
    {11, "DosDateTimeToVariantTime"},
    {12, "SystemTimeToVariantTime"},
    {13, "VariantTimeToSystemTime"},
    {14, "SystemTimeToTzSpecificLocalTime"},
    {15, "TzSpecificLocalTimeToSystemTime"},
    {16, "VariantTimeToSystemTime"},
    {17, "LoadTypeLib"},
    {18, "LoadRegTypeLib"},
    {19, "RegisterTypeLib"},
    {20, "UnRegisterTypeLib"},
    {21, "RegisterTypeLibForUser"},
    {22, "UnRegisterTypeLibForUser"},
    {24, "OaBuildVersion"},
    {25, "ClearCustData"},
    {26, "GetRecordInfoFromTypeInfo"},
    {27, "GetRecordInfoFromGuids"},
    {28, "OaEnablePerUserTlbRegistration"},
  };

  const OrdinalMap imphash_ws2_32_ords =
  {
    {1, "accept"},
    {2, "bind"},
    {3, "closesocket"},
    {4, "connect"},
    {5, "getpeername"},
    {6, "getsockname"},
    {7, "getsockopt"},
    {8, "htonl"},
    {9, "htons"},
    {10, "ioctlsocket"},
    {11, "inet_addr"},
    {12, "inet_ntoa"},
    {13, "listen"},
    {14, "ntohl"},
    {15, "ntohs"},
    {16, "recv"},
    {17, "recvfrom"},
    {18, "select"},
    {19, "send"},
    {20, "sendto"},
    {21, "setsockopt"},
    {22, "shutdown"},
    {23, "socket"},
    {24, "GetAddrInfoW"},
    {25, "GetAddrInfo"},
    {26, "GetHostname"},
    {27, "GetHostNameW"},
    {31, "WSACleanup"},
    {32, "WSAGetLastError"},
    {33, "WSASetLastError"},
    {34, "WSAStartup"},
    {51, "WSAHtonl"},
    {52, "WSAHtons"},
    {53, "WSARecv"},
    {54, "WSASend"},
    {55, "WSASocketA"},
    {56, "WSASocketW"},
    {57, "WSAEventSelect"},
    {58, "WSAEnumNetworkEvents"},
    {60, "WSAEnumProtocolsA"},
    {61, "WSAEnumProtocolsW"},
    {62, "WSAGetOverlappedResult"},
    {63, "WSAGetQOSByName"},
    {64, "WSAInstallServiceClassA"},
    {65, "WSAInstallServiceClassW"},
    {66, "WSAIoctl"},
    {67, "WSAJoinLeaf"},
    {68, "WSALookupServiceBeginA"},
    {69, "WSALookupServiceBeginW"},
    {70, "WSALookupServiceEnd"},
    {71, "WSALookupServiceNextA"},
    {72, "WSALookupServiceNextW"},
    {73, "WSANSPIoctl"},
    {74, "WSANtohl"},
    {75, "WSANtohs"},
    {76, "WSAProviderConfigChange"},
    {77, "WSARecvDisconnect"},
    {78, "WSARecvFrom"},
    {79, "WSARecvMsg"},
    {80, "WSARemoveServiceClass"},
    {81, "WSAResetAddress"},
    {82, "WSASendDisconnect"},
    {83, "WSASendMsg"},
    {84, "WSASendTo"},
    {85, "WSASetServiceA"},
    {86, "WSASetServiceW"},
    {87, "WSASocketA"},
    {88, "WSASocketW"},
    {89, "WSAAsyncSelect"},
    {90, "WSACancelAsyncRequest"},
    {91, "WSACancelBlockingCall"},
    {92, "WSACloseEvent"},
    {93, "WSACreateEvent"},
    {94, "WSADuplicateSocketA"},
    {95, "WSADuplicateSocketW"},
    {97, "WSAEnumOrdering"},
  };

  struct ImdLookupEntry
  {
    std::string_view dll;
    const OrdinalMap& table;
  };

  struct ImdLookupEntryImpHash
  {
    std::string_view dll;
    const OrdinalMap& table;
  };

  const OrdinalMap& lookup_table(std::string_view dll_name)
  {
    static const OrdinalMap empty;
    static const std::pair<std::string_view, const OrdinalMap&> tables[] =
    {
      {"oleaut32.dll", oleaut32_ords},
      {"ws2_32.dll", ws2_32_ords},
      {"wsock32.dll", wsock32_ords},
    };
    for (auto& [name, table] : tables)
    {
      if (iequals(name, dll_name))
        return table;
    }
    return empty;
  }

  const OrdinalMap& imphash_lookup_table(std::string_view dll_name)
  {
    static const OrdinalMap empty;
    static const std::pair<std::string_view, const OrdinalMap&> tables[] =
    {
      {"oleaut32.dll", imphash_oleaut32_ords},
      {"ws2_32.dll", imphash_ws2_32_ords},
      {"wsock32.dll", imphash_wsock32_ords},
    };
    for (auto& [name, table] : tables)
    {
      if (iequals(name, dll_name))
        return table;
    }
    return empty;
  }


  const OrdinalMap& get_ordinals(std::string_view dll_name)
    { return lookup_table(dll_name); }

  const OrdinalMap& get_imphash_ordinals(std::string_view dll_name)
    { return imphash_lookup_table(dll_name); }

  std::string ordinal_lookup(std::string_view dll_name, uint16_t ordinal, bool make_name)
  {
    auto& table = lookup_table(dll_name);
    auto it = table.find(ordinal);
    if (it != table.end())
      return it->second;
    if (make_name)
      return "ord" + std::to_string(ordinal);
    return "";
  }

  std::string imphash_ordinal_lookup(std::string_view dll_name, uint16_t ordinal, bool make_name)
  {
    auto& table = imphash_lookup_table(dll_name);
    auto it = table.find(ordinal);
    if (it != table.end())
      return it->second;
    if (make_name)
      return "ord" + std::to_string(ordinal);
    return "";
  }

} // namespace pefile::ordlookup
