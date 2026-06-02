/*
  PURPOSE: Intentionally insecure C++ file for SCA testing.
  WARNING: Do NOT use this in production. It contains deliberate security flaws.

  Third-party components included:

  1) GNU libidn — Internationalized Domain Names processing
     SPDX-License-Identifier: GPL-3.0-or-later
     Homepage: https://www.gnu.org/software/libidn/
     License text: https://www.gnu.org/licenses/gpl-3.0-standalone.html

  2) libcurl — Client-side URL transfers
     SPDX-License-Identifier: curl
     Homepage: https://curl.se/libcurl/
     License text: https://curl.se/docs/copyright.html
*/

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <ctime>

// Third-party OSS includes (with licenses noted above)
#include <curl/curl.h>      // libcurl (SPDX: curl)
#include <idna.h>           // GNU libidn (SPDX: GPL-3.0-or-later)
#include <stringprep.h>

// Optional OpenSSL MD5 (commented out by default)
// Requires: libssl-dev
// #include <openssl/md5.h>

// Hardcoded credentials (bad practice)
static const char* DB_USERNAME = "admin";
static const char* DB_PASSWORD = "password123";

// Global secret key in code (bad practice)
static const char* GLOBAL_API_TOKEN = "sk_live_ThisIsNotARealToken_ButStillBad";

// Insecure PRNG-based "key" (bad practice)
std::string generateWeakApiKey(size_t length = 32) {
    std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string key;
    key.reserve(length);
    // Seeding with time() (predictable) — insecure
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
    for (size_t i = 0; i < length; ++i) {
        key.push_back(chars[std::rand() % chars.size()]);
    }
    return key;
}

// Insecure buffer handling (overflow risk)
void insecureBufferCopy(const char* userInput) {
    char buf[64]; // too small for long inputs
    // No bounds checking — overflow risk
    std::strcpy(buf, userInput);
    std::cout << "[insecureBufferCopy] Copied: " << buf << std::endl;
}

// Insecure path handling: naive join enables traversal
void insecurePathJoinAndWrite(const std::string& userPath, const std::string& data) {
    std::string base = "./data/";
    // No validation of userPath — enables ../../etc/passwd patterns
    std::string full = base + userPath;
    std::ofstream ofs(full.c_str(), std::ios::binary);
    if (!ofs) {
        std::cerr << "[insecurePathJoinAndWrite] Failed to open: " << full << std::endl;
        return;
    }
    ofs << data;
    std::cout << "[insecurePathJoinAndWrite] Wrote to: " << full << std::endl;
}

// Insecure temporary file usage: mktemp is unsafe (race condition)
void insecureTempFileWrite(const std::string& content) {
    char tmpl[] = "/tmp/insecureXXXXXX";
    // mktemp returns a potentially guessable filename — TOCTOU risk
    char* path = mktemp(tmpl);
    if (!path) {
        std::cerr << "[insecureTempFileWrite] mktemp failed" << std::endl;
        return;
    }
    FILE* f = std::fopen(path, "w+"); // No O_EXCL; raceable
    if (!f) {
        std::cerr << "[insecureTempFileWrite] fopen failed: " << path << std::endl;
        return;
    }
    std::fwrite(content.data(), 1, content.size(), f);
    std::fclose(f);
    std::cout << "[insecureTempFileWrite] Wrote temp file: " << path << std::endl;
}

// Command execution with user-controlled input — command injection risk
void insecureSystemExec(const std::string& cmd) {
    std::cout << "[insecureSystemExec] Executing: " << cmd << std::endl;
    // No sanitization; executes arbitrary commands — dangerous
    std::system(cmd.c_str());
}

// libcurl write callback
static size_t curlWriteToString(void* ptr, size_t size, size_t nmemb, void* userdata) {
    size_t total = size * nmemb;
    std::string* s = static_cast<std::string*>(userdata);
    s->append(static_cast<char*>(ptr), total);
    return total;
}

// Insecure HTTPS fetch: disables certificate and host verification
void insecureHttpsFetch(const std::string& url) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "[insecureHttpsFetch] curl_easy_init failed" << std::endl;
        return;
    }
    std::string body;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    // Intentionally insecure settings:
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // disable CA validation
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); // disable hostname verification

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteToString);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);

    CURLcode rc = curl_easy_perform(curl);
    if (rc == CURLE_OK) {
        std::cout << "[insecureHttpsFetch] Body size: " << body.size() << " bytes" << std::endl;
    } else {
        std::cerr << "[insecureHttpsFetch] curl error: " << curl_easy_strerror(rc) << std::endl;
    }
    curl_easy_cleanup(curl);
}

// Weak hash usage example (MD5) — cryptographically broken
// Uncomment if OpenSSL headers are available.
// std::string md5Hex(const std::string& data) {
//     unsigned char digest[16];
//     MD5(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);
//     static const char hex[] = "0123456789abcdef";
//     std::string out;
//     out.reserve(32);
//     for (int i = 0; i < 16; ++i) {
//         out.push_back(hex[(digest[i] >> 4) & 0xF]);
//         out.push_back(hex[digest[i] & 0xF]);
//     }
//     return out;
// }

// GNU libidn usage — also provides a 3rd-party include for license scanning
void idnPunycodeExample(const std::string& domainUtf8) {
    char* output = nullptr;
    int rc = idna_to_ascii_8z(domainUtf8.c_str(), &output, IDNA_USE_STD3_ASCII_RULES);
    if (rc == IDNA_SUCCESS && output) {
        std::cout << "[idnPunycodeExample] " << domainUtf8 << " -> " << output << std::endl;
        free(output);
    } else {
        std::cerr << "[idnPunycodeExample] IDNA error: " << idna_strerror(rc) << std::endl;
    }
    const char* ver = stringprep_check_version(nullptr);
    if (ver) {
        std::cout << "[idnPunycodeExample] libidn version: " << ver << std::endl;
    }
}

int main(int argc, char** argv) {
    std::cout << "==== Insecure Demo App (for SCA testing) ====" << std::endl;

    // Print hardcoded secrets — terrible practice
    std::cout << "[secrets] DB_USERNAME=" << DB_USERNAME
              << " DB_PASSWORD=" << DB_PASSWORD << std::endl;
    std::cout << "[secrets] GLOBAL_API_TOKEN=" << GLOBAL_API_TOKEN << std::endl;

    // Insecure key generation
    std::string weakKey = generateWeakApiKey();
    std::cout << "[weakKey] Generated (insecure) API key: " << weakKey << std::endl;

    // Insecure buffer copy from argv
    if (argc > 1) {
        insecureBufferCopy(argv[1]); // overflow if argv[1] > 63 chars
    } else {
        insecureBufferCopy("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    }

    // Insecure path join and write (possible traversal)
    std::string userPath = (argc > 2) ? argv[2] : "../out.txt";
    insecurePathJoinAndWrite(userPath, "This is test data written insecurely.\n");

    // Insecure temporary file usage
    insecureTempFileWrite("Sensitive temp content\n");

    // Insecure command execution
    std::string cmd = (argc > 3) ? argv[3] : "ls -la";
    insecureSystemExec(cmd);

    // Insecure HTTPS fetch with disabled verification
    std::string url = (argc > 4) ? argv[4] : "https://expired.badssl.com/";
    insecureHttpsFetch(url);

    // Weak hashing example (requires OpenSSL headers/libs)
    // std::string md5 = md5Hex("SensitiveValue");
    // std::cout << "[weakHash] MD5 of SensitiveValue: " << md5 << std::endl;

    // GNU libidn example — third-party include for license detection
    idnPunycodeExample("müller.de");

    std::cout << "==== Done ====" << std::endl;
    return 0;
}
