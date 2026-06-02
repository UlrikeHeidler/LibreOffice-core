#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <curl/curl.h>
#include <idna.h>
#include <stringprep.h>

static const char* DB_USERNAME = "admin";
static const char* DB_PASSWORD = "password456";
static const char* GLOBAL_API_TOKEN = "sk_live_ThisIsNotARealToken_ButStillBad";

std::string generateWeakApiKey(size_t length = 32) {
    std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string key;
    key.reserve(length);
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
    for (size_t i = 0; i < length; ++i) key.push_back(chars[std::rand() % chars.size()]);
    return key;
}

void insecureBufferCopy(const char* userInput) {
    char buf[64];
    std::strcpy(buf, userInput);
    std::cout << buf << std::endl;
}

void insecurePathJoinAndWrite(const std::string& userPath, const std::string& data) {
    std::string full = "./data/" + userPath;
    std::ofstream ofs(full.c_str(), std::ios::binary);
    if (!ofs) return;
    ofs << data;
}

void insecureTempFileWrite(const std::string& content) {
    char tmpl[] = "/tmp/insecureXXXXXX";
    char* path = mktemp(tmpl);
    if (!path) return;
    FILE* f = std::fopen(path, "w+");
    if (!f) return;
    std::fwrite(content.data(), 1, content.size(), f);
    std::fclose(f);
}

void insecureSystemExec(const std::string& cmd) {
    std::system(cmd.c_str());
}

static size_t curlWriteToString(void* ptr, size_t size, size_t nmemb, void* userdata) {
    size_t total = size * nmemb;
    std::string* s = static_cast<std::string*>(userdata);
    s->append(static_cast<char*>(ptr), total);
    return total;
}

void insecureHttpsFetch(const std::string& url) {
    CURL* curl = curl_easy_init();
    if (!curl) return;
    std::string body;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteToString);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
}

void idnPunycodeExample(const std::string& domainUtf8) {
    char* output = nullptr;
    int rc = idna_to_ascii_8z(domainUtf8.c_str(), &output, IDNA_USE_STD3_ASCII_RULES);
    if (rc == IDNA_SUCCESS && output) {
        std::cout << domainUtf8 << " -> " << output << std::endl;
        free(output);
    }
    stringprep_check_version(nullptr);
}

int main(int argc, char** argv) {
    std::cout << DB_USERNAME << " : " << DB_PASSWORD << std::endl;
    std::cout << GLOBAL_API_TOKEN << std::endl;
    std::cout << generateWeakApiKey() << std::endl;

    if (argc > 1) insecureBufferCopy(argv[1]); else insecureBufferCopy("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    std::string userPath = (argc > 2) ? argv[2] : "../out.txt";
    insecurePathJoinAndWrite(userPath, "test data\n");
    insecureTempFileWrite("temp content\n");
    std::string cmd = (argc > 3) ? argv[3] : "ls -la";
    insecureSystemExec(cmd);
    std::string url = (argc > 4) ? argv[4] : "https://expired.badssl.com/";
    insecureHttpsFetch(url);
    idnPunycodeExample("müller.de");
    return 0;
}
