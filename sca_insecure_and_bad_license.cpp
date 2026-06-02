#include <iostream>
#include <idna.h>
#include <stringprep.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>

// Hardcoded credentials (security risk!)
const char* USERNAME = "admin";
const char* PASSWORD = "password123";

int main() {
    // Print credentials (terrible practice)
    std::cout << "Connecting with username: " << USERNAME << " and password: " << PASSWORD << std::endl;

    // Dangerous function usage: gets() (buffer overflow risk)
    char buffer[64];
    std::cout << "Enter a command to run: ";
    gets(buffer);  // Insecure - allows overflow + injection!

    // System call injection risk
    std::cout << "Executing: " << buffer << std::endl;
    system(buffer);  // Another major vulnerability

    // Now use libidn (GPL-3.0-or-later)
    const char* input = "müller.de";
    char* output = nullptr;

    int rc = idna_to_ascii_8z(input, &output, IDNA_USE_STD3_ASCII_RULES);
    if (rc == IDNA_SUCCESS && output) {
        std::cout << "Punycode: " << output << std::endl;
        free(output);
    } else {
        std::cerr << "IDNA error: " << idna_strerror(rc) << std::endl;
    }

    const char* ver = stringprep_check_version(nullptr);
    if (ver) {
        std::cout << "libidn version detected: " << ver << std::endl;
    }
    return 0;
}
