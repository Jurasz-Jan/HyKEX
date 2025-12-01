#include "Benchmark.hpp"
#include "HybridKeyExchange.hpp"
#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>

namespace quantum_shield {

using Clock = std::chrono::high_resolution_clock;

void Benchmark::Run(int iterations, const std::string& output_file) {
    std::cout << "Running Benchmark (" << iterations << " iterations)..." << std::endl;
    
    std::vector<BenchmarkResult> results;
    results.reserve(iterations);

    for (int i = 0; i < iterations; ++i) {
        HybridKeyExchange client;
        HybridKeyExchange server;
        BenchmarkResult res;

        // 1. Client KeyGen
        auto t1 = Clock::now();
        bool success = client.GenerateScatteredKeys();
        auto t2 = Clock::now();
        res.keygen_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
        
        if (!success) {
            std::cerr << "Benchmark KeyGen failed" << std::endl;
            continue;
        }

        ClientHello ch = client.GenerateClientHello();

        // 2. Server Processing (Encap + Derive)
        auto t3 = Clock::now();
        auto sh_opt = server.ProcessClientHello(ch);
        auto t4 = Clock::now();
        res.server_encap_ms = std::chrono::duration<double, std::milli>(t4 - t3).count();

        if (!sh_opt) {
            std::cerr << "Benchmark Server Encap failed" << std::endl;
            continue;
        }

        // 3. Client Processing (Decap + Derive)
        auto t5 = Clock::now();
        bool decap_success = client.ProcessServerHello(sh_opt.value());
        auto t6 = Clock::now();
        res.client_decap_ms = std::chrono::duration<double, std::milli>(t6 - t5).count();

        if (!decap_success) {
            std::cerr << "Benchmark Client Decap failed" << std::endl;
            continue;
        }

        results.push_back(res);
        
        if (i % 10 == 0) {
            std::cout << "." << std::flush;
        }
    }
    std::cout << std::endl;

    SaveResults(results, output_file);
    std::cout << "Results saved to " << output_file << std::endl;
}

void Benchmark::SaveResults(const std::vector<BenchmarkResult>& results, const std::string& filename) {
    std::ofstream csv(filename);
    csv << "keygen_ms,server_encap_ms,client_decap_ms\n";
    
    for (const auto& r : results) {
        csv << r.keygen_ms << "," 
            << r.server_encap_ms << "," 
            << r.client_decap_ms << "\n";
    }
}

} // namespace quantum_shield
