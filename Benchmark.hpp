#pragma once

#include <string>
#include <vector>

namespace quantum_shield {

struct BenchmarkResult {
    double keygen_ms;
    double server_encap_ms;
    double client_decap_ms;
};

class Benchmark {
public:
    void Run(int iterations, const std::string& output_file);
    
private:
    void SaveResults(const std::vector<BenchmarkResult>& results, const std::string& filename);
};

} // namespace quantum_shield
