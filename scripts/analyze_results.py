import pandas as pd
import matplotlib.pyplot as plt
import sys
import os

def analyze(input_file="benchmark_results.csv", output_image="results/benchmark_report.png"):
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found")
        return

    print(f"Analyzing {input_file}...")
    df = pd.read_csv(input_file)
    
    # Calculate stats
    stats = df.describe()
    print(stats)
    
    # Plot
    plt.figure(figsize=(10, 6))
    
    # Box plot for distribution
    plt.boxplot([df['keygen_ms'], df['server_encap_ms'], df['client_decap_ms']], 
                labels=['Client KeyGen', 'Server Encap', 'Client Decap'])
    
    plt.title('Post-Quantum Hybrid Key Exchange Latency (X25519 + ML-KEM-768)')
    plt.ylabel('Time (ms)')
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Save
    os.makedirs(os.path.dirname(output_image), exist_ok=True)
    plt.savefig(output_image)
    print(f"Plot saved to {output_image}")

    # Also save as textual report
    with open("results/report.txt", "w") as f:
        f.write("Quantum-Shield 6G Performance Report\n")
        f.write("====================================\n\n")
        f.write(str(stats))

if __name__ == "__main__":
    analyze()
