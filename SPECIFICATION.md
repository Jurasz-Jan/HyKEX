Project Specification: Quantum-Shield 6G
Tytuł projektu
Quantum-Safe Hybrid Communication System (QSHCS) High-Performance C++ Implementation of Post-Quantum Cryptography for Next-Gen Networks

1. Executive Summary
Celem projektu jest stworzenie prototypu bezpiecznego kanału komunikacyjnego odpornego na ataki komputerów kwantowych (Post-Quantum Cryptography - PQC). System implementuje hybrydową wymianę kluczy (Hybrid Key Exchange), łączącą sprawdzoną kryptografię eliptyczną (ECC) z nowym standardem NIST – ML-KEM (Kyber).

Projekt adresuje zagrożenie typu "Harvest Now, Decrypt Later", krytyczne dla infrastruktury 5G/6G oraz urządzeń IoT o długim cyklu życia. Rozwiązanie kładzie nacisk na wydajność, bezpieczeństwo pamięci (Modern C++) oraz inżynierię protokołów sieciowych.

2. Architektura Systemu
2.1. Model Komunikacji
Architektura klient-serwer oparta na gniazdach TCP (Linux Sockets) z własnym protokołem warstwy aplikacji.

2.2. Kryptografia Hybrydowa (Strict Hybrid Scheme)
Bezpieczeństwo opiera się na zasadzie "najsłabszego ogniwa" – atakujący musi złamać zarówno algorytm klasyczny, jak i kwantowy, aby odczytać dane.

Warstwa Klasyczna: X25519 (Elliptic Curve Diffie-Hellman) – wysoka wydajność, małe klucze.

Warstwa Kwantowa: ML-KEM-768 (dawniej Kyber-768) – Security Level 3 (wg NIST), balans między bezpieczeństwem a rozmiarem szyfrogramu.

Funkcja Derywacji Klucza (KDF): HKDF-SHA256.

Nie używamy XOR. Klucz sesji jest wynikiem kryptograficznego zmieszania obu sekretów.

Wzór: Session_Key = HKDF(Salt, IKM = (SharedSecret_X25519 || SharedSecret_Kyber))

Szyfrowanie Transportu: AES-256-GCM (Galois/Counter Mode).

Zapewnia poufność (Confidentiality) oraz integralność (Integrity/Auth Tag).

3. Tech Stack & Wymagania
Core Engineering
Język: C++20 (Concepts, Spans, Smart Pointers, std::vector zamiast surowych tablic).

Build System: CMake (wersja 3.15+).

Package Manager: vcpkg lub Conan (do zarządzania zależnościami).

Biblioteki
Quantum Crypto: liboqs (Open Quantum Safe) – implementacja referencyjna algorytmów NIST.

Classic Crypto: OpenSSL (lub BoringSSL) – dla X25519, AES-GCM, SHA256.

Testing: Google Test (GTest) – testy jednostkowe modułów kryptograficznych.

DevOps & Tools
Konteneryzacja: Docker (wieloetapowy Dockerfile do budowania i uruchamiania).

Analiza: Python 3 + Matplotlib/Pandas (skrypty do benchmarkingu).

Analiza pamięci: Valgrind / AddressSanitizer (ASan).

4. Protokół Komunikacyjny (Handshake Specification)
Protokół binarny (nie tekstowy) zaprojektowany dla minimalizacji narzutu danych.

Faza 1: Client Hello
Klient inicjuje połączenie, wysyłając swoje klucze publiczne.

C++

struct ClientHello {
    uint8_t protocol_version;   // np. 0x01
    uint8_t cipher_suite;       // ID hybrydy (np. X25519_Kyber768)
    uint8_t pubkey_classic[32]; // X25519 Public Key
    uint8_t pubkey_quantum[1184]; // Kyber-768 Public Key
};
Faza 2: Server Hello & KEM
Serwer generuje swoją parę X25519, kapsułkuje sekret Kybera i odsyła dane.

C++

struct ServerHello {
    uint8_t status;             // 0x00 OK, 0xFF Error
    uint8_t pubkey_classic[32]; // X25519 Public Key (Server)
    uint8_t ciphertext_quantum[1088]; // Kyber Encapsulated Secret
    uint8_t auth_tag[16];       // Initial Handshake Integrity Tag
};
Faza 3: Secure Session
Obie strony obliczają ten sam Session_Key lokalnie. Od teraz każda wiadomość ma strukturę:

C++

struct SecureFrame {
    uint16_t payload_length;
    uint8_t iv[12];             // Initialization Vector dla GCM
    uint8_t auth_tag[16];       // GCM Tag
    uint8_t encrypted_data[];   // Payload
};
5. Plan Implementacji (Roadmap)
Krok 1: Environment Setup
Konfiguracja CMakeLists.txt z integracją vcpkg.

Stworzenie Dockerfile (bazującego na Ubuntu 22.04/24.04).

Cel: Kompilacja "Hello World" z linkowaniem do liboqs i openssl.

Krok 2: Crypto Engine (The "Brain")
Implementacja klasy HybridKeyExchange.

Metody: GenerateKeyPairs(), Encapsulate(), Decapsulate().

Implementacja HKDF do bezpiecznego łączenia sekretów.

Deliverable: Działające Unit Testy (GTest) sprawdzające, czy Klient i Serwer uzgadniają identyczny klucz.

Krok 3: Networking Layer
Implementacja klas TcpServer i TcpClient (RAII, obsługa wyjątków, setsockopt).

Obsługa protokołu binarnego (serializacja/deserializacja struktur).

Zastosowanie asynchroniczności lub wielowątkowości (std::thread) do obsługi klienta.

Krok 4: Secure Transport
Integracja HybridKeyExchange z warstwą sieciową.

Implementacja szyfrowania AES-GCM dla przesyłanych wiadomości.

Demo: Przesłanie pliku binarnego (np. obrazka) przez bezpieczny kanał.

Krok 5: Performance Benchmarking
Instrumentacja kodu (pomiar czasu w µs dla: KeyGen, Encap, Decap).

Porównanie narzutu rozmiaru pakietów (Klasyczne ECDH vs Hybryda).

Wygenerowanie raportu wydajności (Wykresy Python).

6. Kryteria Sukcesu (Definition of Done)
Poprawność kryptograficzna: Wygenerowany klucz sesji jest identyczny po obu stronach.

Bezpieczeństwo pamięci: Brak wycieków pamięci (potwierdzone przez Valgrind/ASan).

Odporność: Serwer nie crashuje się przy błędnych danych od klienta.

Reprodukowalność: Projekt buduje się jedną komendą w Dockerze.
