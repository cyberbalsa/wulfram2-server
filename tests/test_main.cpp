#include <exception>
#include <iostream>
#include <string>

struct TestFailure : std::exception {
    explicit TestFailure(std::string message) : message_(std::move(message)) {}
    const char* what() const noexcept override { return message_.c_str(); }
    std::string message_;
};

[[maybe_unused]] inline void Expect(bool condition, const char* message) {
    if (!condition) throw TestFailure(message);
}

int main() {
    int failures = 0;
    // Tests are registered below in later tasks.
    std::cout << "wfh_tests: " << failures << " failures\n";
    return failures == 0 ? 0 : 1;
}
