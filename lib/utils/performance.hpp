#pragma once
#include <string>
#include <chrono>

namespace performance {
    struct time_sp {
        explicit time_sp() : time_sp("") {}

        explicit time_sp(const std::string& msg) :_msg(msg) {
            _start = std::chrono::steady_clock::now();
        }
        ~time_sp() {
            auto end = std::chrono::steady_clock::now();
            std::chrono::duration<double> dur = end - _start;
            if (!_msg.empty()) {
                printf("%s ", _msg.c_str());
            }
            printf("spent: %lf s\n", dur.count());
        }
        std::chrono::time_point<std::chrono::steady_clock> _start;
        std::string _msg;
    };
}