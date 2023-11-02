#include "app.h"

int main(int argc, char* argv[]) {
    static App app;
    return app.exec(argc, argv);
}