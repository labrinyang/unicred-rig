// Apple Metal entry point; build instructions are in README.md.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#define UNICRED_METAL 1
#define main miner_main
#include "miner.cu"
#undef main

int main(int argc, char **argv) {
  @autoreleasepool {
    return miner_main(argc, argv);
  }
}
