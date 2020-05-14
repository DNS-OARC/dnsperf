#!/bin/sh

clang-format \
    -style=file \
    -i \
    src/*.c \
    src/*.h
