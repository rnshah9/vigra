FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake

COPY . /repo
WORKDIR /repo/build
RUN cmake .. -DVIGRA_STATIC_LIB=1
RUN make -j8
RUN make -j8 examples
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y clang
RUN clang++ /repo/mayhem/fuzz_trimString.cpp -fsanitize=fuzzer,address -L /repo/build/src/impex/ -lvigraimpex -o /fuzz

FROM ubuntu:22.04 as package

COPY --from=builder /repo/build/src/impex/libvigraimpex* /deps/
COPY --from=builder /repo/build/src/examples/example_invert /repo/build/src/examples/example_invert
ENV LD_LIBRARY_PATH=/deps
COPY --from=builder /fuzz /fuzz_trimString
