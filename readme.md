# SHARKSCRIPT

SharkScript is a high-performance domain-specific language and virtual machine engineered for real-time packet analysis, system orchestration, and low-latency automation. It is designed for environments where microsecond-level execution is a hard requirement.

Detailed documentation is available at: https://larping.today/docs.html

## TECHNICAL PILLARS

### SHARK01 BYTECODE ENGINE
The compiler translates .shark source into a serialized instruction tree (LIGMA02 specification). The Virtual Machine utilizes an O(1) jump table dispatcher, bypassing the performance overhead found in traditional switch-case or map-lookup based interpreters.

### MULTI-CORE PARALLELISM
High-throughput tasks leverage the parallel execution engine. By generating thread-local memory snapshots, the VM enables lock-free concurrency across all available CPU cores, preventing RWMutex contention bottlenecks during heavy iteration cycles.

### AOT TRANSPILLATION
For maximum performance, SharkScript supports Ahead-of-Time compilation. This process transpiles script logic into native Go source, which is then compiled into a stripped, standalone binary. This removes the VM layer entirely and allows for zero-overhead execution.

### MEMORY OPTIMIZATION
The math and string expansion engines are built on a zero-allocation philosophy. By utilizing sync.Pool for buffer management and pre-calculating static templates during the "bake" phase, the runtime significantly reduces Garbage Collector pressure.

## CLI USAGE

### BYTECODE COMPILATION
Generate an optimized .shx bytecode file from source.
```bash
shs compile script.shark
```

### VIRTUAL MACHINE EXECUTION
Run the SharkScript VM against a compiled bytecode file.
```bash
shs run script.shx
```

### NATIVE BINARY GENERATION (AOT)
Generate a standalone native binary for a specific target operating system.
```bash
shs aot script.shark -os linux
```

## ARCHITECTURE VERIFICATION

The following benchmark demonstrates the parallel engine capability by executing one million iterations.

```plaintext
TIME start

PARALLEL LOOP 1000000
  # Multi-core iterations occur here
ENDLOOP

TIME end
SET duration = %end% - %start%

PRINT Benchmark: 1,000,000 iterations processed in %duration%ms
```

For a comprehensive list of opcodes, built-in symbols, and hardware interaction primitives, see the language specification in the docs.

## SETUP

```bash
chmod +x setup.sh
./setup.sh
```
