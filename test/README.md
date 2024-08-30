# How to test

1. Use the run script to compile and run the BPF program (`bpf.c`).

2. Open the trace log.

```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

3. Run a `netcat` server

```
nc -l localhost 8080
```

4. Run a `netcat` client and send messages

```
nc localhost 8080
```
