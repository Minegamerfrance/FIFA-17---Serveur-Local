# Recherche SSL FIFA 17 ? findings (2026-07-25)

## SUCCESS: The SSL Bypass is Complete!

After extensive dynamic analysis and iterative patching, we have successfully bypassed the SSL certificate validation in FIFA 17's ProtoSSL implementation.

### The Problem: `FAIL_9` (`0x1009`)
FIFA 17 uses a custom implementation of EA's DirtySDK `ProtoSSL`. When connecting to our custom server, the game would successfully parse the certificate but then abruptly terminate the connection with a `FAIL_9` error.

This error was triggered because, despite setting the `bAllowAnyCert` flag and spoofing the hostname, a secondary validation check (likely a strict CA chain or hostname verification deep within the state machine) was still failing.

### The Solution: State Machine Manipulation (v73-FINAL)

The breakthrough came from understanding how the `FAIL_9` state was being applied. The error was dispatched through a jump-table stub located at `0x1461326fa`.

The original code at this stub was:
```assembly
mov eax, 0x1009  ; Load FAIL_9 state code
jmp error_handler ; Jump to common state-update function
```

Instead of trying to find and patch every single validation check that could lead to this stub, we neutralized the error at the stub itself. We patched the instruction to load `0x15` (which is `21` in decimal, the enum value for `ST_RECV_HELLO`) instead of `0x1009`.

**The Patch:**
```assembly
; Patch at 0x1461326fa
mov eax, 0x15    ; Load ST_RECV_HELLO state code
jmp error_handler ; Jump to common state-update function
```

**Why this works:**
When the validation failed, the code jumped to our patched stub. The stub told the state machine to transition to state `21` (`RECV_HELLO`). Since the connection was *already* in the `RECV_HELLO` state (waiting for the `ServerHelloDone` message), this effectively acted as a no-op for the state machine. 

The game ignored the validation failure, naturally continued to wait for `ServerHelloDone`, processed it, and then transitioned through all the remaining handshake states successfully:
1. `RECV_HELLO` (21)
2. `SEND_CKE` (23) - ClientKeyExchange sent!
3. `SEND_FINISH` (24) - ChangeCipherSpec and Finished sent!
4. `SECURE` (30) - Handshake complete!

Once in the `SECURE` state, the game began sending encrypted application data.

### Supporting Patches
To ensure complete stability, this state-machine manipulation was combined with two `je -> jmp` patches to ignore error codes returned by earlier certificate parsing functions:
- `je -> jmp` at `0x612f39c`
- `je -> jmp` at `0x61261eb`

### Conclusion
By neutralizing the `FAIL_9` error at its dispatch stub and forcing the state machine to remain in `RECV_HELLO`, we achieved a flawless, crash-free SSL bypass that allows the game to complete the handshake with our custom server.