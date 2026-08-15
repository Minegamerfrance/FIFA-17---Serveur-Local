/**
 * ORIGIN_VERSION_FIX only — FIFA17.exe+0x717d6a6
 * When EAX == 0xa2000003 (TXT_ORIGIN_GAME_VERSION_OUT_OF_DATE path), force EAX=0.
 * No AuthSetup poke, no AuthCode/Login/GoOnline inject.
 */
"use strict";

const DO_FIX =
  typeof __DO_ORIGIN_VERSION_FIX__ !== "undefined"
    ? !!__DO_ORIGIN_VERSION_FIX__
    : true;
const GATE_RVA = 0x717d6a6;
const AUTH_SETUP_RESULT_RVA = 0x717d692; // obs only

function mod() {
  const m = Process.findModuleByName("FIFA17.exe");
  if (!m) throw new Error("FIFA17.exe not found");
  return m;
}

function arm() {
  const base = mod().base;
  const gate = base.add(GATE_RVA);
  let hits = 0;
  let applied = 0;

  // OBS only: non-zero EAX here skips VERSION_GATE (known third-party path).
  try {
    Interceptor.attach(base.add(AUTH_SETUP_RESULT_RVA), {
      onEnter: function () {
        const eax = this.context.rax.toInt32() >>> 0;
        console.log(
          "[origin-ver] ORIGIN_AUTH_SETUP_RESULT eax=0x" +
            eax.toString(16) +
            " (obs only, no poke)",
        );
      },
    });
  } catch (e) {
    console.log("[origin-ver] AUTH_SETUP obs FAIL " + e);
  }

  try {
    Interceptor.attach(gate, {
      onEnter: function () {
        hits++;
        const retWas = this.context.rax.toInt32() >>> 0;
        console.log(
          "[origin-ver] ORIGIN_VERSION_GATE HIT #" +
            hits +
            " retWas=0x" +
            retWas.toString(16) +
            " fix=" +
            (DO_FIX ? 1 : 0),
        );
        if (DO_FIX && retWas === 0xa2000003) {
          this.context.rax = ptr(0);
          applied++;
          console.log(
            "[origin-ver] ORIGIN_VERSION_FIX applied=1 retWas=0xa2000003 retNow=0 n=" +
              applied,
          );
        }
      },
    });
    console.log(
      "[origin-ver] ORIGIN_VERSION_GATE hooked @" +
        gate +
        " rva=0x" +
        GATE_RVA.toString(16) +
        " FIX=" +
        (DO_FIX ? 1 : 0),
    );
  } catch (e) {
    console.log("[origin-ver] ORIGIN_VERSION_GATE hook FAIL " + e);
  }
}

setImmediate(arm);
