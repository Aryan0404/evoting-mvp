import { useState } from "react";
import { View, Text, ScrollView, TouchableOpacity, Platform } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { fetchElection } from "../api/client";
import {
  encodeBallot, finishBallot, precompute, proofContext, publicParamsFromHex,
} from "../crypto/ballot";
import { newDeviceKey, packageBytes, publicKeyHex, signPackage } from "../crypto/device";
import { rootFromPath } from "../crypto/receipt";

/**
 * On-device timing for the paper (Section 5.8, device column): runs the exact
 * code the voter's phone runs, with the election's real 2048-bit key when the
 * server is reachable. Each figure is mean ± SD over the stated repetitions.
 */

// Fallback 2048-bit odd modulus (timing only) if the server is unreachable.
const FALLBACK_N =
  "c7f1b0f3a9d4e6b2" .repeat(32).slice(0, 511) + "b";

type Row = { label: string; values: number[] };

const fmt = (xs: number[]) => {
  if (!xs.length) return "—";
  const m = xs.reduce((a, b) => a + b, 0) / xs.length;
  const sd = Math.sqrt(xs.reduce((a, b) => a + (b - m) ** 2, 0) / Math.max(1, xs.length - 1));
  return `${m.toFixed(1)} ± ${sd.toFixed(1)} ms`;
};

export default function BenchmarkScreen() {
  const [rows, setRows] = useState<Row[]>([]);
  const [running, setRunning] = useState(false);
  const [note, setNote] = useState("");
  const [keySource, setKeySource] = useState("");

  async function run() {
    setRunning(true);
    setRows([]);
    const out: Row[] = [];
    const push = (r: Row) => { out.push(r); setRows([...out]); };
    try {
      let nHex = FALLBACK_N, electionId = "benchmark";
      try {
        const e = await fetchElection();
        nHex = e.public_n; electionId = e.election_id;
        setKeySource("election key from the server (2048-bit)");
      } catch {
        setKeySource("built-in 2048-bit test modulus (server unreachable; timing only)");
      }
      const pp = publicParamsFromHex(nHex);
      const REPS = 5;

      const keygen: number[] = [];
      let priv = "";
      for (let i = 0; i < 20; i++) { const t = Date.now(); priv = newDeviceKey(); publicKeyHex(priv); keygen.push(Date.now() - t); }
      push({ label: "Device key generation (P-256)", values: keygen });

      for (const k of [2, 5]) {
        const pre: number[] = [], online: number[] = [], sign: number[] = [];
        let bytes = 0;
        for (let i = 0; i < REPS; i++) {
          setNote(`k = ${k}: ballot ${i + 1}/${REPS}…`);
          const uti = "ab".repeat(32);
          let t = Date.now();
          const p = await precompute(pp, k);
          pre.push(Date.now() - t);
          t = Date.now();
          const { cts, proof } = finishBallot(pp, p, i % k, proofContext(electionId, uti));
          const enc = encodeBallot(cts, proof);
          online.push(Date.now() - t);
          bytes = enc.zkp_proof.length;
          t = Date.now();
          signPackage(priv, packageBytes(electionId, uti, k, enc.ciphertext, enc.zkp_proof, Date.now() / 1000));
          sign.push(Date.now() - t);
        }
        push({ label: `k = ${k}: precompute (while voter reads)`, values: pre });
        push({ label: `k = ${k}: finish proof after choice`, values: online });
        push({ label: `k = ${k}: total encrypt + prove`, values: pre.map((v, j) => v + online[j]) });
        push({ label: `k = ${k}: sign package (ECDSA)`, values: sign });
        push({ label: `k = ${k}: proof JSON size ${bytes.toLocaleString()} chars`, values: [] });
      }

      const path = Array.from({ length: 14 }, (_, i) => ({ side: (i % 2 ? "L" : "R") as "L" | "R", hash: "11".repeat(32) }));
      const rc: number[] = [];
      for (let i = 0; i < 50; i++) { const t = Date.now(); rootFromPath("22".repeat(32), path); rc.push(Date.now() - t); }
      push({ label: "Receipt check (14-hash Merkle path)", values: rc });
      setNote("Done.");
    } catch (e: any) {
      setNote(`Failed: ${e?.message ?? e}`);
    } finally {
      setRunning(false);
    }
  }

  const report = [
    `Device: ${Platform.OS} ${String(Platform.Version)}`,
    `Key: ${keySource}`,
    ...rows.map((r) => `${r.label}: ${fmt(r.values)}${r.values.length ? ` (n=${r.values.length})` : ""}`),
  ].join("\n");

  return (
    <SafeAreaView className="flex-1 bg-slate-900" edges={["bottom"]}>
      <ScrollView contentContainerStyle={{ padding: 24 }}>
        <Text className="text-white text-2xl font-bold mb-2">Device Benchmark</Text>
        <Text className="text-slate-400 text-sm mb-6 leading-relaxed">
          Times the voter-side cryptography on this phone: the same code used when casting a ballot.
          Keep the app in the foreground; it takes a minute or two.
        </Text>
        <TouchableOpacity
          className={`w-full rounded-2xl py-4 items-center mb-6 ${running ? "bg-slate-700" : "bg-blue-600"}`}
          onPress={run}
          disabled={running}
        >
          <Text className="text-white text-base font-bold">{running ? "Running…" : "Run benchmark"}</Text>
        </TouchableOpacity>
        {!!note && <Text className="text-slate-400 text-xs mb-4">{note}</Text>}
        {rows.length > 0 && (
          <View className="bg-slate-800 rounded-2xl border border-slate-700 p-4">
            <Text className="text-slate-200 text-xs font-mono leading-5" selectable>{report}</Text>
          </View>
        )}
        {rows.length > 0 && (
          <Text className="text-slate-600 text-xs mt-3">Long-press the text to copy it.</Text>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}
