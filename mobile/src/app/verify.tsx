import { useEffect, useState } from "react";
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  ActivityIndicator,
  ScrollView,
  KeyboardAvoidingView,
  Platform,
} from "react-native";
import { useRouter } from "expo-router";
import { SafeAreaView } from "react-native-safe-area-context";
import { selectReceipt, useVotingStore } from "../store/votingStore";
import { fetchBoard, fetchReceiptProof, type BoardResponse, type ReceiptProofResponse } from "../api/client";
import { checkReceipt } from "../crypto/voterDevice";
import { secrets } from "../crypto/secureStore";

type VerifyStep = "input" | "loading" | "verified" | "pending" | "not_found" | "mismatch" | "error";

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Voter verification, done on the phone itself: the server supplies the Merkle
 * audit path and the root published by the air-gapped replica; the phone
 * recomputes the root from its own receipt. A match proves the ballot is in
 * the ledger exactly as cast, without trusting the server's word for it.
 */
export default function VerifyScreen() {
  const router = useRouter();
  const stored = useVotingStore(selectReceipt);
  const setReceipt = useVotingStore((s) => s.setReceipt);

  const [hash, setHash]         = useState(stored?.ballotHash ?? "");
  const [step, setStep]         = useState<VerifyStep>("input");
  const [proof, setProof]       = useState<ReceiptProofResponse | null>(null);
  const [board, setBoard]       = useState<BoardResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [ms, setMs]             = useState<number | null>(null);

  /* Receipt saved on this phone after casting (survives app restarts). */
  useEffect(() => {
    secrets.getReceipt().then((r) => {
      if (r) {
        setReceipt(r);
        setHash((h) => h || r.ballotHash);
      }
    }).catch(() => {});
  }, []);

  const valid = HEX64.test(hash.trim().toLowerCase());

  async function handleVerify() {
    const h = hash.trim().toLowerCase();
    if (!HEX64.test(h)) return;
    setStep("loading");
    try {
      const [p, b] = await Promise.all([fetchReceiptProof(h), fetchBoard().catch(() => null)]);
      setProof(p);
      setBoard(b);
      if (!p.included) {
        setStep(p.reason === "NOT_IN_LEDGER_YET" ? "not_found" : "pending");
        return;
      }
      if (!p.verified_by_replica || !p.path || !p.replica_root) {
        setStep("pending");
        return;
      }
      const t0 = Date.now();
      const ok = checkReceipt(h, p.path, p.replica_root);
      setMs(Date.now() - t0);
      setStep(ok ? "verified" : "mismatch");
    } catch (err: any) {
      setErrorMsg(err?.message ?? "Could not reach the server.");
      setStep("error");
    }
  }

  return (
    <SafeAreaView className="flex-1 bg-slate-900" edges={["bottom"]}>
      <KeyboardAvoidingView className="flex-1" behavior={Platform.OS === "ios" ? "padding" : "height"}>
        <ScrollView
          contentContainerStyle={{ flexGrow: 1 }}
          keyboardShouldPersistTaps="handled"
          showsVerticalScrollIndicator={false}
        >
          <View className="flex-1 px-6 pt-6 pb-10">

            {(step === "input" || step === "error") && (
              <View>
                <Text className="text-white text-2xl font-bold mb-2">Verify Your Vote</Text>
                <Text className="text-slate-400 text-sm mb-8 leading-relaxed">
                  Your phone checks your receipt against the fingerprint (Merkle root) published by
                  the independent forensic replica. It does not take the server's word for it.
                </Text>

                <Text className="text-slate-300 text-sm font-semibold mb-2">Receipt (64 hex characters)</Text>
                <TextInput
                  className="bg-slate-800 border border-slate-700 rounded-xl px-4 py-3.5 text-white text-xs font-mono"
                  placeholder="receipt shown after you voted"
                  placeholderTextColor="#475569"
                  value={hash}
                  onChangeText={setHash}
                  autoCapitalize="none"
                  autoCorrect={false}
                  multiline
                  returnKeyType="search"
                />
                {stored && (
                  <TouchableOpacity
                    className="mt-3 bg-blue-950 border border-blue-800 rounded-xl px-4 py-3"
                    onPress={() => setHash(stored.ballotHash)}
                  >
                    <Text className="text-blue-300 text-xs">
                      Use the receipt saved on this phone (ledger #{stored.sequenceNo})
                    </Text>
                  </TouchableOpacity>
                )}
                {step === "error" && (
                  <Text className="text-red-400 text-xs mt-3">{errorMsg}</Text>
                )}

                <TouchableOpacity
                  className={`w-full rounded-2xl py-4 items-center mt-8 ${valid ? "bg-blue-600" : "bg-slate-700"}`}
                  onPress={handleVerify}
                  disabled={!valid}
                  activeOpacity={0.85}
                >
                  <Text className={`text-base font-bold ${valid ? "text-white" : "text-slate-500"}`}>
                    Verify on this phone →
                  </Text>
                </TouchableOpacity>
              </View>
            )}

            {step === "loading" && (
              <View className="flex-1 items-center justify-center">
                <ActivityIndicator size="large" color="#3b82f6" />
                <Text className="text-slate-400 text-sm mt-4">Fetching the audit path…</Text>
              </View>
            )}

            {(step === "verified" || step === "mismatch" || step === "pending" || step === "not_found") && (
              <View>
                <View className={`w-20 h-20 rounded-full items-center justify-center mb-5 self-center
                  ${step === "verified" ? "bg-emerald-600" : step === "mismatch" ? "bg-red-700" : "bg-amber-700"}`}>
                  <Text className="text-4xl">{step === "verified" ? "✓" : step === "mismatch" ? "✕" : "…"}</Text>
                </View>
                <Text className="text-white text-2xl font-bold mb-2 text-center">
                  {step === "verified" && "Your ballot is in the ledger"}
                  {step === "mismatch" && "Receipt does NOT match"}
                  {step === "pending" && "Recorded — check again shortly"}
                  {step === "not_found" && "Not in the ledger yet"}
                </Text>
                <Text className="text-slate-400 text-sm text-center mb-6 leading-relaxed">
                  {step === "verified" &&
                    "Your phone recomputed the replica's published root from your own receipt. The ballot is stored exactly as you cast it."}
                  {step === "mismatch" &&
                    "The audit path does not lead to the replica's root. Report this receipt to the election observers — this is what tampering looks like."}
                  {step === "pending" &&
                    "The ledger has your ballot, but the forensic replica has not sealed that part of the ledger yet (it checks every few seconds)."}
                  {step === "not_found" &&
                    "Ballots reach the ledger within seconds of being accepted. If this persists, report the receipt."}
                </Text>

                {proof && (
                  <View className="bg-slate-800 rounded-2xl border border-slate-700 px-5 py-4 mb-4">
                    {proof.ledger_position !== undefined && <Row label="Ledger position" value={`#${proof.ledger_position}`} />}
                    {proof.bundle_id !== undefined && <Row label="Bundle" value={`${proof.bundle_id} (${proof.bundle_count ?? "?"} ballots)`} />}
                    {proof.path && <Row label="Hashes checked" value={`${proof.path.length}`} />}
                    {ms !== null && <Row label="Check time on phone" value={`${ms} ms`} />}
                    {proof.replica_root && <Row label="Replica root" value={`${proof.replica_root.slice(0, 16)}…`} />}
                  </View>
                )}
                {board && (
                  <View className="bg-slate-800 rounded-2xl border border-slate-700 px-5 py-4 mb-4">
                    <Row label="Replica status" value={board.replica_status ?? "—"} />
                    <Row label="Replica liveness" value={board.liveness?.status ?? "—"} />
                    <Row label="Ballots verified by replica" value={`${board.replica_ballots_verified}`} />
                  </View>
                )}

                <TouchableOpacity
                  className="w-full bg-slate-700 rounded-2xl py-4 items-center border border-slate-600"
                  onPress={() => setStep("input")}
                >
                  <Text className="text-slate-200 text-base font-semibold">Check again</Text>
                </TouchableOpacity>
                <TouchableOpacity className="mt-4 items-center" onPress={() => router.push("/")}>
                  <Text className="text-slate-500 text-sm">← Back to Home</Text>
                </TouchableOpacity>
              </View>
            )}

          </View>
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <View className="flex-row justify-between items-center mb-2">
      <Text className="text-slate-500 text-xs uppercase tracking-wider">{label}</Text>
      <Text className="text-slate-200 text-xs font-semibold font-mono">{value}</Text>
    </View>
  );
}
