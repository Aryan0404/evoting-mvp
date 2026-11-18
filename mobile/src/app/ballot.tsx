import { useEffect, useCallback, useRef, useState } from "react";
import {
  View,
  Text,
  ScrollView,
  TouchableOpacity,
  ActivityIndicator,
} from "react-native";
import { useRouter, useLocalSearchParams } from "expo-router";
import { SafeAreaView } from "react-native-safe-area-context";
import BallotCard from "../components/BallotCard";
import VIDDisplay from "../components/VIDDisplay";
import {
  useVotingStore,
  selectBallot,
  selectSelectedCandidate,
  selectReceipt,
  selectVotingStatus,
  selectVotingError,
  type BallotItem,
} from "../store/votingStore";
import { useAuthStore, selectVoter } from "../store/authStore";
import { ApiError, castBallot, errorCode, fetchElection } from "../api/client";
import {
  prepareBallot, restampBallot, sealBallot,
  type PreparedBallot, type SealedBallot,
} from "../crypto/voterDevice";
import { secrets } from "../crypto/secureStore";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Transient failures where the ticket was NOT consumed, so resending is safe. */
function isRetryable(err: unknown): boolean {
  const status = (err as ApiError)?.status;
  const code = errorCode(err);
  if (status === undefined) return true;                       // network error / timeout
  if (status === 503 && code !== "FORENSIC_LOCKDOWN") return true;  // ledger down or server busy
  if (status === 400 && code === "STALE_TIMESTAMP") return true;    // clock drift: restamp
  return false;
}

function explain(err: unknown): string {
  const status = (err as ApiError)?.status;
  switch (errorCode(err)) {
    case "FORENSIC_LOCKDOWN":
      return "Voting is paused while an integrity alert is investigated. Your ticket is still valid — please try again later.";
    case "TICKET_INVALID_OR_USED":
      return "This phone's ballot ticket has already been used or has expired. A ticket can cast exactly one ballot.";
    case "INVALID_PROOF":
      return "The server could not verify the ballot proof. Nothing was recorded and your ticket is still valid.";
    case "INVALID_SIGNATURE":
      return "The device signature was rejected. Nothing was recorded. Register again on this phone.";
    case "LEDGER_UNAVAILABLE":
      return "The ledger is temporarily unavailable. Your vote was NOT recorded and your ticket is still valid.";
  }
  if (status === undefined) return "Could not reach the server. Your vote was not recorded — please try again.";
  return (err as Error)?.message ?? "Something went wrong. Please try again.";
}

export default function BallotScreen() {
  const router = useRouter();
  const params = useLocalSearchParams<{ voterId: string }>();

  /* ── Store state ── */
  const status            = useVotingStore(selectVotingStatus);
  const ballot            = useVotingStore(selectBallot);
  const selectedCandidate = useVotingStore(selectSelectedCandidate);
  const receipt           = useVotingStore(selectReceipt);
  const errorMessage      = useVotingStore(selectVotingError);
  const progress          = useVotingStore((s) => s.precomputeProgress);
  const voter             = useAuthStore(selectVoter);

  const {
    setBallotLoading,
    setBallot,
    selectCandidate,
    clearSelection,
    setSubmitting,
    setSubmitted,
    setError,
    setPrecomputeProgress,
    reset,
  } = useVotingStore();

  /* Background precomputation: started as soon as the ballot is shown, so
     the expensive exponentiations run while the voter reads the candidates. */
  const prepared = useRef<Promise<PreparedBallot> | null>(null);
  const [hasTicket, setHasTicket] = useState<boolean | null>(null);
  const [timing, setTiming] = useState<{ pre: number; seal: number } | null>(null);
  const [submitNote, setSubmitNote] = useState("");

  const loadBallot = useCallback(async () => {
    setBallotLoading();
    setPrecomputeProgress(0);
    try {
      setHasTicket(!!(await secrets.getTicket()));
      const election = await fetchElection();
      const items: BallotItem[] = election.candidates.map((c) => ({
        position: c.position,
        candidate: {
          id:           c.id,
          name:         c.name,
          party:        c.party,
          partySymbol:  c.symbol,
          constituency: election.election_id,
        },
      }));
      setBallot(items);
      prepared.current = prepareBallot(election, setPrecomputeProgress);
      prepared.current.catch(() => {});
    } catch (err) {
      setError(explain(err));
    }
  }, []);

  /* ── Load ballot on mount ── */
  useEffect(() => {
    if (status === "idle") loadBallot();
  }, [status]);

  /* ── Submit vote ── */
  const handleSubmit = useCallback(async () => {
    if (!selectedCandidate || !prepared.current) return;
    const item = ballot.find((b) => b.candidate.id === selectedCandidate.id);
    if (!item) return;
    setSubmitting();
    setSubmitNote("Encrypting your choice on this phone…");
    try {
      const prep = await prepared.current;
      let sealed: SealedBallot = await sealBallot(prep, item.position - 1);
      setSubmitNote("Sending the sealed ballot…");

      let lastErr: unknown;
      for (let attempt = 0; attempt < 4; attempt++) {
        try {
          if (attempt > 0) {
            setSubmitNote(`Retrying (${attempt}/3)…`);
            await sleep(1000 * 2 ** (attempt - 1));
            sealed = await restampBallot(prep, sealed);
          }
          const { uti, ...body } = sealed;
          const r = await castBallot({ uti, ciphertext: body.ciphertext, zkp_proof: body.zkp_proof,
                                       num_candidates: body.num_candidates, ts: body.ts, signature: body.signature });
          const rec = {
            ballotHash: r.ballot_hash,
            ballotId:   r.ballot_id,
            sequenceNo: r.sequence_no,
            castAt:     r.cast_at,
            electionId: prep.election.election_id,
          };
          await secrets.setReceipt(rec);
          await secrets.clearTicket();          // spent: one ticket, one ballot
          setTiming({ pre: prep.precomputeMs, seal: sealed.sealMs });
          setSubmitted(rec);
          return;
        } catch (err) {
          lastErr = err;
          if (!isRetryable(err)) break;
        }
      }
      throw lastErr;
    } catch (err) {
      setError(explain(err));
    }
  }, [selectedCandidate, ballot]);

  /* ══════════════════════════════════════
     Render
  ══════════════════════════════════════ */
  return (
    <SafeAreaView className="flex-1 bg-slate-900" edges={["bottom"]}>

      {/* ── LOADING ── */}
      {status === "loading_ballot" && (
        <View className="flex-1 items-center justify-center">
          <ActivityIndicator size="large" color="#3b82f6" />
          <Text className="text-slate-400 text-sm mt-4">Loading ballot…</Text>
        </View>
      )}

      {/* ── BALLOT READY ── */}
      {status === "ballot_ready" && (
        <ScrollView
          contentContainerStyle={{ flexGrow: 1 }}
          showsVerticalScrollIndicator={false}
        >
          <View className="px-6 pt-6 pb-10">

            {/* Header */}
            <Text className="text-white text-2xl font-bold mb-1">
              Cast Your Vote
            </Text>
            <Text className="text-slate-400 text-sm mb-2">
              Select one candidate and tap Submit.
            </Text>

            {/* Election badge */}
            <View className="bg-slate-800 rounded-full px-4 py-1.5 self-start mb-4 border border-slate-700">
              <Text className="text-slate-300 text-xs font-semibold">
                🗳 {ballot[0]?.candidate.constituency ?? ""}
              </Text>
            </View>

            {/* On-device encryption status */}
            <View className="bg-slate-800 rounded-xl px-4 py-3 mb-4 border border-slate-700">
              <Text className="text-slate-300 text-xs">
                {progress < 1
                  ? `🔐 Preparing encryption on this phone… ${Math.round(progress * 100)}%`
                  : "🔐 Ready. Your choice will be encrypted on this phone before it is sent."}
              </Text>
              <View className="h-1 bg-slate-700 rounded-full mt-2 overflow-hidden">
                <View className="h-1 bg-blue-500" style={{ width: `${Math.round(progress * 100)}%` }} />
              </View>
            </View>

            {hasTicket === false && (
              <View className="bg-amber-950 border border-amber-800 rounded-xl px-4 py-3 mb-4">
                <Text className="text-amber-300 text-xs">
                  This phone has no ballot ticket. Complete registration (face check) first — you can
                  view the ballot, but casting needs the ticket issued at registration.
                </Text>
              </View>
            )}

            {/* Voter ID badge */}
            {(params.voterId || voter?.voterId) && (
              <View className="bg-blue-950 border border-blue-800 rounded-xl px-4 py-3 mb-6">
                <Text className="text-blue-300 text-xs">
                  Voting as:{" "}
                  <Text className="font-bold">
                    {params.voterId ?? voter?.voterId}
                  </Text>
                </Text>
              </View>
            )}

            {/* Candidates */}
            {(ballot || []).map((item) => (
              <BallotCard
                key={item.candidate.id}
                candidate={item.candidate}
                position={item.position}
                selected={selectedCandidate?.id === item.candidate.id}
                disabled={false}
                onSelect={selectCandidate}
              />
            ))}

            {/* Action row */}
            <View className="mt-4 flex-row gap-x-3">
              <TouchableOpacity
                className="flex-1 bg-slate-700 rounded-2xl py-4 items-center border border-slate-600"
                onPress={clearSelection}
                disabled={!selectedCandidate}
                activeOpacity={0.85}
              >
                <Text className={`text-sm font-semibold
                  ${selectedCandidate ? "text-slate-200" : "text-slate-600"}`}>
                  Clear
                </Text>
              </TouchableOpacity>

              <TouchableOpacity
                className={`flex-1 rounded-2xl py-4 items-center
                  ${selectedCandidate ? "bg-blue-600 active:bg-blue-700" : "bg-slate-700"}`}
                onPress={handleSubmit}
                disabled={!selectedCandidate}
                activeOpacity={0.85}
              >
                <Text className={`text-sm font-bold
                  ${selectedCandidate ? "text-white" : "text-slate-500"}`}>
                  Submit Vote →
                </Text>
              </TouchableOpacity>
            </View>

          </View>
        </ScrollView>
      )}

      {/* ── SUBMITTING ── */}
      {status === "submitting" && (
        <View className="flex-1 items-center justify-center px-6">
          <ActivityIndicator size="large" color="#3b82f6" />
          <Text className="text-white text-lg font-semibold mt-6">
            Recording Your Vote…
          </Text>
          <Text className="text-slate-400 text-sm mt-2 text-center">
            {submitNote || "Please do not close the app."}
          </Text>
        </View>
      )}

      {/* ── SUBMITTED / SUCCESS ── */}
      {status === "submitted" && receipt && (
        <ScrollView
          contentContainerStyle={{ flexGrow: 1 }}
          showsVerticalScrollIndicator={false}
        >
          <View className="flex-1 px-6 pt-8 pb-10 items-center">

            <View className="w-20 h-20 rounded-full bg-emerald-600 items-center justify-center mb-5">
              <Text className="text-4xl">✓</Text>
            </View>

            <Text className="text-white text-2xl font-bold mb-2 text-center">
              Vote Recorded!
            </Text>
            <Text className="text-slate-400 text-sm text-center mb-8 leading-relaxed">
              Your encrypted ballot is in the ledger. Nobody, including the
              operator, can see your choice.
            </Text>

            <VIDDisplay receipt={receipt} />

            {timing && (
              <Text className="text-slate-600 text-xs mt-3 text-center">
                On this phone: precomputation {timing.pre} ms (while you read the ballot),
                sealing {timing.seal} ms after you pressed Submit.
              </Text>
            )}

            <TouchableOpacity
              className="w-full bg-blue-600 rounded-2xl py-4 items-center mt-8 active:bg-blue-700"
              onPress={() => router.push("/verify")}
              activeOpacity={0.85}
            >
              <Text className="text-white text-base font-bold">
                Verify My Vote →
              </Text>
            </TouchableOpacity>

            <TouchableOpacity
              className="mt-4"
              onPress={() => router.push("/")}
            >
              <Text className="text-slate-500 text-sm">← Back to Home</Text>
            </TouchableOpacity>

          </View>
        </ScrollView>
      )}

      {/* ── ERROR ── */}
      {status === "error" && (
        <View className="flex-1 items-center justify-center px-6">
          <View className="w-20 h-20 rounded-full bg-red-900 items-center justify-center mb-6">
            <Text className="text-4xl">✕</Text>
          </View>
          <Text className="text-white text-2xl font-bold mb-2">Vote Failed</Text>
          <Text className="text-slate-400 text-sm text-center mb-10 leading-relaxed">
            {errorMessage || "Something went wrong. Please try again."}
          </Text>
          <TouchableOpacity
            className="w-full bg-blue-600 rounded-2xl py-4 items-center active:bg-blue-700"
            onPress={() => { reset(); }}
            activeOpacity={0.85}
          >
            <Text className="text-white text-base font-bold">Try Again</Text>
          </TouchableOpacity>
        </View>
      )}

    </SafeAreaView>
  );
}