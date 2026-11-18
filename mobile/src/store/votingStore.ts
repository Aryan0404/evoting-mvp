import { create } from "zustand";

/* ══════════════════════════════════════
   Types
══════════════════════════════════════ */
export type VotingStatus =
  | "idle"
  | "loading_ballot"
  | "ballot_ready"
  | "submitting"
  | "submitted"
  | "error";

export type Candidate = {
  id: string;
  name: string;
  party: string;
  partySymbol: string;   // emoji or icon identifier
  constituency: string;
};

export type BallotItem = {
  candidate: Candidate;
  position: number;
};

export type VoteReceipt = {
  ballotHash: string;    // receipt = SHA-256 of the sealed ballot = Merkle leaf
  ballotId:   string;
  sequenceNo: number;
  castAt:     string;    // ISO timestamp
  electionId: string;
};

export type VotingState = {
  /* ── State ── */
  status: VotingStatus;
  ballot: BallotItem[];
  selectedCandidateId: string | null;
  receipt: VoteReceipt | null;
  errorMessage: string;
  precomputeProgress: number;   // 0..1, background proof precomputation

  /* ── Actions ── */
  setBallotLoading: () => void;
  setBallot: (items: BallotItem[]) => void;
  selectCandidate: (candidateId: string) => void;
  clearSelection: () => void;
  setSubmitting: () => void;
  setSubmitted: (receipt: VoteReceipt) => void;
  setError: (message: string) => void;
  setPrecomputeProgress: (f: number) => void;
  setReceipt: (receipt: VoteReceipt) => void;
  reset: () => void;
};

/* ══════════════════════════════════════
   Initial state
══════════════════════════════════════ */
const INITIAL_STATE = {
  status:              "idle" as VotingStatus,
  ballot:              [] as BallotItem[],
  selectedCandidateId: null,
  receipt:             null,
  errorMessage:        "",
  precomputeProgress:  0,
};

/* ══════════════════════════════════════
   Store
══════════════════════════════════════ */
export const useVotingStore = create<VotingState>((set, get) => ({
  ...INITIAL_STATE,

  /* ── Fetching ballot from API ── */
  setBallotLoading() {
    set({ status: "loading_ballot", ballot: [], selectedCandidateId: null });
  },

  /* ── Ballot received ── */
  setBallot(items) {
    const sorted = [...items].sort((a, b) => a.position - b.position);
    set({ status: "ballot_ready", ballot: sorted, errorMessage: "" });
  },

  /* ── Voter taps a candidate ── */
  selectCandidate(candidateId) {
    const { ballot } = get();
    const exists = ballot.some((b) => b.candidate.id === candidateId);
    if (!exists) return;
    set({ selectedCandidateId: candidateId });
  },

  /* ── Voter deselects ── */
  clearSelection() {
    set({ selectedCandidateId: null });
  },

  /* ── Vote being submitted to API ── */
  setSubmitting() {
    set({ status: "submitting" });
  },

  /* ── Vote confirmed by backend ── */
  setSubmitted(receipt) {
    set({
      status: "submitted",
      receipt,
      selectedCandidateId: null,
      errorMessage: "",
    });
  },

  /* ── Error ── */
  setError(message) {
    set({ status: "error", errorMessage: message });
  },

  /* ── Background precomputation progress ── */
  setPrecomputeProgress(f) {
    set({ precomputeProgress: f });
  },

  /* ── Receipt loaded from secure storage ── */
  setReceipt(receipt) {
    set({ receipt });
  },

  /* ── Full reset ── */
  reset() {
    set(INITIAL_STATE);
  },
}));

/* ══════════════════════════════════════
   Selectors
══════════════════════════════════════ */
export const selectBallot = (s: VotingState) => s.ballot;

export const selectSelectedCandidate = (s: VotingState) =>
  s.ballot.find((b) => b.candidate.id === s.selectedCandidateId)?.candidate ?? null;

export const selectHasVoted = (s: VotingState) => s.status === "submitted";

export const selectReceipt = (s: VotingState) => s.receipt;

export const selectVotingStatus = (s: VotingState) => s.status;

export const selectVotingError = (s: VotingState) => s.errorMessage;