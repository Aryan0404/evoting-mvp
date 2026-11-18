/* ══════════════════════════════════════
   Auth
══════════════════════════════════════ */
export type AuthStatus =
  | "idle"
  | "registering"
  | "liveness_pending"
  | "liveness_passed"
  | "liveness_failed"
  | "authenticated"
  | "error";

export type Voter = {
  aadhaarId:     string;
  voterId:       string;
  sessionToken?: string;
  verifiedAt?:   string;
};

export type LivenessCapture = {
  uri:         string;
  base64?:     string;
  width:       number;
  height:      number;
  capturedAt:  string;
};

/* ══════════════════════════════════════
   Ballot & Voting
══════════════════════════════════════ */
export type Candidate = {
  id:           string;
  name:         string;
  party:        string;
  partySymbol:  string;
  constituency: string;
};

export type BallotItem = {
  candidate: Candidate;
  position:  number;
};

export type VoteReceipt = {
  ballotHash: string;
  ballotId:   string;
  sequenceNo: number;
  castAt:     string;
  electionId: string;
};

export type VotingStatus =
  | "idle"
  | "loading_ballot"
  | "ballot_ready"
  | "submitting"
  | "submitted"
  | "error";

/* ══════════════════════════════════════
   API payloads
══════════════════════════════════════ */
// API request/response types live in api/client.ts next to the calls.

/**
 * LivenessPayload is defined in api/client.ts.
 * Re-exported here for convenience — import from api/client directly
 * for the full type including frames and challenge_results.
 * @see mobile/src/api/client.ts → LivenessPayload
 */
export type { LivenessPayload } from "../api/client";



/* ══════════════════════════════════════
   API responses
══════════════════════════════════════ */


export type LivenessResponse = {
  liveness_passed: boolean;   // renamed — matches backend LivenessSubmitResponse
  session_id:      string;
};







/* ══════════════════════════════════════
   UI helpers
══════════════════════════════════════ */
export type LoadingState = "idle" | "loading" | "success" | "error";

export type ToastType = "success" | "error" | "info" | "warning";

export type Toast = {
  id:      string;
  type:    ToastType;
  message: string;
};