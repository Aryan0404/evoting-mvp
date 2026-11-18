import axios, {
  AxiosInstance,
  AxiosRequestConfig,
  AxiosResponse,
  InternalAxiosRequestConfig,
} from "axios";
import { useAuthStore } from "../store/authStore";
import { config } from "../config";

/* ══════════════════════════════════════
   Config
══════════════════════════════════════ */
const BASE_URL     = config.BASE_URL;
const TIMEOUT_MS   = config.TIMEOUT_MS;
const API_VERSION  = config.API_VERSION;

/* ══════════════════════════════════════
   Axios instance
══════════════════════════════════════ */
export const apiClient: AxiosInstance = axios.create({
  baseURL: `${BASE_URL}${API_VERSION}`,
  timeout: TIMEOUT_MS,
  headers: {
    "Content-Type": "application/json",
    Accept:         "application/json",
  },
});

/* ══════════════════════════════════════
   Request interceptor
   — attaches session token if present
══════════════════════════════════════ */
apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const token = useAuthStore.getState().voter?.sessionToken;

    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    if (__DEV__) {
      console.log(
        `[API →] ${config.method?.toUpperCase()} ${config.baseURL}${config.url}`,
        config.data ?? ""
      );
    }

    return config;
  },
  (error) => {
    console.error("[API request error]", error);
    return Promise.reject(error);
  }
);

/* ══════════════════════════════════════
   Response interceptor
   — normalizes errors
══════════════════════════════════════ */
apiClient.interceptors.response.use(
  (response: AxiosResponse) => {
    if (__DEV__) {
      console.log(
        `[API ←] ${response.status} ${response.config.url}`,
        response.data
      );
    }
    return response;
  },
  (error) => {
    const status  = error.response?.status;
    const detail  = error.response?.data?.detail;
    const message = error.response?.data?.message;

    if (__DEV__) {
      console.error(`[API error] ${status}`, error.response?.data ?? error.message);
    }

    /* ── Map status codes to readable messages ── */
    const readable = resolveErrorMessage(status, detail ?? message ?? error.message);

    return Promise.reject(new ApiError(readable, status, error.response?.data));
  }
);

/* ══════════════════════════════════════
   ApiError — typed error class
══════════════════════════════════════ */
export class ApiError extends Error {
  status:   number | undefined;
  payload:  unknown;

  constructor(message: string, status?: number, payload?: unknown) {
    super(message);
    this.name    = "ApiError";
    this.status  = status;
    this.payload = payload;
  }
}

/* ══════════════════════════════════════
   Error message resolver
══════════════════════════════════════ */
function resolveErrorMessage(
  status: number | undefined,
  fallback: string
): string {
  switch (status) {
    case 400: return "Invalid request. Please check your details.";
    case 401: return "Session expired. Please re-authenticate.";
    case 403: return "Access denied. You are not authorized.";
    case 404: return "Resource not found.";
    case 409: return "Conflict — you may have already voted.";
    case 422: return "Validation failed. Please check your inputs.";
    case 429: return "Too many requests. Please wait and try again.";
    case 500: return "Server error. Please try again shortly.";
    case 503: return "Service unavailable. Please try again later.";
    default:  return fallback ?? "An unexpected error occurred.";
  }
}

/* ══════════════════════════════════════
   API endpoint functions
══════════════════════════════════════ */

/* ── Health check ── */
export async function checkHealth(): Promise<{ status: string }> {
  // Health endpoint is at /api/v1/health/full
  console.log(BASE_URL);
  const res = await axios.get(`${BASE_URL}${API_VERSION}/health/full`, {
    timeout: 5_000,
  });
  return res.data;
}


/* ── Registration initiation ── */
export type RegisterPayload = {
  aadhaar_id: string;
  voter_id:   string;
  full_name:  string;
};

/**
 * Response from POST /api/v1/registration/initiate
 * Contains the liveness session details needed for the next step.
 */
export type RegisterResponse = {
  registration_id:     string;
  liveness_session_id: string;
  challenges:          string[];   // e.g. ["blink_twice", "turn_head_left", "smile"]
  nonce:               string;
  nonce_expires_at:    string;     // ISO 8601
};

export async function registerVoter(
  payload: RegisterPayload
): Promise<RegisterResponse> {
  const res = await apiClient.post<RegisterResponse>(
    "/registration/initiate",
    payload
  );
  return res.data;
}

/* ── Liveness verification ── */

/**
 * Per-frame facial signal — mirrors FrameData from LivenessCamera.tsx.
 * Sent to backend so it can validate motion patterns server-side.
 */
export type FrameData = {
  leftEyeOpen:  number;
  rightEyeOpen: number;
  yaw:          number;
  pitch:        number;
  smileScore?:  number;
  timestamp:    number;
};

/**
 * Single challenge completion event.
 * challenge_results is serialised to JSON string for multipart form.
 */
export type ChallengeResult = {
  challenge:    string;
  passed:       boolean;
  timestamp_ms: number;
};

/**
 * Full liveness submission payload.
 * Sent as multipart/form-data to POST /api/v1/registration/liveness
 */
export type LivenessPayload = {
  session_id:        string;          // UUID from /initiate
  nonce:             string;          // hex nonce from /initiate
  challenge_results: ChallengeResult[];
  frames:            FrameData[];     // frame signal array for backend validation
  image_base64?:     string;          // captured face image (optional for MVP)
  image_uri?:        string;          // local file URI for FormData append
};

export type LivenessResponse = {
  liveness_passed: boolean;
  session_id:      string;
};

/**
 * Submit liveness challenge results to the backend.
 *
 * Sends multipart/form-data with:
 *   - session_id    (form field)
 *   - nonce         (form field)
 *   - challenge_results (form field — JSON string)
 *   - frames_meta   (form field — JSON string, for backend frame validation)
 *   - face_frames   (file — the captured image, if URI provided)
 *
 * The backend IGNORES any top-level "passed" field.
 * Only the computed challenge_results and frame data are trusted.
 */
export async function submitLiveness(
  payload: LivenessPayload
): Promise<LivenessResponse> {
  const form = new FormData();

  form.append("session_id", payload.session_id);
  form.append("nonce",      payload.nonce);

  // challenge_results must be a JSON string (backend does json.loads on it)
  form.append(
    "challenge_results",
    JSON.stringify(payload.challenge_results)
  );

  // frames_meta: backend will use this in B4 for motion validation
  form.append(
    "frames_meta",
    JSON.stringify(payload.frames)
  );

  // Attach the captured image if a local URI was provided
  if (payload.image_uri) {
    const filename = payload.image_uri.split("/").pop() ?? "liveness.jpg";
    const match    = /\.(\w+)$/.exec(filename);
    const mimeType = match ? `image/${match[1]}` : "image/jpeg";

    // React Native FormData accepts { uri, name, type } objects
    form.append("face_frames", {
      uri:  payload.image_uri,
      name: filename,
      type: mimeType,
    } as any);
  }

  const res = await apiClient.post<LivenessResponse>(
    "/registration/liveness",
    form,
    {
      headers: {
        // Let axios set the correct multipart boundary automatically
        "Content-Type": "multipart/form-data",
      },
      // Increase timeout for image upload
      timeout: 30_000,
    }
  );

  return res.data;
}

// verifyLiveness() removed in Phase 2.5 (STEP B5).
// Use submitLiveness() from this file directly.
// The old endpoint /auth/liveness no longer exists.

/* ── Complete registration: face match + device key → one-time ticket ── */
export type VerifyIdentityResponse = {
  registration_status: "active";
  uti:                 string;   // one-time ballot ticket — stored in secure storage only
  voter_ref_id:        string;
  message:             string;
};

export async function verifyIdentity(args: {
  session_id:        string;
  aadhaar_id:        string;
  voter_id:          string;
  image_uri:         string;
  device_public_key: string;   // compressed P-256 point, hex
}): Promise<VerifyIdentityResponse> {
  const form = new FormData();
  form.append("session_id", args.session_id);
  form.append("aadhaar_id", args.aadhaar_id);
  form.append("voter_id", args.voter_id);
  form.append("device_public_key", args.device_public_key);
  const filename = args.image_uri.split("/").pop() ?? "live.jpg";
  const ext = (/\.(\w+)$/.exec(filename)?.[1] ?? "jpeg").toLowerCase();
  form.append("live_image", {
    uri:  args.image_uri,
    name: filename,
    type: ext === "png" ? "image/png" : "image/jpeg",
  } as any);
  const res = await apiClient.post<VerifyIdentityResponse>("/registration/verify-identity", form, {
    headers: { "Content-Type": "multipart/form-data" },
    timeout: 30_000,
  });
  return res.data;
}

/* ── Public election parameters (key, candidates, clock) ── */
export type { ElectionInfo } from "../crypto/voterDevice";
import type { ElectionInfo } from "../crypto/voterDevice";

export async function fetchElection(): Promise<ElectionInfo> {
  const res = await apiClient.get<ElectionInfo>("/election");
  return res.data;
}

/* ── Cast an encrypted, proven, signed ballot (Algorithm 1) ── */
export type CastBallotPayload = {
  uti:            string;
  ciphertext:     string;
  zkp_proof:      string;
  num_candidates: number;
  ts:             number;
  signature:      string;
};

export type CastBallotResponse = {
  ballot_id:         string;
  ballot_hash:       string;   // the receipt (Merkle leaf)
  sequence_no:       number;
  ledger_message_id: string;
  cast_at:           string;
  message:           string;
};

export async function castBallot(payload: CastBallotPayload): Promise<CastBallotResponse> {
  const res = await apiClient.post<CastBallotResponse>("/vote/cast", payload, { timeout: 30_000 });
  return res.data;
}

/** Server error code from a FastAPI detail body, e.g. "FORENSIC_LOCKDOWN". */
export function errorCode(err: unknown): string | undefined {
  const p = (err as ApiError)?.payload as any;
  return p?.detail?.error ?? p?.error;
}

/* ── Receipt check: Merkle path + the replica's published root ── */
export type ReceiptProofResponse = {
  included:            boolean;
  ballot_hash:         string;
  reason?:             "NOT_IN_LEDGER_YET" | "REPLICA_NOT_CAUGHT_UP" | "LEDGER_NOT_READY";
  ledger_position?:    number;
  bundle_id?:          number;
  leaf_index?:         number;
  bundle_count?:       number;
  path?:               { side: "L" | "R"; hash: string }[];
  replica_root?:       string;
  primary_root?:       string;
  verified_by_replica?: boolean;
};

export async function fetchReceiptProof(ballotHash: string): Promise<ReceiptProofResponse> {
  const res = await apiClient.get<ReceiptProofResponse>(`/audit/proof/${ballotHash}`);
  return res.data;
}

export type BoardResponse = {
  total_votes_cast:         number;
  replica_ballots_verified: number;
  replica_status:           string | null;
  liveness:                 { status?: string } | null;
  alert:                    unknown;
};

export async function fetchBoard(): Promise<BoardResponse> {
  const res = await apiClient.get<BoardResponse>("/audit/board");
  return res.data;
}
