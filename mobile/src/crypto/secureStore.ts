/**
 * Secrets kept on the phone, in the OS keystore-backed secure storage
 * (iOS Keychain / Android Keystore via expo-secure-store), never in plain
 * AsyncStorage and never sent anywhere:
 *   - the device signing key (ECDSA P-256 private key),
 *   - the one-time ballot ticket (UTI) issued at the end of registration,
 *   - the receipt of the cast ballot, so the voter can check it later.
 */
import * as SecureStore from "expo-secure-store";

const OPTS: SecureStore.SecureStoreOptions = {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

const K_DEVICE_KEY = "evote.device_key";
const K_TICKET = "evote.ticket";
const K_RECEIPT = "evote.receipt";

export type StoredReceipt = {
  ballotHash: string;
  ballotId: string;
  sequenceNo: number;
  castAt: string;
  electionId: string;
};

export const secrets = {
  getDeviceKey: () => SecureStore.getItemAsync(K_DEVICE_KEY, OPTS),
  setDeviceKey: (hex: string) => SecureStore.setItemAsync(K_DEVICE_KEY, hex, OPTS),

  getTicket: () => SecureStore.getItemAsync(K_TICKET, OPTS),
  setTicket: (uti: string) => SecureStore.setItemAsync(K_TICKET, uti, OPTS),
  clearTicket: () => SecureStore.deleteItemAsync(K_TICKET, OPTS),

  async getReceipt(): Promise<StoredReceipt | null> {
    const raw = await SecureStore.getItemAsync(K_RECEIPT, OPTS);
    return raw ? (JSON.parse(raw) as StoredReceipt) : null;
  },
  setReceipt: (r: StoredReceipt) => SecureStore.setItemAsync(K_RECEIPT, JSON.stringify(r), OPTS),

  async wipeAll() {
    await Promise.all([K_DEVICE_KEY, K_TICKET, K_RECEIPT].map((k) => SecureStore.deleteItemAsync(k, OPTS)));
  },
};
