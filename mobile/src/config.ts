import Constants from 'expo-constants';

/**
 * Environment configuration, read from app.json → expo.extra.
 * (Constants.manifest is null on current Expo SDKs; expoConfig is the live source.)
 */
const extra = (Constants.expoConfig?.extra ?? {}) as Record<string, any>;

export const config = {
  BASE_URL: (extra.BASE_URL as string) || "http://localhost:8000",
  API_VERSION: (extra.API_VERSION as string) || "/api/v1",
  TIMEOUT_MS: Number(extra.TIMEOUT_MS) || 10000,
} as const;

export default config;
