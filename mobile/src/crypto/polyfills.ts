/**
 * Must be imported before anything that needs randomness.
 * Installs crypto.getRandomValues (backed by the OS CSPRNG) on React Native,
 * which @noble/curves and @noble/hashes use for keys, nonces and ballot
 * randomness. Imported first thing in app/_layout.tsx.
 */
import "react-native-get-random-values";
