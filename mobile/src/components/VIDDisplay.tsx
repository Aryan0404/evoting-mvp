import { useState } from "react";
import { View, Text, TouchableOpacity } from "react-native";
import type { VoteReceipt } from "../types";

type Props = {
  receipt: VoteReceipt;
};

/**
 * The voter's receipt. The receipt is the SHA-256 of the sealed ballot exactly
 * as it was written to the ledger; it reveals nothing about the vote, and it is
 * what the phone later checks against the replica's published Merkle root.
 */
export default function VIDDisplay({ receipt }: Props) {
  const [hashVisible, setHashVisible] = useState(false);

  const formattedDate = new Date(receipt.castAt).toLocaleString("en-IN", {
    dateStyle: "medium",
    timeStyle: "short",
  });
  const short = `${receipt.ballotHash.slice(0, 8)}…${receipt.ballotHash.slice(-8)}`;

  return (
    <View className="w-full bg-slate-800 rounded-2xl border border-slate-700 overflow-hidden">

      <View className="bg-emerald-900 border-b border-emerald-700 px-5 py-3 flex-row items-center">
        <View className="w-2 h-2 rounded-full bg-emerald-400 mr-2" />
        <Text className="text-emerald-300 text-xs font-semibold uppercase tracking-wider">
          Ballot Recorded
        </Text>
      </View>

      <View className="px-5 py-5">

        <View className="mb-5">
          <Text className="text-slate-500 text-xs uppercase tracking-wider mb-1">
            Your receipt
          </Text>
          <View className="bg-slate-900 rounded-xl px-4 py-3 border border-slate-700">
            <Text className="text-blue-300 text-base font-mono font-bold tracking-widest" selectable>
              {short}
            </Text>
          </View>
          <Text className="text-slate-600 text-xs mt-1.5">
            Saved securely on this phone. It does not reveal your choice.
          </Text>
        </View>

        <ReceiptRow label="Cast at"         value={formattedDate} />
        <ReceiptRow label="Ledger position" value={`#${receipt.sequenceNo}`} />
        <ReceiptRow label="Election"        value={receipt.electionId} />

        <View className="mt-1">
          <View className="flex-row items-center justify-between mb-1">
            <Text className="text-slate-500 text-xs uppercase tracking-wider">
              Full receipt hash
            </Text>
            <TouchableOpacity onPress={() => setHashVisible((v) => !v)}>
              <Text className="text-blue-400 text-xs font-semibold">
                {hashVisible ? "Hide" : "Show"}
              </Text>
            </TouchableOpacity>
          </View>
          <View className="bg-slate-900 rounded-xl px-4 py-3 border border-slate-700">
            <Text
              className="text-slate-400 text-xs font-mono"
              numberOfLines={hashVisible ? undefined : 1}
              selectable
            >
              {hashVisible ? receipt.ballotHash : "••••••••••••••••••••••••••••••••"}
            </Text>
          </View>
        </View>

      </View>

      <View className="bg-slate-900 border-t border-slate-700 px-5 py-3">
        <Text className="text-slate-600 text-xs text-center leading-relaxed">
          Your choice was encrypted on this phone before sending.{"\n"}
          Use "Verify My Vote" to check it is in the ledger unchanged.
        </Text>
      </View>

    </View>
  );
}

function ReceiptRow({ label, value }: { label: string; value: string }) {
  return (
    <View className="flex-row justify-between items-center mb-4">
      <Text className="text-slate-500 text-xs uppercase tracking-wider">{label}</Text>
      <Text className="text-slate-200 text-sm font-semibold">{value}</Text>
    </View>
  );
}
