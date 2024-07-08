import {
  Address,
  Hex,
  createClient,
  createPublicClient,
  decodeAbiParameters,
  encodeAbiParameters,
  encodeFunctionData,
  hexToBigInt,
  hexToBytes,
  http,
  keccak256,
  parseAbiParameter,
} from "viem";
import { base, baseSepolia } from "viem/chains";
import { paymasterActionsEip7677 } from "permissionless/experimental";
import { accountAbi } from "../../abi/account";
import { entrypointAbi, entrypointAddress } from "@/app/abi/entrypoint";
import {
  ENTRYPOINT_ADDRESS_V06,
  UserOperation,
  createBundlerClient,
  deepHexlify,
} from "permissionless";
import { base64urlnopad } from "@scure/base";
import { sessionCallPermissionAbi } from "@/app/abi/sessionCallPermission";

const DUMMY_SIGNATURE =
  "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000170000000000000000000000000000000000000000000000000000000000000001949fc7c88032b9fcb5f6efc7a7b8c63668eae9871b765e23123bb473ff57aa831a7c0d9276168ebcc29f2875a0239cffdf2a9cd1c2007c5c77c071db9264df1d000000000000000000000000000000000000000000000000000000000000002549960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008a7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2273496a396e6164474850596759334b7156384f7a4a666c726275504b474f716d59576f4d57516869467773222c226f726967696e223a2268747470733a2f2f7369676e2e636f696e626173652e636f6d222c2263726f73734f726967696e223a66616c73657d00000000000000000000000000000000000000000000";
export const publicClient = createPublicClient({
  chain: baseSepolia,
  transport: http(),
});
export const bundlerClient = createBundlerClient({
  chain: baseSepolia,
  transport: http(
    "https://api.developer.coinbase.com/rpc/v1/base-sepolia/fsDbwDOLzfzHE6dxxdphhGPIjoSCxtt2"
  ),
  entryPoint: entrypointAddress,
});
export const paymasterEip7677Client = createClient({
  chain: baseSepolia,
  transport: http("https://paymaster.base.org"),
}).extend(paymasterActionsEip7677(ENTRYPOINT_ADDRESS_V06));

export type Session = {
  account: Address;
  approval: Hex;
  signer: Hex;
  permissionContract: Address;
  permissionData: Hex;
  expiry: number; // unix seconds
  chainId: bigint;
  verifyingContract: Address;
};

export const sessionStruct = parseAbiParameter([
  "Session session",
  "struct Session { address account; uint256 chainId; bytes signer; uint40 expiry; address permissionContract; bytes permissionData; address verifyingContract; bytes approval; }",
]);

export function decodePermissionsContext(permissionsContext: Hex): {
  sessionManagerOwnerIndex: bigint;
  session: Session;
} {
  const [sessionManagerOwnerIndex, session] = decodeAbiParameters(
    [{ name: "sessionManagerOwnerIndex", type: "uint256" }, sessionStruct],
    permissionsContext
  );
  return { sessionManagerOwnerIndex, session };
}

// Hashable version of Session struct.
// 1. Removes `bytes approval`
// 2. Pre-hashes `bytes signer` into `bytes32 signerHash`
// 3. Pre-hashes `bytes permissionData` into `bytes32 permissionDataHash`
// export const sessionStructHashable = parseAbiParameter([
//   'SessionHashable sessionHashable',
//   'struct SessionHashable { address account; bytes32 signerHash; address permissionContract; bytes32 permissionDataHash; uint40 expiresAt; uint256 chainId; address verifyingContract; }',
// ]);
export const sessionStructHashable = parseAbiParameter([
  "SessionHashable sessionHashable",
  "struct SessionHashable { address account; uint256 chainId; bytes32 signerHash; uint40 expiry; address permissionContract; bytes32 permissionDataHash; address verifyingContract; }",
]);

// returns a bytes32 to sign, encodes session struct with approval stripped (later populated by signing over this hash)
export function hashSession(session: Session): Hex {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { approval, signer, permissionData, ...sessionHashable } = session;

  return keccak256(
    encodeAbiParameters(
      [sessionStructHashable],
      [
        {
          ...sessionHashable,
          signerHash: keccak256(signer),
          permissionDataHash: keccak256(permissionData),
        } as never,
      ]
    )
  );
}

export async function POST(r: Request) {
  const req = (await r.json()) as {
    method: "wallet_sendCalls" | "wallet_submitOp";
    params: {
      capabilities: {
        paymasterService: { url: string };
        permissions?: { context: Hex };
      };
      calls: { to: Address; data: Hex; value: Hex }[];
      from: Address;
      chainId: Hex;
    }[];
  };

  if (req.method === "wallet_sendCalls") {
    const { calls, capabilities, from } = req.params[0];
    // accumulate attempted spend from calls and insert new call to registerSpend
    let attemptedSpend = BigInt(0);
    for (const call of calls) {
      attemptedSpend += hexToBigInt(call.value ?? "0x0");
    }
    if (attemptedSpend > BigInt(0)) {
      const { session } = decodePermissionsContext(
        capabilities.permissions?.context!
      );
      const balance = await publicClient.getBalance({
        address: session.account,
      });
      const assertSpendCall = {
        to: session.permissionContract as Address,
        value: "0x0" as Hex,
        data: encodeFunctionData({
          abi: sessionCallPermissionAbi,
          functionName: "assertSpend",
          args: [
            balance - attemptedSpend, // enforce balance only decreases by accounted attempted spend for reentrancy protection
            hashSession(session),
            attemptedSpend,
          ],
        }),
      };
      calls.push(assertSpendCall);
    }

    let result;

    const callData = encodeFunctionData({
      abi: accountAbi,
      functionName: "executeBatch",
      args: [
        calls.map((call) => ({
          target: call.to as Address,
          data: call.data ?? "0x",
          value: hexToBigInt(call.value ?? "0x0"),
        })),
      ],
    });
    const nonce = await publicClient.readContract({
      address: entrypointAddress,
      abi: entrypointAbi,
      functionName: "getNonce",
      args: [from, BigInt(0)],
    });
    const maxFeePerGas = await publicClient.getGasPrice();
    const maxPriorityFeePerGas =
      await publicClient.estimateMaxPriorityFeePerGas();

    const gasEstimates = await bundlerClient.estimateUserOperationGas({
      userOperation: {
        sender: from,
        nonce,
        maxFeePerGas,
        maxPriorityFeePerGas,
        callData: callData,
        initCode: "0x",
        signature: DUMMY_SIGNATURE,
        paymasterAndData: "0x",
      },
    });

    const userOpToSign: UserOperation<"v0.6"> = {
      sender: from,
      nonce,
      maxFeePerGas: maxFeePerGas * BigInt(2),
      maxPriorityFeePerGas: maxPriorityFeePerGas * BigInt(2),
      callData: callData,
      initCode: "0x",
      paymasterAndData: "0x",
      preVerificationGas: gasEstimates.preVerificationGas * BigInt(5),
      verificationGasLimit: gasEstimates.verificationGasLimit * BigInt(10),
      callGasLimit: gasEstimates.callGasLimit * BigInt(5),
      signature: DUMMY_SIGNATURE,
    };

    const pmData = (
      await paymasterEip7677Client.getPaymasterData({
        userOperation: userOpToSign,
        context: {},
      })
    ).paymasterAndData;

    console.log("pmData", pmData);

    const opWithPm = { ...userOpToSign, paymasterAndData: pmData };

    const userOpHash = await publicClient.readContract({
      address: entrypointAddress,
      abi: entrypointAbi,
      functionName: "getUserOpHash",
      args: [opWithPm],
    });
    const base64UserOpHash = base64urlnopad.encode(hexToBytes(userOpHash));
    return Response.json({
      result: {
        userOp: deepHexlify(opWithPm),
        hash: userOpHash,
        base64Hash: base64UserOpHash,
      },
    });
  } else {
    const { userOp } = req.params;
    const bigIntOp = {
      ...userOp,
      nonce: hexToBigInt(userOp.nonce),
      maxFeePerGas: hexToBigInt(userOp.maxFeePerGas),
      maxPriorityFeePerGas: hexToBigInt(userOp.maxPriorityFeePerGas),
      preVerificationGas: hexToBigInt(userOp.preVerificationGas),
      verificationGasLimit: hexToBigInt(userOp.verificationGasLimit),
      callGasLimit: hexToBigInt(userOp.callGasLimit),
    };
    await bundlerClient.sendUserOperation({ userOperation: bigIntOp });
    return Response.json({ result: "ok" });
  }
}
