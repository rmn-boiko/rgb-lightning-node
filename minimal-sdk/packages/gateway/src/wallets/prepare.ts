/**
 * On-chain prepare/complete flows: the server prepares an unsigned PSBT on the
 * user's watch-only wallet, the client verifies and signs it externally, the
 * server completes (finalize + broadcast via rgb-lib).
 *
 * Every prepare records a pending operation with a TTL so an unsigned PSBT
 * expires, and returns a machine-readable intent summary built from the
 * gateway's OWN inputs (request fields + config) — never echoed from RLN or
 * parsed back out of the PSBT — for the client's verify-before-sign checks.
 */
import { randomUUID } from 'node:crypto';
import { base64, hex } from '@scure/base';
import { Address, OutScript, Transaction } from '@scure/btc-signer';
import type { GatewayConfig } from '../config.js';
import type { GatewayDb } from '../db.js';
import { HttpError } from '../errors.js';
import { recordOwnership } from '../rln/scoping.js';
import {
  WalletBackendError,
  walletHttpError,
  type WalletHandle,
  type WalletIdentity,
} from './backend.js';
import type { WalletPool } from './pool.js';
import type { WalletService } from './service.js';

export type OnchainOpKind = 'send_btc' | 'send_asset' | 'create_utxos';

export interface IntentRecipient {
  address: string;
  scriptHex: string;
  amountSat: number;
}

export interface IntentAsset {
  assetId: string;
  amount: number;
  recipientId: string;
  witnessAmountSat: number | null;
  transportEndpoints: string[];
}

export interface IntentUtxos {
  upTo: boolean;
  num: number;
  size: number;
}

/** What the client verifies the PSBT against before signing (design doc, 5 checks). */
export interface OnchainIntent {
  kind: OnchainOpKind;
  feeRateSatPerVb: number;
  recipients: IntentRecipient[];
  asset: IntentAsset | null;
  utxos: IntentUtxos | null;
}

export interface PreparedOp {
  opId: string;
  psbt: string;
  intent: OnchainIntent;
  /** Unix milliseconds; completion after this fails with 410 OP_EXPIRED. */
  expiresAt: number;
}

export interface CompletedOp {
  /** Broadcast txid; null only for create-utxos when the PSBT is unparsable. */
  txid: string | null;
  /** Only set for create-utxos completions. */
  utxosCreated: number | null;
}

export interface PrepareSendBtcParams {
  address: string;
  amountSat: number;
  feeRateSatPerVb?: number | undefined;
}

export interface PrepareSendAssetParams {
  assetId: string;
  amount: number;
  recipientId: string;
  witnessAmountSat?: number | undefined;
  transportEndpoints?: string[] | undefined;
  donation?: boolean | undefined;
  minConfirmations?: number | undefined;
  feeRateSatPerVb?: number | undefined;
}

export interface PrepareCreateUtxosParams {
  num?: number | undefined;
  size?: number | undefined;
  upTo?: boolean | undefined;
  feeRateSatPerVb?: number | undefined;
}

const DEFAULT_FEE_RATE_SAT_PER_VB = 2;
const DEFAULT_UTXO_NUM = 5;
const DEFAULT_UTXO_SIZE = 1000;
const DEFAULT_MIN_CONFIRMATIONS = 1;

/** Address version bytes / bech32 prefixes per rgb-lib BitcoinNetwork. */
const ADDRESS_NETWORKS: Record<
  GatewayConfig['bitcoinNetwork'],
  { bech32: string; pubKeyHash: number; scriptHash: number; wif: number }
> = {
  Mainnet: { bech32: 'bc', pubKeyHash: 0x00, scriptHash: 0x05, wif: 0x80 },
  Testnet: { bech32: 'tb', pubKeyHash: 0x6f, scriptHash: 0xc4, wif: 0xef },
  Signet: { bech32: 'tb', pubKeyHash: 0x6f, scriptHash: 0xc4, wif: 0xef },
  Regtest: { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4, wif: 0xef },
};

/**
 * Decode a recipient address to its output script (hex) for the intent
 * summary; throws 400 INVALID_ADDRESS on garbage or a wrong-network address.
 */
export function addressToScriptHex(
  address: string,
  network: GatewayConfig['bitcoinNetwork'],
): string {
  try {
    const decoded = Address(ADDRESS_NETWORKS[network]).decode(address);
    return hex.encode(OutScript.encode(decoded));
  } catch {
    throw new HttpError(400, 'INVALID_ADDRESS', `not a valid ${network} bitcoin address`);
  }
}

/**
 * Txid of a (finalized or merely signed) PSBT. Witness data does not affect
 * the txid, so the unsigned tx inside the PSBT already determines it.
 */
export function txidFromPsbt(psbtBase64: string): string | null {
  try {
    const tx = Transaction.fromPSBT(base64.decode(psbtBase64), {
      allowUnknownInputs: true,
      allowUnknownOutputs: true,
    });
    return tx.id;
  } catch {
    return null;
  }
}

/**
 * rgb-lib failures that prove the transaction NEVER reached the network, so
 * blaming the signed PSBT is honest.
 *
 * `send_btc_end`/`create_utxos_end` broadcast FIRST and write their
 * bookkeeping after (`broadcast_psbt` -> BDK `persist` -> colored-txo/spent
 * updates -> `finalize_vanilla_wallet_transaction` -> `update_backup_info` ->
 * `commit`; rgb-lib `wallet/online.rs:89-118,315-322,3750-3754`,
 * `wallet/singlesig.rs:716-726,1103-1113`). Every one of those post-broadcast
 * failure points surfaces as an unclassified `Database`/`IO`/`Internal`
 * error for a transaction that is already on the network — the same hazard
 * the LN withdraw path handles by refusing to treat a 5xx as a rejection.
 * Calling those PSBT_REJECTED would tell the user their signature was bad
 * about money that actually moved, cache that 400 under their idempotency key
 * (4xx is not retryable in `idempotency.onSend`), and leave no server-side
 * trace, since the central handler logs only 5xx-or-caused errors.
 *
 * A broadcast the indexer refused is `FailedBroadcast`, raised only after
 * rgb-lib re-checks that the txid has no confirmations (`online.rs:79-84`) —
 * so tampering, the case this mapping exists for, still lands on a clean 400.
 */
const PSBT_REJECTION_VARIANTS =
  /\b(FailedBroadcast|InvalidPsbt|CannotFinalizePsbt|CannotCombinePsbts)\b/;

interface PendingOpRow {
  id: string;
  user_id: string;
  kind: OnchainOpKind;
  psbt: string;
  intent: string;
  state: 'pending' | 'completed' | 'expired';
  txid: string | null;
  expires_at: number;
}

export class OnchainService {
  constructor(
    private readonly db: GatewayDb,
    private readonly pool: WalletPool,
    private readonly wallets: WalletService,
    private readonly config: GatewayConfig,
  ) {}

  private async run<T>(
    identity: WalletIdentity,
    fn: (wallet: WalletHandle) => Promise<T>,
  ): Promise<T> {
    try {
      return await this.pool.withWallet(identity, fn);
    } catch (error) {
      throw walletHttpError(error);
    }
  }

  private storePrepared(
    userId: string,
    kind: OnchainOpKind,
    psbt: string,
    intent: OnchainIntent,
    now: number,
  ): PreparedOp {
    // Lazy hygiene: retire this user's stale unsigned ops on every prepare.
    this.db
      .prepare(
        `UPDATE pending_ops SET state = 'expired'
         WHERE user_id = ? AND state = 'pending' AND expires_at <= ?`,
      )
      .run(userId, now);
    const opId = randomUUID();
    const expiresAt = now + this.config.onchainOpTtlSeconds * 1000;
    this.db
      .prepare(
        `INSERT INTO pending_ops (id, user_id, kind, psbt, intent, state, txid, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, 'pending', NULL, ?, ?)`,
      )
      .run(opId, userId, kind, psbt, JSON.stringify(intent), now, expiresAt);
    return { opId, psbt, intent, expiresAt };
  }

  async prepareSendBtc(
    userId: string,
    params: PrepareSendBtcParams,
    now: number = Date.now(),
  ): Promise<PreparedOp> {
    const identity = this.wallets.identityOf(userId);
    const feeRateSatPerVb = params.feeRateSatPerVb ?? DEFAULT_FEE_RATE_SAT_PER_VB;
    const scriptHex = addressToScriptHex(params.address, this.config.bitcoinNetwork);
    const psbt = await this.run(identity, (wallet) =>
      wallet.sendBtcBegin(params.address, params.amountSat, feeRateSatPerVb),
    );
    const intent: OnchainIntent = {
      kind: 'send_btc',
      feeRateSatPerVb,
      recipients: [{ address: params.address, scriptHex, amountSat: params.amountSat }],
      asset: null,
      utxos: null,
    };
    return this.storePrepared(userId, 'send_btc', psbt, intent, now);
  }

  async prepareSendAsset(
    userId: string,
    params: PrepareSendAssetParams,
    now: number = Date.now(),
  ): Promise<PreparedOp> {
    const identity = this.wallets.identityOf(userId);
    const feeRateSatPerVb = params.feeRateSatPerVb ?? DEFAULT_FEE_RATE_SAT_PER_VB;
    // Consignment endpoints make the wallet dial out (SSRF guard): only
    // operator-allowlisted proxies are accepted — explicit error, no fallback.
    const transportEndpoints = params.transportEndpoints ?? [this.config.rgbProxyUrl];
    const denied = transportEndpoints.filter(
      (endpoint) => !this.config.rgbTransportAllowlist.includes(endpoint),
    );
    if (denied.length > 0) {
      throw new HttpError(
        400,
        'TRANSPORT_ENDPOINT_NOT_ALLOWED',
        'transportEndpoints must be on the operator allowlist',
      );
    }
    const witnessAmountSat = params.witnessAmountSat ?? null;
    const expiresAtSeconds = Math.floor((now + this.config.onchainOpTtlSeconds * 1000) / 1000);
    const psbt = await this.run(identity, (wallet) =>
      wallet.sendAssetBegin({
        assetId: params.assetId,
        recipientId: params.recipientId,
        amount: params.amount,
        witnessAmountSat,
        transportEndpoints,
        donation: params.donation ?? false,
        feeRateSatPerVb,
        minConfirmations: params.minConfirmations ?? DEFAULT_MIN_CONFIRMATIONS,
        // Wallet-side pending transfer expires together with the op.
        expirationTimestamp: expiresAtSeconds,
      }),
    );
    const intent: OnchainIntent = {
      kind: 'send_asset',
      feeRateSatPerVb,
      recipients: [],
      asset: {
        assetId: params.assetId,
        amount: params.amount,
        recipientId: params.recipientId,
        witnessAmountSat,
        transportEndpoints,
      },
      utxos: null,
    };
    return this.storePrepared(userId, 'send_asset', psbt, intent, now);
  }

  async prepareCreateUtxos(
    userId: string,
    params: PrepareCreateUtxosParams,
    now: number = Date.now(),
  ): Promise<PreparedOp> {
    const identity = this.wallets.identityOf(userId);
    const feeRateSatPerVb = params.feeRateSatPerVb ?? DEFAULT_FEE_RATE_SAT_PER_VB;
    const utxos: IntentUtxos = {
      upTo: params.upTo ?? false,
      num: params.num ?? DEFAULT_UTXO_NUM,
      size: params.size ?? DEFAULT_UTXO_SIZE,
    };
    const psbt = await this.run(identity, (wallet) =>
      wallet.createUtxosBegin({ ...utxos, feeRateSatPerVb }),
    );
    const intent: OnchainIntent = {
      kind: 'create_utxos',
      feeRateSatPerVb,
      recipients: [],
      asset: null,
      utxos,
    };
    return this.storePrepared(userId, 'create_utxos', psbt, intent, now);
  }

  /**
   * Complete a prepared op with the client-signed PSBT: rgb-lib finalizes and
   * broadcasts. A rejected PSBT (tampering, missing signature) surfaces as a
   * clean 400 and the op stays pending until its TTL — the client may retry
   * with a fresh Idempotency-Key and a correctly signed PSBT. A wallet failure
   * that cannot be pinned on the PSBT is reported as an ambiguous 502 instead,
   * because rgb-lib broadcasts before it finishes its bookkeeping.
   */
  async complete(
    userId: string,
    kind: OnchainOpKind,
    opId: string,
    signedPsbt: string,
    now: number = Date.now(),
  ): Promise<CompletedOp> {
    const identity = this.wallets.identityOf(userId);
    const row = this.db.prepare('SELECT * FROM pending_ops WHERE id = ?').get(opId) as
      PendingOpRow | undefined;
    // A foreign user's op is indistinguishable from a missing one (I3).
    if (row === undefined || row.user_id !== userId) {
      throw new HttpError(404, 'OP_NOT_FOUND', 'no such prepared operation');
    }
    if (row.kind !== kind) {
      throw new HttpError(409, 'OP_KIND_MISMATCH', 'operation was prepared for a different flow');
    }
    if (row.state === 'completed') {
      throw new HttpError(409, 'OP_ALREADY_COMPLETED', 'operation was already completed');
    }
    if (row.state === 'expired' || row.expires_at <= now) {
      this.db.prepare(`UPDATE pending_ops SET state = 'expired' WHERE id = ?`).run(opId);
      throw new HttpError(410, 'OP_EXPIRED', 'prepared operation expired; prepare again');
    }
    // Bind the signed PSBT to THIS op: signatures do not change the txid, so a
    // signed PSBT for a different prepared transaction must be rejected —
    // otherwise this op's bookkeeping (intent, txid, transfer ownership) would
    // describe a transaction that never broadcast. rgb-lib prepared PSBTs
    // always parse; whenever the prepared side does, an unparsable or
    // different-txid signed PSBT is a hard 400 — never a silently skipped
    // check. (An unparsable PREPARED psbt only occurs with mock backends; a
    // client could not have verified or signed it anyway.)
    const preparedTxid = txidFromPsbt(row.psbt);
    const signedTxid = txidFromPsbt(signedPsbt);
    if (preparedTxid !== null && preparedTxid !== signedTxid) {
      throw new HttpError(
        400,
        'PSBT_MISMATCH',
        'the signed PSBT does not correspond to this prepared operation',
      );
    }

    let txid: string | null = null;
    let utxosCreated: number | null = null;
    try {
      await this.pool.withWallet(identity, async (wallet) => {
        if (kind === 'send_btc') {
          txid = await wallet.sendBtcEnd(signedPsbt);
        } else if (kind === 'send_asset') {
          txid = await wallet.sendAssetEnd(signedPsbt);
        } else {
          utxosCreated = await wallet.createUtxosEnd(signedPsbt);
          txid = txidFromPsbt(signedPsbt);
        }
      });
    } catch (error) {
      if (error instanceof WalletBackendError) {
        if (error.insufficientFunds) {
          throw new HttpError(400, 'INSUFFICIENT_FUNDS', 'operation no longer affordable', {
            cause: error,
          });
        }
        if (error.clientError || PSBT_REJECTION_VARIANTS.test(error.detail)) {
          throw new HttpError(
            400,
            'PSBT_REJECTED',
            'the signed PSBT was rejected (bad signature, tampering, or mismatch with the prepared transaction)',
            { cause: error },
          );
        }
        // Ambiguous: the transaction may already be on the network. Record the
        // txid so an operator can resolve it, leave the op pending, and answer
        // 5xx — logged by the central handler, retryable in the idempotency
        // middleware. Retrying `complete` is the recovery path and is safe:
        // rebroadcasting a transaction the indexer already knows succeeds
        // (rgb-lib `online.rs:79-84`), so the retry just redoes the
        // bookkeeping that failed here.
        this.db
          .prepare(`UPDATE pending_ops SET txid = ? WHERE id = ? AND state = 'pending'`)
          .run(signedTxid, opId);
        throw new HttpError(
          502,
          'COMPLETE_AMBIGUOUS',
          'the wallet failed after the transaction may have been broadcast; retry this operation',
          { cause: error },
        );
      }
      throw error;
    }

    this.db
      .prepare(`UPDATE pending_ops SET state = 'completed', txid = ? WHERE id = ?`)
      .run(txid, opId);
    if (kind === 'send_asset' && txid !== null) {
      recordOwnership(
        this.db,
        { kind: 'asset_transfer', resourceId: txid, userId, state: 'sent' },
        now,
      );
    }
    return { txid, utxosCreated };
  }
}
