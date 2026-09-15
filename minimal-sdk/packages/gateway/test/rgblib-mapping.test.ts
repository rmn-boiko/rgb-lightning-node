/**
 * Unit tests for the pure marshalling layer of the native rgb-lib backend:
 * error classification (which decides 400 INSUFFICIENT_FUNDS vs opaque 500)
 * and the camelCase JSON → gateway-shape mappers. No native module needed —
 * loadNativeRgbLib() is lazy and never called here.
 */
import { describe, expect, it } from 'vitest';
import {
  mapAssets,
  mapTransfers,
  mapUnspents,
  unquote,
  wrapNativeError,
} from '../src/wallets/rgblib.js';

describe('wrapNativeError', () => {
  it.each([
    'RgbLib(InsufficientBitcoins { needed: 15000, available: 4000 })',
    'RgbLib(InsufficientAllocationSlots)',
    'RgbLib(InsufficientSpendableAssets { asset_id: "rgb:abc" })',
    'RgbLib(InsufficientTotalAssets { asset_id: "rgb:abc" })',
  ])('classifies %s as insufficient funds', (detail) => {
    const wrapped = wrapNativeError('sendBtcBegin', new Error(detail));
    expect(wrapped.insufficientFunds).toBe(true);
    expect(wrapped.message).toBe('wallet sendBtcBegin failed');
    expect(wrapped.detail).toContain(detail);
  });

  it.each([
    'RgbLib(InvalidAddress { details: "bad checksum" })',
    'RgbLib(InvalidRecipientID)',
    'RgbLib(InvalidRecipientNetwork)',
    'RgbLib(InvalidRecipientData { details: "witness data on a blind recipient" })',
    'RgbLib(AssetNotFound { asset_id: "rgb:abc" })',
    'RgbLib(InvalidTransportEndpoint { details: "bad scheme" })',
    'RgbLib(RecipientIDDuplicated)',
    'RgbLib(InvalidFeeRate { details: "below minimum" })',
  ])('classifies %s as a client error, not insufficient funds', (detail) => {
    const wrapped = wrapNativeError('sendAssetBegin', new Error(detail));
    expect(wrapped.insufficientFunds).toBe(false);
    expect(wrapped.clientError).toBe(true);
  });

  it.each([
    'RgbLib(Internal { details: "stash corrupted" })',
    'RgbLib(FailedBdkSync { details: "indexer unreachable" })',
    'RgbLib(Electrum { details: "connection reset" })',
  ])('leaves %s unclassified so it surfaces as a server error', (detail) => {
    const wrapped = wrapNativeError('sync', new Error(detail));
    expect(wrapped.insufficientFunds).toBe(false);
    expect(wrapped.clientError).toBe(false);
  });

  it('stringifies non-Error throwables into the detail', () => {
    const wrapped = wrapNativeError('sync', 'plain-string failure');
    expect(wrapped.detail).toBe('plain-string failure');
    expect(wrapped.insufficientFunds).toBe(false);
    expect(wrapped.clientError).toBe(false);
  });
});

describe('unquote', () => {
  it('strips JSON string quoting', () => {
    expect(unquote('"cHNidP8BAA=="')).toBe('cHNidP8BAA==');
  });

  it('passes through unquoted and malformed values unchanged', () => {
    expect(unquote('cHNidP8BAA==')).toBe('cHNidP8BAA==');
    expect(unquote('"unterminated')).toBe('"unterminated');
  });
});

describe('mapAssets', () => {
  it('flattens the per-schema camelCase asset map', () => {
    const raw = {
      nia: [
        {
          assetId: 'rgb:asset-1',
          ticker: 'TST',
          name: 'Test Asset',
          precision: 0,
          balance: { settled: 100, future: 100, spendable: 100 },
        },
      ],
      cfa: [
        // No assetId → dropped rather than emitted half-formed.
        { ticker: 'BAD', name: 'No Id', precision: 0 },
      ],
      uda: null,
    };
    expect(mapAssets(raw)).toEqual([
      {
        assetId: 'rgb:asset-1',
        schema: 'nia',
        ticker: 'TST',
        name: 'Test Asset',
        precision: 0,
        balance: { settled: 100, future: 100, spendable: 100 },
      },
    ]);
  });

  it('returns an empty list for a non-object payload', () => {
    expect(mapAssets(null)).toEqual([]);
    expect(mapAssets('garbage')).toEqual([]);
  });
});

describe('mapUnspents', () => {
  it('maps utxos with their rgb allocations', () => {
    const raw = [
      {
        utxo: {
          outpoint: { txid: 'txid-1', vout: 2 },
          btcAmount: 998,
          colorable: true,
        },
        rgbAllocations: [
          { assetId: 'rgb:asset-1', assignment: { Fungible: 42 }, settled: true },
          { assetId: null, assignment: 'Any', settled: false },
        ],
      },
    ];
    expect(mapUnspents(raw)).toEqual([
      {
        txid: 'txid-1',
        vout: 2,
        amountSat: 998,
        colorable: true,
        allocations: [
          { assetId: 'rgb:asset-1', amount: 42, settled: true },
          { assetId: null, amount: null, settled: false },
        ],
      },
    ]);
  });

  it('returns an empty list for a non-array payload', () => {
    expect(mapUnspents({ not: 'an array' })).toEqual([]);
  });
});

describe('mapTransfers', () => {
  it('prefers the requested assignment amount and falls back to summed assignments', () => {
    const raw = [
      {
        idx: 1,
        requestedAssignment: { Fungible: 50 },
        assignments: [],
        kind: 'ReceiveBlind',
        status: 'Settled',
        txid: 'txid-1',
        recipientId: 'utxob:recipient',
        expiration: 1_700_000_000,
        createdAt: 1,
        updatedAt: 2,
      },
      {
        idx: 2,
        requestedAssignment: null,
        assignments: [{ Fungible: 10 }, { Fungible: 15 }, 'Any'],
        kind: 'Send',
        status: 'WaitingConfirmations',
        txid: null,
        recipientId: null,
        expiration: null,
        createdAt: 3,
        updatedAt: 4,
      },
    ];
    const mapped = mapTransfers(raw, 'rgb:asset-1');
    expect(mapped).toEqual([
      {
        idx: 1,
        assetId: 'rgb:asset-1',
        amount: 50,
        kind: 'ReceiveBlind',
        status: 'Settled',
        txid: 'txid-1',
        recipientId: 'utxob:recipient',
        expiration: 1_700_000_000,
        createdAt: 1,
        updatedAt: 2,
      },
      {
        idx: 2,
        assetId: 'rgb:asset-1',
        amount: 25,
        kind: 'Send',
        status: 'WaitingConfirmations',
        txid: null,
        recipientId: null,
        expiration: null,
        createdAt: 3,
        updatedAt: 4,
      },
    ]);
  });

  it('defaults missing fields instead of throwing on shape drift', () => {
    const mapped = mapTransfers([{}], null);
    expect(mapped).toEqual([
      {
        idx: 0,
        assetId: null,
        amount: null,
        kind: 'Unknown',
        status: 'Unknown',
        txid: null,
        recipientId: null,
        expiration: null,
        createdAt: 0,
        updatedAt: 0,
      },
    ]);
  });
});
