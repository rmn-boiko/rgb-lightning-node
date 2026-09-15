/**
 * JSON schemas for the wallet routes. Strict responses
 * (additionalProperties: false) strip anything undeclared — nothing from the
 * rgb-lib layer reaches a client unless declared here (I1 backstop).
 */
import { errorBodySchema } from './index.js';

const balanceSchema = {
  type: 'object',
  properties: {
    settled: { type: 'number' },
    future: { type: 'number' },
    spendable: { type: 'number' },
  },
  required: ['settled', 'future', 'spendable'],
  additionalProperties: false,
} as const;

/** Base58 account xpub (tpub/xpub/vpub...); length bounds, not full checksum. */
const xpubPattern = '^[a-zA-Z0-9]{100,120}$';

export const registerXpubsRouteSchema = {
  body: {
    type: 'object',
    properties: {
      vanilla: { type: 'string', pattern: xpubPattern },
      colored: { type: 'string', pattern: xpubPattern },
      fingerprint: { type: 'string', pattern: '^[0-9a-f]{8}$' },
    },
    required: ['vanilla', 'colored', 'fingerprint'],
    additionalProperties: false,
  },
  response: {
    201: {
      type: 'object',
      properties: {
        fingerprint: { type: 'string' },
        address: { type: 'string' },
      },
      required: ['fingerprint', 'address'],
      additionalProperties: false,
    },
    400: errorBodySchema,
    401: errorBodySchema,
    409: errorBodySchema,
  },
} as const;

export const walletAddressRouteSchema = {
  response: {
    200: {
      type: 'object',
      properties: { address: { type: 'string' } },
      required: ['address'],
      additionalProperties: false,
    },
    401: errorBodySchema,
    404: errorBodySchema,
  },
} as const;

export const walletBalancesRouteSchema = {
  response: {
    200: {
      type: 'object',
      properties: {
        btc: {
          type: 'object',
          properties: { vanilla: balanceSchema, colored: balanceSchema },
          required: ['vanilla', 'colored'],
          additionalProperties: false,
        },
        assets: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              assetId: { type: 'string' },
              schema: { type: 'string' },
              ticker: { type: ['string', 'null'] },
              name: { type: 'string' },
              precision: { type: 'integer' },
              balance: balanceSchema,
            },
            required: ['assetId', 'schema', 'ticker', 'name', 'precision', 'balance'],
            additionalProperties: false,
          },
        },
      },
      required: ['btc', 'assets'],
      additionalProperties: false,
    },
    401: errorBodySchema,
    404: errorBodySchema,
  },
} as const;

export const walletUnspentsRouteSchema = {
  response: {
    200: {
      type: 'object',
      properties: {
        unspents: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              txid: { type: 'string' },
              vout: { type: 'integer' },
              amountSat: { type: 'number' },
              colorable: { type: 'boolean' },
              allocations: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    assetId: { type: ['string', 'null'] },
                    amount: { type: ['number', 'null'] },
                    settled: { type: 'boolean' },
                  },
                  required: ['assetId', 'amount', 'settled'],
                  additionalProperties: false,
                },
              },
            },
            required: ['txid', 'vout', 'amountSat', 'colorable', 'allocations'],
            additionalProperties: false,
          },
        },
      },
      required: ['unspents'],
      additionalProperties: false,
    },
    401: errorBodySchema,
    404: errorBodySchema,
  },
} as const;

export const walletTransfersRouteSchema = {
  querystring: {
    type: 'object',
    properties: { assetId: { type: 'string', minLength: 1 } },
    additionalProperties: false,
  },
  response: {
    200: {
      type: 'object',
      properties: {
        transfers: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              idx: { type: 'integer' },
              assetId: { type: ['string', 'null'] },
              amount: { type: ['number', 'null'] },
              kind: { type: 'string' },
              status: { type: 'string' },
              txid: { type: ['string', 'null'] },
              recipientId: { type: ['string', 'null'] },
              expiration: { type: ['number', 'null'] },
              createdAt: { type: 'number' },
              updatedAt: { type: 'number' },
            },
            required: [
              'idx',
              'assetId',
              'amount',
              'kind',
              'status',
              'txid',
              'recipientId',
              'expiration',
              'createdAt',
              'updatedAt',
            ],
            additionalProperties: false,
          },
        },
      },
      required: ['transfers'],
      additionalProperties: false,
    },
    401: errorBodySchema,
    404: errorBodySchema,
  },
} as const;

export const walletReceiveRouteSchema = {
  body: {
    type: 'object',
    properties: {
      mode: { type: 'string', enum: ['blind', 'witness'] },
      assetId: { type: 'string', minLength: 1 },
      // Integer for the same reason as sendAssetPrepareRouteSchema: rgb-lib
      // deserializes a fungible assignment into a u64.
      amount: { type: 'integer', minimum: 1 },
      durationSeconds: { type: 'integer', minimum: 60, maximum: 2_592_000 },
      minConfirmations: { type: 'integer', minimum: 0, maximum: 100 },
    },
    required: ['mode'],
    additionalProperties: false,
  },
  response: {
    201: {
      type: 'object',
      properties: {
        invoice: { type: 'string' },
        recipientId: { type: 'string' },
        expirationTimestamp: { type: ['number', 'null'] },
        mode: { type: 'string', enum: ['blind', 'witness'] },
      },
      required: ['invoice', 'recipientId', 'expirationTimestamp', 'mode'],
      additionalProperties: false,
    },
    400: errorBodySchema,
    401: errorBodySchema,
    404: errorBodySchema,
  },
} as const;

export const walletSyncRouteSchema = {
  response: {
    200: {
      type: 'object',
      properties: { status: { type: 'string', enum: ['ok'] } },
      required: ['status'],
      additionalProperties: false,
    },
    401: errorBodySchema,
    404: errorBodySchema,
  },
} as const;
