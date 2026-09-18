/**
 * On-chain prepare/complete routes: server prepares, client signs, server
 * completes. All money-moving, so every route requires an Idempotency-Key;
 * auth runs onRequest (before body parsing) and all downstream work goes
 * through the per-user FIFO queue.
 */
import type { FastifyInstance, FastifySchema } from 'fastify';
import {
  createUtxosCompleteRouteSchema,
  createUtxosPrepareRouteSchema,
  operationGetRouteSchema,
  sendAssetCompleteRouteSchema,
  sendAssetPrepareRouteSchema,
  sendBtcCompleteRouteSchema,
  sendBtcPrepareRouteSchema,
} from '../schemas/onchain.js';
import type {
  OnchainOpKind,
  PrepareCreateUtxosParams,
  PrepareSendAssetParams,
  PrepareSendBtcParams,
} from '../wallets/prepare.js';

interface CompleteBody {
  opId: string;
  signedPsbt: string;
}

export function registerOnchainRoutes(app: FastifyInstance): void {
  const routeOptions = (schema: FastifySchema) => ({
    schema,
    onRequest: [app.authenticate],
    preHandler: [app.idempotency.preHandler],
    onSend: app.idempotency.onSend,
  });

  const completeRoute = (url: string, schema: FastifySchema, kind: OnchainOpKind): void => {
    app.post(url, routeOptions(schema), (request) => {
      const userId = request.userId as string;
      const { opId, signedPsbt } = request.body as CompleteBody;
      return app.queues.enqueue(userId, async () => {
        const { txid, utxosCreated } = await app.onchain.complete(userId, kind, opId, signedPsbt);
        return kind === 'create_utxos' ? { txid, utxosCreated } : { txid };
      });
    });
  };

  // Read-only recovery route: the outcome of `complete` can be lost to a
  // timeout, a crash, or the 502 COMPLETE_AMBIGUOUS that rgb-lib's
  // broadcast-before-bookkeeping ordering makes possible, and the txid is
  // recorded on the op in exactly that case. Deliberately NOT on the per-user
  // queue and with no Idempotency-Key: it is a single SQLite read, and queueing
  // it behind the very wallet call that is stuck would make it unavailable
  // precisely when a client needs it.
  app.get(
    '/v1/onchain/operations/:opId',
    { schema: operationGetRouteSchema, onRequest: [app.authenticate] },
    (request) => {
      const userId = request.userId as string;
      const { opId } = request.params as { opId: string };
      return app.onchain.getOperation(userId, opId);
    },
  );

  app.post(
    '/v1/onchain/send-btc/prepare',
    routeOptions(sendBtcPrepareRouteSchema),
    (request, reply) => {
      const userId = request.userId as string;
      const params = request.body as PrepareSendBtcParams;
      return app.queues.enqueue(userId, async () => {
        const prepared = await app.onchain.prepareSendBtc(userId, params);
        return reply.code(201).send(prepared);
      });
    },
  );
  completeRoute('/v1/onchain/send-btc/complete', sendBtcCompleteRouteSchema, 'send_btc');

  app.post(
    '/v1/onchain/send-asset/prepare',
    routeOptions(sendAssetPrepareRouteSchema),
    (request, reply) => {
      const userId = request.userId as string;
      const params = request.body as PrepareSendAssetParams;
      return app.queues.enqueue(userId, async () => {
        const prepared = await app.onchain.prepareSendAsset(userId, params);
        return reply.code(201).send(prepared);
      });
    },
  );
  completeRoute('/v1/onchain/send-asset/complete', sendAssetCompleteRouteSchema, 'send_asset');

  app.post(
    '/v1/onchain/create-utxos/prepare',
    routeOptions(createUtxosPrepareRouteSchema),
    (request, reply) => {
      const userId = request.userId as string;
      const params = request.body as PrepareCreateUtxosParams;
      return app.queues.enqueue(userId, async () => {
        const prepared = await app.onchain.prepareCreateUtxos(userId, params);
        return reply.code(201).send(prepared);
      });
    },
  );
  completeRoute(
    '/v1/onchain/create-utxos/complete',
    createUtxosCompleteRouteSchema,
    'create_utxos',
  );
}
