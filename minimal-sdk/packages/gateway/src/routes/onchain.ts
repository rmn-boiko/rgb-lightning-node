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
