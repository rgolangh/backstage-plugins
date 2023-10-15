import {
  ConflictError,
  InputError,
  NotAllowedError,
  NotFoundError,
} from '@backstage/errors';
import {
  getBearerTokenFromAuthorizationHeader,
  IdentityApi,
} from '@backstage/plugin-auth-node';
import {
  createRouter,
  RouterOptions,
} from '@backstage/plugin-permission-backend';
import {
  AuthorizeResult,
  ConditionalPolicyDecision,
  PermissionEvaluator,
  QueryPermissionRequest,
} from '@backstage/plugin-permission-common';
import { createPermissionIntegrationRouter } from '@backstage/plugin-permission-node';

import { Enforcer } from 'casbin';
import { Router } from 'express';
import { Request } from 'express-serve-static-core';
import { isEqual } from 'lodash';
import { ParsedQs } from 'qs';

import {
  EntityReferencedPolicy,
  policyEntityCreatePermission,
  policyEntityDeletePermission,
  policyEntityPermissions,
  policyEntityReadPermission,
  policyEntityUpdatePermission,
  RESOURCE_TYPE_POLICY_ENTITY,
} from '@janus-idp/backstage-plugin-rbac-common';

import { ConditionalStorage } from '../database/conditional-storage';
import {
  validateEntityReference,
  validatePolicy,
  validatePolicyQueries,
} from './policies-validation';

export class PolicesServer {
  constructor(
    private readonly identity: IdentityApi,
    private readonly permissions: PermissionEvaluator,
    private readonly options: RouterOptions,
    private readonly enforcer: Enforcer,
    private readonly conditionalStorage: ConditionalStorage,
  ) {}

  private async authorize(
    identity: IdentityApi,
    request: Request,
    permissionEvaluator: PermissionEvaluator,
    permission: QueryPermissionRequest,
  ) {
    const user = await identity.getIdentity({ request });
    if (!user) {
      throw new NotAllowedError();
    }

    const authHeader = request.header('authorization');
    const token = getBearerTokenFromAuthorizationHeader(authHeader);

    const decision = (
      await permissionEvaluator.authorizeConditional([permission], { token })
    )[0];

    return decision;
  }

  async serve(): Promise<Router> {
    const router = await createRouter(this.options);
    const permissionsIntegrationRouter = createPermissionIntegrationRouter({
      resourceType: RESOURCE_TYPE_POLICY_ENTITY,
      permissions: policyEntityPermissions,
    });

    router.use(permissionsIntegrationRouter);

    router.get('/', async (request, response) => {
      const decision = await this.authorize(
        this.identity,
        request,
        this.permissions,
        {
          permission: policyEntityReadPermission,
        },
      );

      if (decision.result === AuthorizeResult.DENY) {
        throw new NotAllowedError(); // 403
      }
      response.send({ status: 'Authorized' });
    });

    router.get('/policies', async (req, response) => {
      const decision = await this.authorize(
        this.identity,
        req,
        this.permissions,
        {
          permission: policyEntityReadPermission,
        },
      );

      if (decision.result === AuthorizeResult.DENY) {
        throw new NotAllowedError(); // 403
      }

      let policies: string[][];
      if (this.isPolicyFilterEnabled(req)) {
        const entityRef = this.getFirstQuery(req.query.entityRef);
        const permission = this.getFirstQuery(req.query.permission);
        const policy = this.getFirstQuery(req.query.policy);
        const effect = this.getFirstQuery(req.query.effect);

        const filter: string[] = [entityRef, permission, policy, effect];
        policies = await this.enforcer.getFilteredPolicy(0, ...filter);
      } else {
        policies = await this.enforcer.getPolicy();
      }

      response.json(this.transformPolicyArray(...policies));
    });

    router.get('/policies/:kind/:namespace/:name', async (req, response) => {
      const decision = await this.authorize(
        this.identity,
        req,
        this.permissions,
        {
          permission: policyEntityReadPermission,
        },
      );

      if (decision.result === AuthorizeResult.DENY) {
        throw new NotAllowedError(); // 403
      }

      const entityRef = this.getEntityReference(req);

      const policy = await this.enforcer.getFilteredPolicy(0, entityRef);
      if (policy.length !== 0) {
        response.json(this.transformPolicyArray(...policy));
      } else {
        throw new NotFoundError(); // 404
      }
    });

    router.delete(
      '/policies/:kind/:namespace/:name',
      async (request, response) => {
        const decision = await this.authorize(
          this.identity,
          request,
          this.permissions,
          {
            permission: policyEntityDeletePermission,
          },
        );

        if (decision.result === AuthorizeResult.DENY) {
          throw new NotAllowedError(); // 403
        }

        const entityRef = this.getEntityReference(request);

        const err = validatePolicyQueries(request);
        if (err) {
          throw new InputError( // 400
            `Invalid policy definition. Cause: ${err.message}`,
          );
        }

        const permission = this.getFirstQuery(request.query.permission!);
        const policy = this.getFirstQuery(request.query.policy!);
        const effect = this.getFirstQuery(request.query.effect!);

        const policyPermission = [entityRef, permission, policy, effect];

        if (!(await this.enforcer.hasPolicy(...policyPermission))) {
          throw new NotFoundError(); // 404
        }

        const isRemoved = await this.enforcer.removePolicy(...policyPermission);
        if (!isRemoved) {
          throw new Error('Unexpected error'); // 500
        }
        response.status(204).end();
      },
    );
    router.post('/policies', async (request, response) => {
      const decision = await this.authorize(
        this.identity,
        request,
        this.permissions,
        {
          permission: policyEntityCreatePermission,
        },
      );

      if (decision.result === AuthorizeResult.DENY) {
        throw new NotAllowedError(); // 403
      }

      const policyRaw: EntityReferencedPolicy = request.body;
      const err = validatePolicy(policyRaw);
      if (err) {
        throw new InputError( // 400
          `Invalid policy definition. Cause: ${err.message}`,
        );
      }

      const policy = this.transformPolicyToArray(policyRaw);

      if (await this.enforcer.hasPolicy(...policy)) {
        throw new ConflictError(); // 409
      }

      const isAdded = await this.enforcer.addPolicy(...policy);
      if (!isAdded) {
        throw new Error('Unexpected error'); // 500
      }
      response.status(201).end();
    });

    router.put('/policies/:kind/:namespace/:name', async (req, resp) => {
      const decision = await this.authorize(
        this.identity,
        req,
        this.permissions,
        {
          permission: policyEntityUpdatePermission,
        },
      );

      if (decision.result === AuthorizeResult.DENY) {
        throw new NotAllowedError(); // 403
      }

      const entityRef = this.getEntityReference(req);

      const oldPolicyRaw = req.body.oldPolicy;
      if (!oldPolicyRaw) {
        throw new InputError(`'oldPolicy' object must be present`); // 400
      }
      const newPolicyRaw = req.body.newPolicy;
      if (!newPolicyRaw) {
        throw new InputError(`'newPolicy' object must be present`); // 400
      }

      oldPolicyRaw.entityReference = entityRef;
      let err = validatePolicy(oldPolicyRaw);
      if (err) {
        throw new InputError( // 400
          `Invalid old policy object. Cause: ${err.message}`,
        );
      }
      newPolicyRaw.entityReference = entityRef;
      err = validatePolicy(newPolicyRaw);
      if (err) {
        throw new InputError( // 400
          `Invalid new policy object. Cause: ${err.message}`,
        );
      }

      const oldPolicy = this.transformPolicyToArray(oldPolicyRaw);
      const newPolicy = this.transformPolicyToArray(newPolicyRaw);

      if (await this.enforcer.hasPolicy(...newPolicy)) {
        if (isEqual(oldPolicy, newPolicy)) {
          resp.status(204).end();
          return;
        }
        throw new ConflictError(); // 409
      }

      if (!(await this.enforcer.hasPolicy(...oldPolicy))) {
        throw new NotFoundError(); // 404
      }

      // enforcer.updatePolicy(oldPolicyPermission, newPolicyPermission) was not implemented
      // for ORMTypeAdapter.
      // So, let's compensate this combination delete + create.
      const isRemoved = await this.enforcer.removePolicy(...oldPolicy);
      if (!isRemoved) {
        throw new Error('Unexpected error'); // 500
      }

      const isAdded = await this.enforcer.addPolicy(...newPolicy);
      if (!isAdded) {
        throw new Error('Unexpected error');
      }

      resp.status(200).end();
    });

    router.get('/conditions', async (req, resp) => {
      const decision = await this.authorize(
        this.identity,
        req,
        this.permissions,
        {
          permission: policyEntityReadPermission,
        },
      );

      if (decision.result === AuthorizeResult.DENY) {
        throw new NotAllowedError(); // 403
      }

      const pluginId = this.getFirstQuery(req.query.pluginId);
      const resourceType = this.getFirstQuery(req.query.resourceType);
      const conditions = await this.conditionalStorage.getConditions(
        pluginId,
        resourceType,
      );

      resp.json(conditions);
    });

    router.post('/conditions', async (req, resp) => {
      const decision = await this.authorize(
        this.identity,
        req,
        this.permissions,
        {
          permission: policyEntityCreatePermission,
        },
      );

      if (decision.result === AuthorizeResult.DENY) {
        throw new NotAllowedError(); // 403
      }

      const conditionalPolicy: ConditionalPolicyDecision = req.body;
      // TODO add validation.
      const id =
        await this.conditionalStorage.createCondition(conditionalPolicy);

      resp.status(201).json({ id: id });
    });

    router.get('/conditions/:id', async (req, resp) => {
      const decision = await this.authorize(
        this.identity,
        req,
        this.permissions,
        {
          permission: policyEntityReadPermission,
        },
      );

      if (decision.result === AuthorizeResult.DENY) {
        throw new NotAllowedError(); // 403
      }

      const id: number = parseInt(req.params.id, 10);

      const condition = await this.conditionalStorage.getCondition(id);
      if (!condition) {
        throw new NotFoundError();
      }

      resp.json(condition);
    });

    router.delete('/conditions/:id', async (req, resp) => {
      const decision = await this.authorize(
        this.identity,
        req,
        this.permissions,
        {
          permission: policyEntityDeletePermission,
        },
      );

      if (decision.result === AuthorizeResult.DENY) {
        throw new NotAllowedError(); // 403
      }

      const id: number = parseInt(req.params.id, 10);

      await this.conditionalStorage.deleteCondition(id);
      resp.status(204).end();
    });

    router.put('/conditions/:id', async (req, resp) => {
      const decision = await this.authorize(
        this.identity,
        req,
        this.permissions,
        {
          permission: policyEntityUpdatePermission,
        },
      );

      if (decision.result === AuthorizeResult.DENY) {
        throw new NotAllowedError(); // 403
      }

      const id: number = parseInt(req.params.id, 10);
      const conditionalPolicy: ConditionalPolicyDecision = req.body;

      await this.conditionalStorage.updateCondition(id, conditionalPolicy);
      resp.status(200).end();
    });

    return router;
  }

  getEntityReference(req: Request): string {
    const kind = req.params.kind;
    const namespace = req.params.namespace;
    const name = req.params.name;
    const entityRef = `${kind}:${namespace}/${name}`;

    const err = validateEntityReference(entityRef);
    if (err) {
      throw new InputError(err.message);
    }

    return entityRef;
  }

  transformPolicyArray(...policies: string[][]): EntityReferencedPolicy[] {
    return policies.map((p: string[]) => {
      const [entityReference, permission, policy, effect] = p;
      return { entityReference, permission, policy, effect };
    });
  }

  transformPolicyToArray(policy: EntityReferencedPolicy): string[] {
    return [
      policy.entityReference!,
      policy.permission!,
      policy.policy!,
      policy.effect!,
    ];
  }

  getFirstQuery(
    queryValue: string | string[] | ParsedQs | ParsedQs[] | undefined,
  ): string {
    if (!queryValue) {
      return '';
    }
    if (Array.isArray(queryValue)) {
      if (typeof queryValue[0] === 'string') {
        return queryValue[0].toString();
      }
      throw new InputError(`This api doesn't support nested query`);
    }

    if (typeof queryValue === 'string') {
      return queryValue;
    }
    throw new InputError(`This api doesn't support nested query`);
  }

  isPolicyFilterEnabled(req: Request): boolean {
    return (
      !!req.query.entityRef ||
      !!req.query.permission ||
      !!req.query.policy ||
      !!req.query.effect
    );
  }
}
