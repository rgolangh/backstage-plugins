import {
  DatabaseManager,
  errorHandler,
  PluginEndpointDiscovery,
} from '@backstage/backend-common';
import { CatalogClient } from '@backstage/catalog-client';
import { Entity } from '@backstage/catalog-model';
import { Config } from '@backstage/config';

import express from 'express';
import Router from 'express-promise-router';
import { Logger } from 'winston';

import { JiraApiService } from '../api';
import { DatabaseFeedbackStore } from '../database/feedbackStore';
import { FeedbackCategory, FeedbackModel } from '../model/feedback.model';
import { NodeMailer } from './emails';

export interface RouterOptions {
  logger: Logger;
  config: Config;
  discovery: PluginEndpointDiscovery;
}

export async function createRouter(
  options: RouterOptions,
): Promise<express.Router> {
  const { logger, config, discovery } = options;

  const router = Router();
  const feedbackDB = await DatabaseFeedbackStore.create({
    database: DatabaseManager.fromConfig(config).forPlugin('feedback'),
    skipMigrations: false,
    logger: logger,
  });

  const mailer = new NodeMailer(config, logger);
  const catalogClient = new CatalogClient({ discoveryApi: discovery });

  router.use(express.json());

  router.post('/', (req, res) => {
    (async () => {
      const reqData: FeedbackModel = req.body;
      if (!reqData.summary || reqData.summary?.trim().length < 1) {
        return res.status(500).json({ error: 'Summary field empty' });
      }
      reqData.createdAt = new Date().toISOString();
      reqData.updatedBy = reqData.createdBy;
      reqData.updatedAt = reqData.createdAt;

      if (reqData.feedbackType?.toUpperCase() === 'FEEDBACK')
        reqData.feedbackType = FeedbackCategory.FEEDBACK;
      else if (reqData.feedbackType?.toUpperCase() === 'BUG')
        reqData.feedbackType = FeedbackCategory.BUG;
      else
        return res.status(400).json({
          error: `The value of feedbackType should be either 'FEEDBACK'/'BUG'`,
        });

      const entityRef: Entity | undefined = await catalogClient.getEntityByRef(
        reqData.projectId!,
      );
      if (!entityRef) {
        return res
          .status(404)
          .json({ error: `Entity not found: ${reqData.projectId}` });
      }

      const entityRoute = `${config.getString('app.baseUrl')}/catalog/${
        entityRef.metadata.namespace
      }/${entityRef.kind}/${entityRef.metadata.name}/feedback`;

      const feedbackType =
        reqData.feedbackType === 'FEEDBACK' ? 'Feedback' : 'Issue';

      if (reqData.summary?.length > 255) {
        reqData.description = reqData.summary
          ?.concat('\n\n')
          .concat(reqData.description ?? '');
        reqData.summary = `${feedbackType} reported by ${reqData.createdBy?.split(
          '/',
        )[1]} for ${entityRef.metadata.title ?? entityRef.metadata.name}`;
      }

      const respObj = await feedbackDB.storeFeedbackGetUuid(reqData);
      if (respObj === 0) {
        return res.status(500).json({
          error: `Failed to create ${feedbackType}`,
        });
      }

      reqData.feedbackId = respObj.feedbackId;
      res.status(201).json({
        message: `${feedbackType} created successfully`,
        data: respObj,
      });

      if (entityRef.metadata.annotations) {
        const annotations = entityRef.metadata.annotations;
        const type = annotations['feedback/type'];
        const replyTo = annotations['feedback/email-to'];
        const reporterEmail = (
          (await catalogClient.getEntityByRef(reqData.createdBy!))?.spec
            ?.profile as { email: string }
        ).email;
        const appTitle = config.getString('app.title');

        if (
          type.toUpperCase() === 'JIRA' &&
          !reqData.tag?.match(/(Excellent|Good)/g)
        ) {
          let host = annotations['feedback/host'];
          // if host is undefined then
          // use the first host from config
          const serviceConfig =
            config
              .getConfigArray('feedback.integrations.jira')
              .find(hostConfig => host === hostConfig.getString('host')) ??
            config.getConfigArray('feedback.integrations.jira')[0];
          host = serviceConfig.getString('host');
          const authToken = serviceConfig.getString('token');
          const hostType = serviceConfig.getOptionalString('hostType');

          const projectKey = entityRef.metadata.annotations['jira/project-key'];
          const jiraService = new JiraApiService(host, authToken, hostType);
          const jiraUsername =
            await jiraService.getJiraUsernameByEmail(reporterEmail);

          // if jira id is not there for reporter, add reporter email in description
          const jiraDescription = reqData.description!.concat(
            `\n\n${
              jiraUsername === undefined
                ? `Reported by: ${reporterEmail}`
                : '\r'
            }\n*Submitted from ${appTitle}*\n[${feedbackType} link|${entityRoute}?id=${
              reqData.feedbackId
            }]`,
          );

          const resp = await jiraService.createJiraTicket({
            projectKey: projectKey,
            summary: reqData.summary,
            description: jiraDescription,
            tag: reqData.tag!.toLowerCase().split(' ').join('-'),
            feedbackType: reqData.feedbackType,
            reporter: jiraUsername,
          });
          reqData.ticketUrl = `${host}/browse/${resp.key}`;
          await feedbackDB.updateFeedback(reqData);
        }

        if (type.toUpperCase() === 'MAIL' || replyTo) {
          mailer.sendMail({
            to: reporterEmail,
            replyTo: replyTo,
            subject: `${
              reqData.tag
            } - ${feedbackType} reported for ${reqData.projectId?.split(
              '/',
            )[1]}`,
            body: `
            <div>
              Hi ${reqData.createdBy?.split('/')[1]},
              <br/> 
              <br/> 
              We have received your feedback for 
                <b>
                  ${reqData.projectId?.split('/')[1]}
                </b>, 
              and here are the details:
              <br/>
              <br/>
              Summary: ${reqData.summary}
              <br/>
              <br/>
              ${
                reqData.description?.length! > 0
                  ? `Description: ${reqData.description}
                <br/>
                <br/>`
                  : '\r'
              }
              Submitted from: ${reqData.url}
              <br/>
              Submitted at: ${new Date(reqData.createdAt).toUTCString()} 
              <br/>
              <br/>
              <a href="${entityRoute}?id=${reqData.feedbackId}">
                View on ${appTitle}
              </a>
            </div>`,
          });
        }
      }
      return 1;
    })();
  });

  router.get('/', (req, res) => {
    (async () => {
      const projectId = req.query.projectId
        ? (req.query.projectId as string)
        : 'all';
      const offset = req.query.offset
        ? parseInt(req.query.offset as string, 10)
        : 0;
      const limit = req.query.limit
        ? parseInt(req.query.limit as string, 10)
        : 10;
      const searchKey = req.query.query?.toString() ?? '';

      const feedbackData = await feedbackDB.getAllFeedbacks(
        projectId,
        offset,
        limit,
        searchKey,
      );
      const page = offset / limit + 1;
      return res
        .status(200)
        .json({ ...feedbackData, currentPage: page, pageSize: limit });
    })();
  });

  router.get('/:id', (req, res) => {
    (async () => {
      const feedbackId = req.params.id;

      if (await feedbackDB.checkFeedbackId(feedbackId)) {
        const feedback: FeedbackModel =
          await feedbackDB.getFeedbackByUuid(feedbackId);
        return res.status(200).json({
          data: feedback,
          message: 'Feedback fetched successfully',
        });
      }
      return res
        .status(404)
        .json({ error: `No feedback found for id ${feedbackId}` });
    })();
  });

  router.get('/:id/ticket', (req, res) => {
    (async () => {
      const ticketId = req.query.ticketId
        ? (req.query.ticketId as string)
        : null;
      const projectId = req.query.projectId
        ? (req.query.projectId as string)
        : null;

      if (ticketId && projectId) {
        const entityRef: Entity | undefined =
          await catalogClient.getEntityByRef(projectId);
        if (!entityRef) {
          return res
            .status(404)
            .json({ error: `Entity not found: ${projectId}` });
        }
        const feedbackType = entityRef.metadata.annotations?.['feedback/type'];
        if (feedbackType?.toLowerCase() === 'jira') {
          let host = entityRef.metadata.annotations?.['feedback/host'];

          // if host is undefined then
          // use the first host from config
          const serviceConfig =
            config
              .getConfigArray('feedback.integrations.jira')
              .find(hostConfig => host === hostConfig.getString('host')) ??
            config.getConfigArray('feedback.integrations.jira')[0];
          host = serviceConfig.getString('host');
          const authToken = serviceConfig.getString('token');

          const resp = await new JiraApiService(
            host,
            authToken,
          ).getTicketDetails(ticketId);
          return res.status(200).json({
            data: { ...resp },
            message: 'fetched successfully',
          });
        }
      }

      return res
        .status(404)
        .json({ error: `Unable to fetch jira ticket ${ticketId}` });
    })();
  });

  // patch and delete apis
  router.patch('/:id', (req, res) => {
    (async () => {
      const feedbackId = req.params.id;
      const data: FeedbackModel = req.body;

      if (await feedbackDB.checkFeedbackId(feedbackId)) {
        data.feedbackId = feedbackId;
        data.updatedAt = new Date().toISOString();
        const updatedData = await feedbackDB.updateFeedback(data);
        if (updatedData) {
          return res.status(200).json({
            data: updatedData,
            message: 'Feedback updated successfully',
          });
        }
        return res.status(500).json({ error: 'Failed to edit the feedback' });
      }

      return res
        .status(404)
        .json({ error: `No feedback found for id ${feedbackId}` });
    })();
  });

  router.delete('/:id', (req, res) => {
    (async () => {
      const feedbackId = req.params.id;
      if (await feedbackDB.checkFeedbackId(feedbackId)) {
        await feedbackDB.deleteFeedbackById(feedbackId);
        return res.status(200).json({ message: 'Deleted successfully' });
      }

      logger.error(`No feedback found for id ${feedbackId}`);
      return res
        .status(404)
        .json({ error: `No feedback found for id ${feedbackId}` });
    })();
  });

  router.use(errorHandler());
  return router;
}
