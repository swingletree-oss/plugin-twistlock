"use strict";

import { suite, test, describe } from "mocha";
import { expect, assert } from "chai";
import * as chai from "chai";
import * as sinon from "sinon";
import { mockReq, mockRes } from "sinon-express-mock";
import TwistlockWebhook from "../../src/webhook";
import { ConfigurationServiceMock, TwistlockStatusEmitterMock } from "../mock-classes";
import TwistlockStatusEmitter from "../../src/status-emitter";
import { Harness, Comms } from "@swingletree-oss/harness";
import { TwistlockModel } from "../../src/model";

chai.use(require("sinon-chai"));

const sandbox = sinon.createSandbox();

describe("Twistlock Webhook", () => {

  let uut;
  let requestMock, responseMock;
  let twistlockTestData;

  beforeEach(() => {
    uut = new TwistlockWebhook(
      new ConfigurationServiceMock(),
      new TwistlockStatusEmitterMock()
    );

    requestMock = mockReq();
    requestMock.headers = {};
    responseMock = mockRes();

    twistlockTestData = Object.assign({}, require("../mock/twistlock-report-all.json"));
  });



  ["owner", "repo", "sha", "branch"].forEach((prop) => {
    it(`should answer with 400 when missing ${prop} parameter`, async () => {
      requestMock.body = {
        data: {
          report: {
            results: [
              {}, {}
            ]
          },
          headers: {}
        },
        meta: {
          source: {
            branch: [ "master" ],
            owner: "org",
            repo: "repo",
            sha: "sha"
          } as Harness.GithubSource
        } as Comms.Gate.PluginReportProcessMetadata
      } as Comms.Gate.PluginReportProcessRequest<TwistlockModel.Report>;

      requestMock.body.meta.source[prop] = undefined;

      await uut.webhook(requestMock, responseMock);

      sinon.assert.calledOnce(responseMock.send);
      sinon.assert.calledWith(responseMock.status, 400);
    });
  });

  it(`should answer with 400 when missing site property in report body`, async () => {
    requestMock.query = {
      org: "org",
      repo: "repo",
      sha: "sha",
      branch: "branch"
    };

    requestMock.body = {
      data: {}
    };

    await uut.webhook(requestMock, responseMock);

    sinon.assert.calledOnce(responseMock.send);
    sinon.assert.calledWith(responseMock.status, 400);
  });

  it(`should answer with 204 when receiving valid request`, async () => {
    requestMock.body = {
      data: {
        report: {
          results: [
            {}, {}
          ]
        }
      },
      meta: {
        source: {
          branch: [ "master" ],
          owner: "org",
          repo: "repo",
          sha: "sha"
        } as Harness.GithubSource
      }
    };

    await uut.webhook(requestMock, responseMock);

    sinon.assert.calledOnce(responseMock.send);
    sinon.assert.calledWith(responseMock.status, 204);
  });
});
