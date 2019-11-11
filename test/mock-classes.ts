import { ConfigurationService } from "../src/configuration";
import * as sinon from "sinon";
import { TemplateEngine } from "../src/template/template-engine";
import ScottyClient from "@swingletree-oss/scotty-client";
import { Comms, Harness } from "@swingletree-oss/harness";
import TwistlockStatusEmitter from "../src/status-emitter";

export class ConfigurationServiceMock extends ConfigurationService {
  constructor() {
    super();
    const configStub = sinon.stub();
    this.get = configStub;
  }
}


export class TemplateEngineMock extends TemplateEngine {
  constructor() {
    super();

    this.addFilter = sinon.stub();
    this.template = sinon.stub().returns("stubbed template text");
  }
}


export class ScottyClientMock extends ScottyClient {
  constructor() {
    super("");

    this.getRepositoryConfig = sinon.stub().resolves(
      new Harness.RepositoryConfig({})
    );
    this.sendReport = sinon.stub().resolves();
  }
}

export class TwistlockStatusEmitterMock extends TwistlockStatusEmitter {
  constructor() {
    super(
      new ConfigurationServiceMock(),
      new TemplateEngineMock()
    );

    this.sendReport = sinon.stub().resolves();
  }
}