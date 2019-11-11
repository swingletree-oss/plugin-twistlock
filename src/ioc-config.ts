import "reflect-metadata";

import { Container } from "inversify";

import { ConfigurationService } from "./configuration";
import TwistlockStatusEmitter from "./status-emitter";
import TwistlockWebhook from "./webhook";
import { TemplateEngine } from "./template/template-engine";
import { WebServer } from "./webserver";


const container = new Container();

container.bind<ConfigurationService>(ConfigurationService).toSelf().inSingletonScope();
container.bind<TwistlockStatusEmitter>(TwistlockStatusEmitter).toSelf().inSingletonScope();
container.bind<TwistlockWebhook>(TwistlockWebhook).toSelf().inSingletonScope();
container.bind<WebServer>(WebServer).toSelf().inSingletonScope();
container.bind<TemplateEngine>(TemplateEngine).toSelf().inSingletonScope();


export default container;