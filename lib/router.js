import { fileURLToPath, URL } from 'node:url';
import basicAuth from 'basic-auth-connect';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import errorHandler from 'errorhandler';
import express from 'express';
import pico from 'picocolors';
import favicon from 'serve-favicon';
import logger from 'morgan';
import methodOverride from 'method-override';
import mongodb from 'mongodb';

import session from 'express-session';
import memorystore from 'memorystore';
import csrf from 'csurf';
import rateLimit from 'express-rate-limit';
import db from './db.js';
import { isFormStrategy, loadOidcAuth, loginPath, requireLogin, verifyCredentials } from './auth.js';
import { Access } from './access.js';
import routes from './routes/index.js';
import { buildCollectionURL, buildDatabaseURL, colsToGrid } from './utils.js';

const MemoryStore = memorystore(session);

const ALLOWED_SUBTYPES = new Set([
  mongodb.Binary.SUBTYPE_UUID_OLD,
  mongodb.Binary.SUBTYPE_UUID,
]);

const PASSWORD_PLACEHOLDER = '••••••••••••••••';

// RBAC objects of routes whose target is in the request body or a bucket.
const newDatabase = (req) => String(req.body?.database ?? '');
const newCollection = (req) => `${req.dbName}/${String(req.body?.collection ?? '')}`;
const bucketNs = (req) => `${req.dbName}/${req.bucketName}`;

const addTrailingSlash = function (s) {
  return s + (s.at(-1) === '/' ? '' : '/');
};

const buildBaseHref = function (originalUrl, reqUrl) {
  if (reqUrl === '/') {
    return addTrailingSlash(originalUrl);
  }
  const idx = originalUrl.lastIndexOf(reqUrl);
  const rootPath = originalUrl.slice(0, idx);
  return addTrailingSlash(rootPath);
};

const buildId = function (id, query) {
  // Case 1 : ObjectId
  try {
    return mongodb.BSON.ObjectId.createFromHexString(id);
  } catch {
    // Case 2 : BinaryID (only subtype 3 and 4)
    if (('subtype' in query)) {
      const subtype = Number.parseInt(query.subtype, 10);
      if (ALLOWED_SUBTYPES.has(subtype)) {
        if (subtype === mongodb.Binary.SUBTYPE_UUID) {
          return new mongodb.Binary(new Buffer.from(id.replaceAll('-', ''), 'hex'), query.subtype);
        }
        // mongodb.Binary.SUBTYPE_UUID_OLD
        return new mongodb.Binary(new Buffer.from(id, 'base64'), query.subtype);
      }
      // ignore wrong subtype
    }
    // Case 3 : Try as raw ID
    return id;
  }
};

const router = async function (config) {
  // Redirect targets come from configuration, not from res.locals.baseHref: that is derived
  // from req.originalUrl, so feeding it to res.redirect hands the caller influence over
  // where other people get sent. CodeQL reports it as js/server-side-unvalidated-url-redirection.
  const baseHref = config.site.baseUrl || '/';

  // appRouter configuration
  const appRouter = express.Router();
  // Identity (optional OpenShift login) and RBAC for every route below.
  const access = config.access instanceof Access ? config.access : new Access(config);
  let mongo = null;
  try {
    mongo = await db(config);
  } catch (error) {
    // console.debug hid this: the process carried on and the only sign was a debug line most
    // people never see. The app still starts, so the connection form can be used to supply
    // working credentials, but the failure itself is worth saying out loud.
    console.error(pico.red('Could not connect to MongoDB on startup.'));
    console.error(error);
  }

  appRouter.get(config.healthCheck.path, (req, res) => {
    // Reporting ok while unable to reach MongoDB makes the check useless: an orchestrator
    // sees a healthy container, so it neither restarts it nor takes it out of rotation.
    if (mongo === null) {
      return res.status(503).json({ status: 'error', error: 'No MongoDB connection' });
    }

    return res.json({ status: 'ok' });
  });

  // The form strategy gates requests further down, once sessions exist; basic auth can stay
  // here because it is stateless. With OpenShift login the local account uses the sign-in
  // page instead of the basic-auth prompt.
  if (config.useBasicAuth && !isFormStrategy(config) && !access.ssoConfigured) {
    appRouter.use(basicAuth(config.basicAuth.username, config.basicAuth.password));
  }

  if (config.useOidcAuth) {
    // Deliberately fatal if the package is missing: continuing without authentication would
    // leave the database wide open, which is worse than refusing to start.
    const oidcAuth = await loadOidcAuth();
    appRouter.use(oidcAuth(config.oidcAuth));
  }

  appRouter.use(favicon(fileURLToPath(new URL('../public/images/favicon.ico', import.meta.url))));

  appRouter.use(logger('dev', config.options.logger));

  appRouter.use('/public', express.static(fileURLToPath(new URL('../build', import.meta.url))));

  appRouter.use(bodyParser.json());
  // Set request size limit
  appRouter.use(bodyParser.urlencoded({
    extended: true,
    limit: config.site.requestSizeLimit,
  }));

  appRouter.use(cookieParser(config.site.cookieSecret));

  appRouter.use(session({
    key: config.site.cookieKeyName,
    resave: true,
    saveUninitialized: true,
    secret: config.site.sessionSecret,
    // Lax (not Strict): the OpenShift OAuth callback is a top-level navigation from
    // the OAuth server and must carry the session that holds the login state.
    cookie: { httpOnly: true, sameSite: 'lax', secure: Boolean(config.site.sslEnabled) },
    store: new MemoryStore({
      checkPeriod: 86400000,  // prune expired entries every 24h
    }),
  }));

  appRouter.use(csrf(process.env.NODE_ENV === 'test'
    ? { ignoreMethods: ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'DELETE'] }
    : { cookie: true }));

  if (access.ssoConfigured) {
    // OpenShift login, with the local account as fallback when it is configured.
    access.mountSSO(appRouter, rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 100,
      standardHeaders: true,
      legacyHeaders: false,
      message: 'Too many requests. Please wait before trying again.',
    }));
  } else if (isFormStrategy(config)) {
    // Form-based sign-in (#1733). Registered after csurf so the form carries a token, and
    // before the guard below so the page itself stays reachable while signed out.
    // Two limits. The strict one bounds credential guessing; the looser one bounds how many
    // sessions an anonymous caller can make the store allocate by hammering the page, which
    // matters because sessions live in memory.
    const signInLimiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 10,
      standardHeaders: true,
      legacyHeaders: false,
      message: 'Too many sign-in attempts. Please wait before trying again.',
    });

    const signInPageLimiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 100,
      standardHeaders: true,
      legacyHeaders: false,
      message: 'Too many requests. Please wait before trying again.',
    });

    // Also mounted with use(), so the limit applies regardless of how the route below is
    // matched, and so static analysis can see it guarding the path rather than only
    // appearing as a handler argument.
    appRouter.use(loginPath(config), signInPageLimiter);

    appRouter.get(loginPath(config), (req, res) => {
      res.render('signin', {
        loginUrl: loginPath(config),
        csrfToken: req.csrfToken(),
        localLogin: true,
        openshift: { state: 'disabled' },
        openshiftAvailable: false,
      });
    });

    appRouter.post(loginPath(config), signInLimiter, (req, res) => {
      const { username, password } = req.body;

      if (!verifyCredentials(config, username, password)) {
        req.session.error = 'Invalid username or password.';
        return res.redirect(loginPath(config));
      }

      // Regenerate before marking the session authenticated, so a session id an attacker
      // planted beforehand cannot be reused as a signed-in one.
      return req.session.regenerate((error) => {
        if (error) {
          console.error(error);
          req.session.error = 'Could not start a session. Please try again.';
          return res.redirect(loginPath(config));
        }

        req.session.authenticated = true;

        return res.redirect(config.site.baseUrl);
      });
    });

    appRouter.get(`${config.site.baseUrl || '/'}logout`, signInPageLimiter, (req, res) => {
      req.session.destroy(() => res.redirect(loginPath(config)));
    });

    appRouter.use(requireLogin(config));
  }

  appRouter.use(methodOverride(function (req) {
    if (!(req.body && typeof req.body === 'object' && '_method' in req.body)) {
      return;
    }

    // look in urlencoded POST bodies and delete it
    const method = req.body._method;
    delete req.body._method;
    return method;
  }));

  if (process.env.NODE_ENV === 'development') {
    appRouter.use(errorHandler());
  }

  // View helper, sets local variables used in templates
  appRouter.all('/{*splat}', async function (req, res, next) {
    access.locals(req, res);
    if (mongo === null) {
      // The connection form changes where mongo-express connects: admins only.
      if (!access.allowed(req, 'server', 'get', '*')) {
        return access.deny(req, res, 'get server');
      }
      if (req.method === 'POST' && !access.allowed(req, 'server', 'update', '*')) {
        return access.deny(req, res, 'update server');
      }
      const connection = new URL(config.mongodb.connectionString);
      if (req.method === 'POST') {
        const {
          authSource, hostname, port,
          username, password,
        } = req.body;
        connection.hostname = hostname;
        connection.port = port;
        connection.username = username;
        connection.searchParams.set('authSource', authSource);
        if (password !== PASSWORD_PLACEHOLDER) {
          connection.password = password;
        }
        config.mongodb.connectionString = connection.href;
        try {
          mongo = await db(config);
          return res.redirect(config.site.baseUrl);
        } catch (error) {
          console.debug(error);
        }
      }

      return res.render('login', {
        csrfToken: req.csrfToken(),
        authSource: connection.searchParams.get('authSource') ?? '',
        username: connection.username,
        password: PASSWORD_PLACEHOLDER,
        hostname: connection.hostname,
        port: connection.port,
      });
    }
    res.locals.baseHref = buildBaseHref(req.originalUrl, req.url);
    res.locals.databases = access.filterDatabases(req, mongo.getDatabases());
    res.locals.collections = access.filterCollections(req, mongo.collections);
    res.locals.gridFSBuckets = colsToGrid(res.locals.collections);
    res.locals.enableLogout = config.useOidcAuth || access.ssoConfigured || isFormStrategy(config);
    access.decorate(req, res);

    // Flash messages
    if (req.session.success) {
      res.locals.messageSuccess = req.session.success;
      delete req.session.success;
    }

    if (req.session.error) {
      res.locals.messageError = req.session.error;
      delete req.session.error;
    }

    await mongo.updateDatabases().then(() => {
      res.locals.databases = access.filterDatabases(req, mongo.getDatabases());
      next();
    }).catch(next);
  });

  // route param pre-conditions
  appRouter.param('database', function (req, res, next, id) {
    // Make sure database exists
    if (!mongo.connections[id]) {
      req.session.error = 'Database not found!';
      return res.redirect(baseHref);
    }

    req.dbName = id;
    res.locals.dbName = id;
    res.locals.dbUrl = buildDatabaseURL(res.locals.baseHref, id);

    req.dbConnection = mongo.connections[id];
    req.db = mongo.connections[id].db;
    next();
  });

  // :collection param MUST be preceded by a :database param
  appRouter.param('collection', function (req, res, next, id) {
    // Make sure collection exists

    if (!mongo.collections[req.dbName].includes(id)) {
      req.session.error = 'Collection not found!';
      return res.redirect(baseHref + 'db/' + req.dbName);
    }

    req.collectionName = id;
    res.locals.collectionName = id;
    res.locals.collectionUrl = buildCollectionURL(res.locals.baseHref, res.locals.dbName, id);

    res.locals.collections = access.filterCollections(req, { [req.dbName]: mongo.collections[req.dbName] })[req.dbName];
    res.locals.gridFSBuckets = colsToGrid(res.locals.collections);

    const coll = mongo.connections[req.dbName].db.collection(id);

    if (coll === null) {
      req.session.error = 'Collection not found!';
      return res.redirect(baseHref + 'db/' + req.dbName);
    }

    req.collection = coll;

    next();
  });

  // :document param MUST be preceded by a :collection param
  appRouter.param('document', async function (req, res, next, id) {
    if (id === 'undefined' || id === undefined) {
      req.session.error = 'Document lacks an _id!';
      return res.redirect(baseHref + 'db/' + req.dbName + '/' + req.collectionName);
    }

    id = JSON.parse(decodeURIComponent(id));
    const _id = buildId(id, req.query);

    // If an ObjectId was correctly created from passed id param, try getting the ObjID first else falling back to try getting the string id
    // If not valid ObjectId created, try getting string id
    try {
      let doc = await req.collection.findOne({ _id });
      if (doc === null) {
        // No document found with obj_id, try again with straight id
        doc = await req.collection.findOne({ _id: id });
      }
      if (doc === null) {
        req.session.error = 'Document not found!';
      } else {
        // Document found - send it back
        req.document = doc;
        res.locals.document = doc;
        return next();
      }
    } catch (error) {
      req.session.error = 'Error: ' + error;
      console.error(error);
    }
    res.redirect(baseHref + 'db/' + req.dbName + '/' + req.collectionName);
  });

  // get individual property - for async loading of big documents
  // (db)/(collection)/(document)/(prop)
  appRouter.param('prop', function (req, res, next, prop) {
    req.prop = req.document[prop];
    next();
  });

  // GridFS (db)/gridFS/(bucket)
  appRouter.param('bucket', async function (req, res, next, id) {
    req.bucketName = id;
    res.locals.bucketName = id;

    // `.db` matters: connections[dbName] is the connection wrapper, not the Db. Without it
    // every GridFS route died with "connections[req.dbName].collection is not a function".
    const filesConn = mongo.connections[req.dbName].db.collection(id + '.files');

    // Deliberately not `req.files`: express-fileupload owns that property, and overwriting
    // it with the bucket listing is what broke uploads.
    req.filesConn = filesConn;

    try {
      req.connFiles = await filesConn.find().toArray();
    } catch (error) {
      req.session.error = id + '.files collection not found! Err:' + error;
      return res.redirect(baseHref + 'db/' + req.dbName);
    }

    next();
  });

  // GridFS files
  appRouter.param('file', function (req, res, next, id) {
    req.fileID = JSON.parse(decodeURIComponent(id));
    next();
  });

  // mongodb mongoMiddleware
  const mongoMiddleware = function (req, res, next) {
    req.mainClient = mongo.mainClient;
    req.adminDb = mongo.mainClient.adminDb || undefined;
    req.databases = mongo.getDatabases(); // List of database names
    req.collections = mongo.collections; // List of collection names in all databases
    req.gridFSBuckets = colsToGrid(mongo.collections);

    // Allow page handlers to request an update for collection list
    req.updateCollections = mongo.updateCollections;
    req.updateDatabases = mongo.updateDatabases;

    next();
  };

  /*
   * Server-side enforcement of readOnly and noDelete. The templates hide the controls and
   * two collection handlers check the flags, but nothing stopped a direct HTTP request, so
   * a DELETE still removed the document with readOnly turned on.
   *
   * Redirects go to the configured base URL rather than res.locals.baseHref: the latter is
   * derived from req.originalUrl, and CodeQL flags feeding request-controlled data into
   * res.redirect. config.site.baseUrl is server configuration the caller cannot influence.
   */
  appRouter.use(function (req, res, next) {
    const safeRedirect = () => res.redirect(baseHref);

    if (config.options.readOnly && ['POST', 'PUT', 'DELETE'].includes(req.method)) {
      req.session.error = 'Application is running in read-only mode!';
      return safeRedirect();
    }
    if (config.options.noDelete && req.method === 'DELETE') {
      req.session.error = 'Delete operations are not permitted!';
      return safeRedirect();
    }
    next();
  });

  // routes
  const configuredRoutes = routes(config);
  const authz = access.authz.bind(access);
  // DELETE on a collection with ?query deletes matching documents, otherwise drops it.
  const deleteInCollection = (req, res, next) => (req.query.query
    ? authz('documents', 'delete')(req, res, next)
    : authz('collections', 'delete')(req, res, next));

  appRouter.get('/', mongoMiddleware, authz('databases', 'get', () => '*'), configuredRoutes.index);
  appRouter.post('/', mongoMiddleware, authz('databases', 'create', newDatabase), configuredRoutes.addDatabase);
  appRouter.delete('/:database', mongoMiddleware, authz('databases', 'delete'), configuredRoutes.deleteDatabase);
  appRouter.get('/db/:database', mongoMiddleware, authz('databases', 'get'), configuredRoutes.viewDatabase);

  // Validates editor input only; any signed-in user may use it.
  appRouter.post('/checkValid', mongoMiddleware, configuredRoutes.checkValid);

  // Collection level routes
  appRouter.post('/db/:database/import/:collection', mongoMiddleware, authz('documents', 'create'), configuredRoutes.importCollection);
  appRouter.get('/db/:database/compact/:collection', mongoMiddleware, authz('collections', 'update'), configuredRoutes.compactCollection);
  appRouter.get('/db/:database/expArr/:collection', mongoMiddleware, authz('documents', 'get'), configuredRoutes.exportColArray);
  appRouter.get('/db/:database/expCsv/:collection', mongoMiddleware, authz('documents', 'get'), configuredRoutes.exportCsv);
  appRouter.get('/db/:database/reIndex/:collection', mongoMiddleware, authz('indexes', 'create'), configuredRoutes.reIndex);
  appRouter.post('/db/:database/addIndex/:collection', mongoMiddleware, authz('indexes', 'create'), configuredRoutes.addIndex);
  appRouter.get('/db/:database/export/:collection', mongoMiddleware, authz('documents', 'get'), configuredRoutes.exportCollection);
  appRouter.get('/db/:database/dropIndex/:collection', mongoMiddleware, authz('indexes', 'delete'), configuredRoutes.dropIndex);
  appRouter.get('/db/:database/updateCollections', mongoMiddleware, authz('databases', 'get'), configuredRoutes.updateCollections);

  // GridFS
  appRouter.post('/db/:database/gridFS', mongoMiddleware, authz('gridfs', 'create', (req) => `${req.dbName}/${String(req.body?.bucket ?? '')}`), configuredRoutes.addBucket);
  appRouter.delete('/db/:database/gridFS/:bucket', mongoMiddleware, authz('gridfs', 'delete', bucketNs), configuredRoutes.deleteBucket);

  appRouter.get('/db/:database/gridFS/:bucket', mongoMiddleware, authz('gridfs', 'get', bucketNs), configuredRoutes.viewBucket);
  appRouter.post('/db/:database/gridFS/:bucket', mongoMiddleware, authz('gridfs', 'create', bucketNs), configuredRoutes.addFile);
  appRouter.get('/db/:database/gridFS/:bucket/:file', mongoMiddleware, authz('gridfs', 'get', bucketNs), configuredRoutes.getFile);
  appRouter.delete('/db/:database/gridFS/:bucket/:file', mongoMiddleware, authz('gridfs', 'delete', bucketNs), configuredRoutes.deleteFile);

  appRouter.get('/db/:database/:collection', mongoMiddleware, authz('documents', 'get'), configuredRoutes.viewCollection);
  appRouter.put('/db/:database/:collection', mongoMiddleware, authz('collections', 'update'), authz('collections', 'create', newCollection), configuredRoutes.renameCollection);
  appRouter.delete('/db/:database/:collection', mongoMiddleware, deleteInCollection, configuredRoutes.deleteCollection);
  appRouter.post('/db/:database', mongoMiddleware, authz('collections', 'create', newCollection), configuredRoutes.addCollection);

  // Document routes
  appRouter.post('/db/:database/:collection', mongoMiddleware, authz('documents', 'create'), configuredRoutes.addDocument);
  appRouter.get('/db/:database/:collection/:document', mongoMiddleware, authz('documents', 'get'), configuredRoutes.viewDocument);
  appRouter.put('/db/:database/:collection/:document', mongoMiddleware, authz('documents', 'update'), configuredRoutes.updateDocument);
  appRouter.delete('/db/:database/:collection/:document', mongoMiddleware, authz('documents', 'delete'), configuredRoutes.deleteDocument);

  // Property routes
  appRouter.get('/db/:database/:collection/:document/:prop', mongoMiddleware, authz('documents', 'get'), configuredRoutes.getProperty);

  return appRouter;
};

export default router;
