const express = require('express'),
    winston = require("winston"),
    CoralogixWinston = require("coralogix-logger-winston"),
    bodyParser = require('body-parser'),
    jsforce = require('jsforce'),
    https = require('https'),
    fs = require('fs');

let app = express();

/**
* Init Coralogix config
*/
const config = {
     privateKey: "65e13c6e-3c47-3c63-c4fe-41d26a742f23",
     applicationName: process.env.HEROKU_APP_NAME,
     subsystemName: "web",
};

/**
* configure winston to user coralogix transport
*/
CoralogixWinston.CoralogixTransport.configure(config);

winston.configure({
    level: process.env.LOG_LEVEL,
    transports: [
        new CoralogixWinston.CoralogixTransport({
            category: "Logs Coralogix"
        }),
        new winston.transports.Console()
    ]
});

if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

app.set('port', process.env.PORT || 8080);

//Session
const redis = require('redis');
const session = require('express-session');

let RedisStore = require('connect-redis')(session)
let redisClient = redis.createClient(
    process.env.REDIS_URL,
    { 
        no_ready_check: true 
    }
);

app.use(session(
    {
        store: new RedisStore({ client: redisClient }),
        secret: 'LDFL09PO09X034',
        resave: true,
        saveUninitialized: true,
        cookie: {
            secure: true
        }
    })
);

//View Engine
app.set('view engine', 'ejs');

//Static files
app.use(express.static(__dirname + '/static'));

//Body parser router
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

//Allow CORS
app.use(function (req, res, next) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, X-Response-Time, X-PINGOTHER, X-CSRF-Token,Authorization,X-Authorization');
    res.setHeader('Access-Control-Expose-Headers', 'X-Api-Version, X-Request-Id, X-Response-Time');
    res.setHeader('Access-Control-Allow-Methods', '*');    
    res.setHeader('Access-Control-Max-Age', '1000');

    next();
});

let oauth2 = new jsforce.OAuth2({
    loginUrl: process.env.SFDC_LOGIN_URL,
    clientId: process.env.SFDC_CLIENT_ID,
    clientSecret: process.env.SFDC_CLIENT_SECRET,
    redirectUri: process.env.SFDC_REDIRECT_URI,
    scope: 'api'    
});

app.get('/auth/login', function (req, res) {
    req.session.retUrl = req.query.retUrl;
    res.redirect(oauth2.getAuthorizationUrl());
});

app.get('/auth/callback', function (req, res) {
    let conn = new jsforce.Connection({
        oauth2: oauth2
    });

    let authorizationCode = req.query.code;
    conn.authorize(authorizationCode, function (err, userInfo) {
        if (err) {
            res.status(404).send('Not Authorized');

            // create a log 
            winston.error(err, { 
                className:"Conn",
                methodName:"authorize"
            });
        }

        req.session.accessToken = conn.accessToken;
        req.session.refreshToken = conn.refreshToken;
        req.session.instanceUrl = conn.instanceUrl.replace(
            '.my.salesforce.', '.lightning.force.'
        );

        req.session.userInfo = userInfo;

        let redirectUrl = process.env.INSTANCE_URL;
        if (req.session.retUrl) {
            redirectUrl = req.session.retUrl;
            
            if(redirectUrl.indexOf('?') != -1){
                redirectUrl += `&sid=${req.session.accessToken}`
            }
            else{
                redirectUrl += `?sid=${req.session.accessToken}`
            }      

            res.redirect(redirectUrl);      
        }
        else{
            res.status(404).send('No Return URL');
        }        
    });
});

app.post('/', function (req, res, next) {
    let accessToken = req.body.accessToken ||
                      req.session.accessToken;
                      
    let instanceUrl = req.body.instanceUrl ||
                      req.session.instanceUrl;
                      

    if (accessToken) {        
        res.render('index', {
            instanceUrl: instanceUrl,
            accessToken: accessToken,
            persons: req.body.persons,
            site: req.body.site,
            role: req.body.role,
            chart: req.body.chart || 'purple',
            frameh: req.body.frameh || '530',                        
            combo: req.body.combo || 0,
            display: process.env.DISPLAY_MODE            
        });
    } else {
        res.redirect(process.env.INSTANCE_URL + '/auth/login');
    }
});

app.get('/', function (req, res, next) {
    let accessToken = req.query.accessToken ||
                      req.session.accessToken;
                      
    let instanceUrl = req.query.instanceUrl ||
                      req.session.instanceUrl;
                      

    if (accessToken) {        
        res.render('index', {
            instanceUrl: instanceUrl,
            accessToken: accessToken,
            persons: req.query.persons,
            site: req.query.site,
            role: req.query.role,
            chart: req.query.chart || 'purple',
            frameh: req.query.frameh || '530',                        
            combo: req.query.combo || 0,
            display: process.env.DISPLAY_MODE            
        });
    } else {
        res.redirect(process.env.INSTANCE_URL + '/auth/login');
    }
});

app.get('/timelineUrl', function (req, res, next) {
    //Auth using header
    if (req.headers.authorization) {
        let conn = new jsforce.Connection({
            serverUrl: process.env.SFDC_LOGIN_URL,
            sessionId: req.headers.authorization.split(' ')[1]
        });
        
        conn.identity(function (err, user) {
            if (err) {
                res.status(401);
                res.send({'AuthUrl': process.env.INSTANCE_URL + '/auth/login'});
        
                // create a log                  
                winston.error(err, { 
                    className:"Conn",
                    methodName:"identity"
                });                
            } else {                
                req.session.accessToken = conn.accessToken;
                req.session.refreshToken = conn.refreshToken;

                res.status(200);
                res.send({
                    'TimelineUrl': process.env.INSTANCE_URL,
                    'instanceUrl': conn.instanceUrl.replace(
                        '.my.salesforce.', '.lightning.force.'
                    )
                });
            }
        });
    }

    //Auth using Session
    else {
        if (req.session.accessToken) {
            res.status(200);
            res.send({
                'TimelineUrl': process.env.INSTANCE_URL,
                'instanceUrl': req.session.instanceUrl
            });
        } else {
            // create a log 
            winston.error("No Access Token", { 
                className:"Conn",
                methodName:"authorize using session"
            });

            res.status(401);
            res.send({'AuthUrl': process.env.INSTANCE_URL + '/auth/login'});            
        }
    }
});

app.use(function (req, res, next) {
    let msg = `Request: HTTP ${req.method} ${req.url}; ipAddress ${req.connection.remoteAddress}`;    
    msg += '; query ' + JSON.stringify(req.query) + '; body ' + JSON.stringify(req.body);
    msg += `; status ${res.statusCode}`;

    winston.info(msg, { 
        className:"Request",
        methodName: req.method
    });

    next();
});

app.listen(app.get('port'), function () {
    console.log('Server listening for HTTP on ' + app.get('port'));
});

if (process.env.NODE_ENV !== 'production') {
    app.set('https_port', process.env.HTTPS_PORT || 8081);

    let options = {
        key: fs.readFileSync('./sec/key.pem', 'utf8'),
        cert: fs.readFileSync('./sec/server.crt', 'utf8')
    };

    https.createServer(options, app).listen(app.get('https_port'), function () {
        console.log("Server listening for HTTPS on port ", app.get('https_port'));
    });
}