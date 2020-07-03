const express = require('express'),
    bodyParser = require('body-parser'),
    jsforce = require('jsforce'),
    https = require('https'),
    fs = require('fs');

let app = express();

if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

app.set('port', process.env.PORT || 8080);

//Session
app.set('trust proxy', 1);
app.use(require('express-session')({
    secret: 'LDFO09034',
    resave: true,
    saveUninitialized: true,
    cookie: {
        secure: true
    }
}));

//View Engine
app.set('view engine', 'ejs');

//Static files
app.use(express.static(__dirname + '/static'));

//Body parser router
app.use(bodyParser.urlencoded());
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
            return console.error(err)
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
        }

        res.redirect(redirectUrl);
    });
});

app.post('/', function (req, res, next) {
    console.log(req);
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
    console.log(req);

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
            res.status(401);
            res.send({'AuthUrl': process.env.INSTANCE_URL + '/auth/login'});
        }
    }
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