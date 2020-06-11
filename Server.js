const express = require('express'),
    bodyParser = require('body-parser'),
    jsforce = require('jsforce'),
    https = require('https'),
    fs = require('fs');
const { UV_FS_O_FILEMAP } = require('constants');

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
app.use(bodyParser.json());

//Allow CORS
app.use(function (req, res, next) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, X-Response-Time, X-PINGOTHER, X-CSRF-Token,Authorization,X-Authorization');
    res.setHeader('Access-Control-Allow-Methods', '*');
    res.setHeader('Access-Control-Expose-Headers', 'X-Api-Version, X-Request-Id, X-Response-Time');
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
        if(req.session.retUrl){
            redirectUrl = req.session.retUrl;
            redirectUrl += `?sid=${req.session.accessToken}`               
        }    
        
        res.redirect(redirectUrl);
    });
});

app.get('/', function (req, res, next) {
    if (req.session.accessToken) {
        res.render('index', {
            instanceUrl: req.session.instanceUrl,
            accessToken: req.session.accessToken
        });

    } else {
        res.redirect(process.env.INSTANCE_URL + '/auth/login');
    }
});

app.get('/home', function (req, res, next) {    
    res.render('home');
});

app.get('/timeline', function (req, res, next) {
    res.render('timeline');
});

app.get('/timelineUrl', function (req, res, next) {
    //Auth using header
    if(req.headers.authorization){
        console.log('Auth using acces token')

        jsforce.login({
            serverUrl : process.env.SFDC_LOGIN_URL,
            sessionId : req.headers.authorization.split(' ')[1]
          }, function(err, userInfo) {
                //KO
                if (err) { 
                    res.status(401);
                    res.send({
                        'AuthUrl': process.env.INSTANCE_URL + '/auth/login'
                    });
                } 
                //OK
                res.status(200);    
                res.send({
                    'TimelineUrl': process.env.INSTANCE_URL          
                });
            }
        );            
    }

    //Auth using Session
    if (req.session.accessToken) {
        res.status(200);    
        res.send({
            'TimelineUrl': process.env.INSTANCE_URL          
        });    
    }else{
        res.status(401);
        res.send({
            'AuthUrl': process.env.INSTANCE_URL + '/auth/login'
        });
    }
});

app.get('/redirect', function (req, res, next) {
    res.render('redirect');
});

app.get('/test', function (req, res, next) {
    res.render('test');
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