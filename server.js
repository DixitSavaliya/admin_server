var express = require('express');
var http = require('http');
var bodyParser = require('body-parser');

// Create Express Application Server
var app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// for intercepting request
app.use(function (req, res, next) {
    var origin = req.headers.origin != undefined ? req.headers.origin : '*';
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Access-Control-Allow-Methods', 'GET,HEAD,PUT,PATCH,POST,DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Access-Control-Allow-Credentials, Access-Control-Allow-Origin, X-Requested-With, Access-Control-Allow-Headers, content-type, Authorization, content-md5');
    var currentUrl = req.url ? req.url : '';
    console.log('requested_plain_url ==>    ' + currentUrl);
    next();
});

// controllers mapping
var userApi = require('./controllers/user_controller');

app.use('/User', userApi);
app.use(express.static(__dirname + '/upload'));
var httpServer = http.createServer(app).listen(3505);
console.log('Listening HTTP on port 3505');
module.exports = app;
