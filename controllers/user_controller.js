var express = require('express');
var router = express.Router();
var pool = require('../database')();
var bcrypt = require('bcryptjs');
var jwttoken = require('jsonwebtoken');
var jwt = require('jwt-simple');
const secret = "secret";
const withAuth = require('./authenticate/authenticate.js');
var nodemailer = require('nodemailer');
var upload = require('express-fileupload');
router.use(upload());
// For OAuth
router.post('/loginUser', loginUser);
router.post('/createUser', createUser);
router.post('/changepassword', changePassword);
router.post('/forgotpassword', forgotPassword);
router.post('/resetpassword', resetPassword);
router.post('/getprofile', getProfile);
router.post('/updateProfile', updateProfile);
router.post('/uploadImage', uploadImage);
// router.post('/checkToken', withAuth, function (req, res) {
//     res.sendStatus(200);
// });

//Create User
function createUser(req, res) {
    var user = {
        first_name: req.body.first_name ? req.body.first_name : '',
        last_name: req.body.last_name ? req.body.last_name : '',
        email: req.body.email ? req.body.email : '',
        password: req.body.password ? req.body.password : ''
    };

    if (user.email && user.password) {
        let salt = 1;
        bcrypt.hash(user.password, salt, function (err, hash) {
            console.log("hash--", hash);
            user.password = hash;
            var detail = user;
            console.log("detail--", detail);
            pool.query('INSERT INTO user SET ?', detail, function (error, results, response) {
                if (error) {
                    res.send({
                        "status": 0,
                        "message": error,
                        "data": []
                    })
                } else {
                    console.log("detail", response);
                    const email = detail.email;
                    const payload = { email };
                    const token = jwttoken.sign(payload, secret, { expiresIn: '1h' });
                    const userData = {
                        user: detail,
                        token: token,
                        userId: detail.id
                    }
                    res.send({
                        "status": 1,
                        "message": "admin login sucessfully",
                        "data": userData
                    });
                }
            });
        });
    } else {
        var jsonObject = {};
        jsonObject["status"] = "0";
        jsonObject["message"] = "username and password is required";
        jsonObject["data"] = [];
        res.send(jsonObject);
    }
}

//Login User
function loginUser(req, res) {
    var obj = {
        email: req.body.email,
        password: req.body.password
    }

    pool.query('SELECT * FROM user WHERE email = ?', [obj.email], function (error, results, fields) {
        if (error) {
            res.send({
                "status": 0,
                "message": error,
                "data": []
            })
        } else {
            console.log("results", results[0].password);
            if (results.length > 0) {
                let salt = 1;

                bcrypt.compare(obj.password, results[0].password, function (err, isMatch) {
                    console.log('password == hash: ', isMatch);
                    if (isMatch) {
                        const email = obj.email;
                        const payload = { email };
                        const token = jwttoken.sign(payload, secret, { expiresIn: '1h' });
                        const userData = {
                            user: obj,
                            token: token,
                            id: results[0].id
                        }
                        res.send({
                            "status": 1,
                            "message": "login sucessfull",
                            "data": userData
                        });
                    } else {
                        res.send({
                            "status": 0,
                            "message": "Email and password does not match",
                            "data": []
                        });
                    }
                });
            } else {
                res.send({
                    "status": 0,
                    "message": "Email does not exits",
                    "data": []
                });
            }
        }
    });
}

//changePassword
function changePassword(req, res) {
    var user_id = req.body.user_id;
    var oldPassword = req.body.oldPassword;
    var newPassword = req.body.newPassword;
    if (oldPassword !== newPassword) {
        let salt = 1;
        pool.query(`SELECT * FROM user WHERE ID = ?`, [user_id], function (error, results, fields) {
            console.log("password", oldPassword, results[0].password)
            bcrypt.compare(oldPassword, results[0].password, function (err, isMatch) {
                if (isMatch) {
                    bcrypt.hash(newPassword, salt, function (err, hash) {
                        var insertQuery = `UPDATE user SET password = '` + hash + `' WHERE ID = ` + user_id;
                        console.log("insertQuery \r\n " + insertQuery);
                        pool.query(insertQuery, function (error, results, fields) {
                            if (error) {
                                res.send({
                                    "status": 0,
                                    "message": error,
                                    "data": []
                                })
                            } else {
                                console.log("results", results);
                                res.send({
                                    "status": 1,
                                    "message": "admin password change sucessfully",
                                    "data": []
                                });
                            }
                        });
                    });
                } else {
                    res.send({
                        "status": 0,
                        "message": "error ocurred",
                        "data": []
                    })
                }
            });
        });
    }
}

//forgot password
function forgotPassword(req, res) {
    var email = req.body.email;
    pool.query(`SELECT * FROM user WHERE email = ?`, [email], function (error, results, fields) {
        if (error) {
            res.send({
                "status": 0,
                "message": error,
                "data": []
            })
        } else {
            const email = req.body.email;
            console.log("resultsemail====", email);
            const payload = { email };
            const token = jwttoken.sign(payload, secret, { expiresIn: '1h' });
            // console.log(user.temporarytoken);
            var output = `<!doctype html>
			<html>
			<head>
			<title> title111</title>
			</head>
			<body>
			<div style="width:100%;margin:0 auto;border-radius: 2px;box-shadow: 0 1px 3px 0 rgba(0,0,0,.5); 
			border: 1px solid #d3d3d3;background:#e7eaf0;">
			<div style="border:10px solid #3998c5;background:#fff;margin:25px;">
			<center><span style="font-size:30px;color:#181123;"><b>RKWebtechnology</b></span></center>								
			<center style="font-size:20px;"><b>Hello</center>
			<div style="width:85%;margin:0 auto;border-radius:4px;border:1px solid white;background:white;box-sizing: border-box; ">
			<div style="margin-left:30px;padding:0;">
			<p style="font-size:15px;">You, or someone else, requested an new password for this account on Project Management Tool</p>
            <p style="font-size:15px;">You can reset your password using given link below. When you do nothing, your password or account will not change.</p>
            <p style="font-size:15px;"><a href="http://localhost:3000/resetpassword/` + token + `">http://localhost:3000/resetpassword</a></p>
			<p style="font-size:15px;">This link will expires in 10 minutes.</p>
			</div>
			</div>
			</div>
			</body>
			</html>
            `;

            var transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: 'dixit20051998@gmail.com',
                    pass: '97262dixit'
                }
            });

            var mailOptions = {
                from: 'dixit20051998@gmail.com',
                to: 'dixit20051998@gmail.com',
                subject: 'Localhost Forgot Password Request',
                text: 'Hello ' + email + ', You recently request a password reset link. Please click on the link below to reset your password:<br><br><a href="http://localhost:3000/resetpassword/' + token,
                html: output
            };

            transporter.sendMail(mailOptions, function (error, info) {
                if (error) {
                    console.log("error", error);
                    return res.status(400).send({ errMsg: 'Bad request' });
                } else {
                    console.log('Email sent: ' + info.response);
                    res.send({
                        "status": 1,
                        "message": "admin login sucessfully",
                        "data": results
                    });
                }
            });
        }
    });
}

function resetPassword(req, res) {
    var tokenhash = req.body.hash;
    var token = tokenhash;
    var decoded = jwt.decode(token, secret);
    console.log("decoded{{{{{{{{{{{{{{{}}}}}}}}", decoded.email);
    var email = decoded.email;
    var obj = {
        newPassword: req.body.newPassword
    }
    console.log("newpassword", obj.newPassword);

    if (email) {
        let salt = 1;
        pool.query(`SELECT * FROM user WHERE email = ?`, [email], function (error, results, fields) {
            bcrypt.hash(obj.newPassword, salt, function (err, hash) {
                console.log("hashnewpassword================", hash);
                if (hash) {
                    var insertQuery = `UPDATE user SET password = '` + hash + `' WHERE email = '` + email + `'`;
                    console.log("insertQuery \r\n " + insertQuery);
                    pool.query(insertQuery, function (error, results, fields) {
                        if (error) {
                            res.send({
                                "status": 0,
                                "message": error,
                                "data": []
                            })
                        } else {
                            console.log("results", results);
                            res.send({
                                "status": 1,
                                "message": "admin password reset sucessfully",
                                "data": []
                            });
                        }
                    });

                } else {
                    res.send({
                        "status": 0,
                        "message": "error ocurred",
                        "data": []
                    })
                }
            });
        });
    }
}

function getProfile(req, res) {
    var user_id = req.body.id;
    pool.query(`SELECT * FROM user WHERE ID = ?`, [user_id], function (error, results, fields) {
        if (error) {
            res.send({
                "status": 0,
                "message": error,
                "data": []
            })
        } else {
            console.log("results", results);
            const obj = {
                first_name: results[0].first_name,
                last_name: results[0].last_name,
                email: results[0].email,
                filename: results[0].filename
            }
            res.send({
                "status": 1,
                "message": "getprofile sucessfull",
                "data": obj
            });
        }
    });
}

function updateProfile(req, res) {
    var user_id = req.body.id
    var obj = {
        first_name: req.body.first_name,
        last_name: req.body.last_name,
        email: req.body.email
    }

    var sql = ` UPDATE user 
                SET 
                    first_name = '` + obj.first_name + `',
                    last_name = '` + obj.last_name + `',
                    email = '` + obj.email + `'
                WHERE ID = ` + user_id;
    console.log("updateProfile sql \r\n " + sql);
    pool.query(sql, function (error, results, fields) {
        if (error) {
            res.send({
                "status": 0,
                "message": error,
                "data": []
            })
        } else {
            console.log("results", results);
            res.send({
                "status": 0,
                "message": "Profile Updated Sucessfully",
                "data": []
            });
        }
    });
}

function uploadImage(req, res) {
    console.log("files==", req.files);
    var file = req.files.filename;
    console.log("file", file.name);
    file.mv('./upload/' + file.name, function (err, result) {
        if (err) {
            console.log("ERROR#$#@$@@#@$##$$#$#", err);
        }
        else {
            console.log("results", result);
            var user_id = req.body.id
            var sql = ` UPDATE user 
                SET 
                    filename = '` + file.name + `'
                WHERE ID = ` + user_id;
            console.log("uploadImage sql \r\n " + sql);
            pool.query(sql, function (error, results, fields) {
                if (error) {
                    res.send({
                        "status": 0,
                        "message": error,
                        "data": []
                    })
                } else {
                    console.log("results", results);
                    res.send({
                        "status": 1,
                        "message": "Image Upload Sucessfully",
                        "data": file.name
                    });
                }
            });
        }
    })


}

module.exports = router;

// var sql = ` SELECT 
// u.first_name,
// u.last_name,
// u.email,
// u.password,
// u.user_type,
// u.user_role_id,
// ur.name as user_role_name
// FROM user as u
// left user_role as ur on ur.id = u.user_role_id
// left user_role_to_right as urtr on urtr.role_id = u.user_role_id
// WHERE 
// ID = ?
// `;