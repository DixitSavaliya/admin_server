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
router.post('/addUserRole', addUserRole);
router.get('/getUserRole', getUserRole);
router.post('/getUserRoleById', getUserRoleById);
router.post('/editUserRole', editUserRole);
router.post('/deleteUserRole', deleteUserRole);
router.post('/searchUserRoleData', searchUserRoleData);
router.get('/userRoleTableCount', userRoleTableCount);
router.post('/userRoleTablePagination', userRoleTablePagination);
router.post('/deleteUserRoleAllData', deleteUserRoleAllData);
router.post('/addUserRight', addUserRight);
router.get('/getUserRight', getUserRight);
router.post('/getUserRightById', getUserRightById);
router.post('/editUserRight', editUserRight);
router.post('/deleteUserRight', deleteUserRight);
router.post('/searchUserRightData', searchUserRightData);
router.get('/userRightTableCount', userRightTableCount);
router.post('/userRightTablePagination', userRightTablePagination);
router.post('/deleteUserRightAllData', deleteUserRightAllData);
router.post('/User_Role_to_Right', User_Role_to_Right);
router.post('/getUserRoleToRight', getUserRoleToRight);

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

function addUserRole(req, res) {
    var userrole = {
        name: req.body.name,
        status: req.body.status
    }
    // var user_id = req.body.id;
    console.log("userRoleName,userRoleStatus", userrole, userrole.name, userrole.status);
    pool.query('INSERT INTO user_role SET ?', userrole, function (error, results, response) {
        if (error) {
            res.send({
                "status": 0,
                "message": error,
                "data": []
            })
        } else {
            console.log("detail", results);
            res.send({
                "status": 1,
                "message": "addUserRole Sucessfully",
                "data": []
            });
        }
    });
}

function getUserRole(req, res) {
    pool.query(`SELECT * FROM user_role`, function (error, results, fields) {
        if (error) {
            res.send({
                "status": 0,
                "message": error,
                "data": []
            })
        } else {
            console.log("results", results);
            var array = [];
            results.forEach(function (item) {
                array.push(item);
            });
            console.log("array", array);

            // const obj = {
            //     name:results.name,
            //     status:results.status,
            //     id:results.id
            // }
            res.send({
                "status": 1,
                "message": "getUserRole sucessfull",
                "data": array
            });
        }
    });
}

function getUserRoleById(req, res) {
    var user_role_id = req.body.user_role_id;
    console.log("userroleid", user_role_id);
    pool.query(`SELECT * FROM user_role WHERE ID = ` + user_role_id, function (error, results, fields) {
        if (error) {
            res.send({
                "status": 0,
                "message": error,
                "data": []
            })
        } else {
            console.log("results", results);
            const obj = {
                name: results[0].name,
                status: results[0].status,
                id: results[0].id
            }
            res.send({
                "status": 1,
                "message": "getUserRole sucessfull",
                "data": obj
            });
        }
    });
}

function editUserRole(req, res) {
    var user_role_id = req.body.id
    var obj = {
        name: req.body.name,
        status: req.body.status
    }
    var sql = `UPDATE user_role 
                SET 
                    name = '` + obj.name + `',
                    status = '` + obj.status + `'
                WHERE ID = ` + user_role_id;
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
                "message": "Userrole Updated Sucessfully",
                "data": []
            });
        }
    });
}

function deleteUserRole(req, res) {
    var user_role_id = req.body.user_role_id;
    console.log("userroleid", user_role_id);
    var sql = "DELETE FROM user_role WHERE ID = " + user_role_id;
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
                "message": "UserRole Deleted Sucessfully",
                "data": []
            });
        }
    });
}

function searchUserRoleData(req, res) {
    var sql = 'SELECT * FROM user_role WHERE name LIKE "%' + req.body.searchkey + '%"';
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
                "message": "Search Result Get Sucessfully",
                "data": results
            });
        }
    });
}

function userRoleTableCount(req, res) {
    var sql = `SELECT COUNT(*) FROM user_role`;
    pool.query(sql, function (error, results, fields) {
        if (error) {
            res.send({
                "status": 0,
                "message": error,
                "data": []
            })
        } else {
            console.log("results", results[0]['COUNT(*)']);
            res.send({
                "status": 1,
                "message": "Search Result Get Sucessfully",
                "data": results[0]['COUNT(*)']
            });
        }
    });
}

function userRoleTablePagination(req, res) {
    var page = req.body.pageNumber;
    console.log("page", page);
    var dataPerPage = req.body.dataPerPage;
    console.log("dataPerPage", dataPerPage);
    var data = (page - 1) * dataPerPage;
    console.log("data", data);
    var offset = data + ',' + dataPerPage;
    console.log("offset", offset);
    pool.query(`SELECT * FROM user_role ORDER BY ID DESC LIMIT ` + offset, function (error, results, fields) {
        if (error) {
            res.send({
                "status": 0,
                "message": error,
                "data": []
            })
        } else {
            console.log("results", results);
            var array = [];
            results.forEach(function (item) {
                array.push(item);
            });
            console.log("array", array);
            res.send({
                "status": 1,
                "message": "getUserRole sucessfull",
                "data": array
            });
        }
    });
}

function deleteUserRoleAllData(req, res) {
    var value = req.body.value;
    console.log("userroleid", value);
    if (value == true) {
        var sql = "DELETE FROM user_role"
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
                    "message": "UserRole Deleted Sucessfully",
                    "data": []
                });
            }
        });
    }
}

function addUserRight(req, res) {
    var userright = {
        name: req.body.name,
        status: req.body.status,
        module: req.body.module
    }
    console.log("userright", userright);
    pool.query('INSERT INTO user_right SET ?', userright, function (error, results, response) {
        if (error) {
            res.send({
                "status": 0,
                "message": error,
                "data": []
            })
        } else {
            console.log("detail", results);
            res.send({
                "status": 1,
                "message": "addUserRight Sucessfully",
                "data": []
            });
        }
    });
}

function getUserRight(req, res) {
    pool.query(`SELECT * FROM user_right`, function (error, results, fields) {
        if (error) {
            res.send({
                "status": 0,
                "message": error,
                "data": []
            })
        } else {
            console.log("results", results);
            var array = [];
            results.forEach(function (item) {
                array.push(item);
            });
            console.log("array", array);

            // const obj = {
            //     name:results.name,
            //     status:results.status,
            //     id:results.id
            // }
            res.send({
                "status": 1,
                "message": "getUserRight Sucessfully",
                "data": array
            });
        }
    });
}

function getUserRightById(req, res) {
    var user_right_id = req.body.user_right_id;
    console.log("userroleid", user_right_id);
    pool.query(`SELECT * FROM user_right WHERE ID = ` + user_right_id, function (error, results, fields) {
        if (error) {
            res.send({
                "status": 0,
                "message": error,
                "data": []
            })
        } else {
            console.log("results", results);
            const obj = {
                name: results[0].name,
                status: results[0].status,
                id: results[0].id,
                module: results[0].module
            }
            res.send({
                "status": 1,
                "message": "getUserRight sucessfull",
                "data": obj
            });
        }
    });
}

function editUserRight(req, res) {
    var user_right_id = req.body.id
    var obj = {
        name: req.body.name,
        status: req.body.status,
        module: req.body.module
    }
    var sql = `UPDATE user_right
                SET 
                    name = '` + obj.name + `',
                    status = '` + obj.status + `',
                    module = '` + obj.module + `'
                WHERE ID = ` + user_right_id;
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
                "message": "Userright Updated Sucessfully",
                "data": []
            });
        }
    });
}

function deleteUserRight(req, res) {
    var user_right_id = req.body.user_right_id;
    console.log("userroleid", user_right_id);
    var sql = "DELETE FROM user_right WHERE ID = " + user_right_id;
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
                "message": "UserRight Deleted Sucessfully",
                "data": []
            });
        }
    });
}

function searchUserRightData(req, res) {
    var sql = 'SELECT * FROM user_right WHERE name LIKE "%' + req.body.searchkey + '%"';
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
                "message": "Search Result Get Sucessfully",
                "data": results
            });
        }
    });
}

function userRightTableCount(req, res) {
    var sql = `SELECT COUNT(*) FROM user_right`;
    pool.query(sql, function (error, results, fields) {
        if (error) {
            res.send({
                "status": 0,
                "message": error,
                "data": []
            })
        } else {
            console.log("results", results[0]['COUNT(*)']);
            res.send({
                "status": 1,
                "message": "Search Result Get Sucessfully",
                "data": results[0]['COUNT(*)']
            });
        }
    });
}

function userRightTablePagination(req, res) {
    var page = req.body.pageNumber;
    console.log("page", page);
    var dataPerPage = req.body.dataPerPage;
    console.log("dataPerPage", dataPerPage);
    var data = (page - 1) * dataPerPage;
    console.log("data", data);
    var offset = data + ',' + dataPerPage;
    console.log("offset", offset);
    pool.query(`SELECT * FROM user_right ORDER BY ID DESC LIMIT ` + offset, function (error, results, fields) {
        if (error) {
            res.send({
                "status": 0,
                "message": error,
                "data": []
            })
        } else {
            console.log("results", results);
            var array = [];
            results.forEach(function (item) {
                array.push(item);
            });
            console.log("array", array);
            res.send({
                "status": 1,
                "message": "getUserRight sucessfull",
                "data": array
            });
        }
    });
}

function deleteUserRightAllData(req, res) {
    var value = req.body.value;
    console.log("userrightid", value);
    if (value == true) {
        var sql = "DELETE FROM user_right"
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
                    "message": "UserRight Deleted Sucessfully",
                    "data": []
                });
            }
        });
    }
}

function getUserRoleToRight(req, res) {
    var sql = `SELECT * , 0 as _read,0 as _write,0 as _delete,0 as _import,0 as _export
               FROM user_right`;
    pool.query(sql, function (error, results, fields) {
        if (error) {
            res.send({
                "status": 0,
                "message": error,
                "data": []
            })
        } else {
            var user_role_id = req.body.user_role_id;
            var sqlquery = `SELECT * FROM user_role_to_right WHERE user_role_id = ` + user_role_id;
            pool.query(sqlquery, function (error1, results1, fields) {
                if (error) {
                    res.send({
                        "status": 0,
                        "message": error1,
                        "data": []
                    })
                } else {
                    for (var i = 0; i < results1.length; i++) {
                        for (var j = 0; j < results.length; j++) {
                            if (results[j].id == results1[i].user_right_id) {
                                results[j].name = results[j].name;
                                results[j].module = results[j].module;
                                results[j]._read = results1[i]._read;
                                results[j]._write = results1[i]._write;
                                results[j]._delete = results1[i]._delete;
                                results[j]._import = results1[i]._import;
                                results[j]._export = results1[i]._export;
                                console.log("results{}{}", results[j]);
                            }
                        }
                    }
                    res.send({
                        "status": 1,
                        "message": "UserRight Deleted Sucessfully",
                        "data": results
                    });
                }
            })
        }
    })
}

function User_Role_to_Right(req, res) {
    var user_role_id = req.body.user_role_id;
    console.log("userroleid", user_role_id, req.body.data);
    var sql = "DELETE FROM user_role_to_right WHERE user_role_id = " + user_role_id;
    pool.query(sql, function (error, results, fields) {
        if (error) {
            res.send({
                "status": 0,
                "message": error,
                "data": []
            })
        } else {
            console.log("results", results);
            var userAllRights = req.body.data;
            console.log("userallrights", userAllRights);
            for (var i = 0; i < userAllRights.length; i++) {
                var user_role_to_right = {
                    user_role_id: req.body.user_role_id,
                    user_right_id: userAllRights[i].id,
                    _read: userAllRights[i]._read,
                    _write: userAllRights[i]._write,
                    _delete: userAllRights[i]._delete,
                    _import: userAllRights[i]._import,
                    _export: userAllRights[i]._export
                }
                pool.query('INSERT INTO user_role_to_right SET ?', user_role_to_right, function (error, results, response) {
                    if (error) {
                        res.send({
                            "status": 0,
                            "message": error,
                            "data": []
                        })
                    } else {
                        console.log("detail", results);
                    }
                });
            }
            res.send({
                "status": 1,
                "message": "User_Role_to_Right Add Sucessfully",
                "data": results
            });
        }
    });
}

module.exports = router;

