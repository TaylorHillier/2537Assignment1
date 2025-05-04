require ('dotenv').config();

const MongoClient = require('mongodb').MongoClient;

const uri = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/?retryWrites=true`
console.log(uri);
var database = new MongoClient(uri, {});

module.exports = {database};