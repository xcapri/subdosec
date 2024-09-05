const fs = require('fs');
const express = require('express');
const { Resolver } = require('dns').promises;
const resolver = new Resolver();
const app = express();
const PORT = process.env.PORT || 3000;
const tldExtract = require('tld-extract');
const axios = require('axios');
const { match_finger_cli, WebsiteData_cli, resolveRecords_cli } = require('./h');
const bodyParser = require('body-parser');


app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));


app.get('/', async (req, res) => {
    return res.status(401).json({ success: false, error: 'You are not authenticated!' });
});


app.post('/local/scan', async (req, res) => {
    const { target, mode, body_fu, sc_fu, title_fu, redirect_url, fingerprint_new } = req.body;

    if (!target || !mode) {
        return res.status(301).json({ success: false, error: 'Target or mode required!' });
    }


    try {
        const { domain, sub } = tldExtract(target);
        const rootdomain = domain;
        const subdomain = sub ? `${sub}.${domain}` : domain;

        const cname_records = await resolveRecords_cli('Cname', subdomain);
        const a_records = await resolveRecords_cli('4', subdomain);

        const response_body_base64 = body_fu;


        const websiteData = new WebsiteData_cli(
            response_body_base64,
            title_fu,
            sc_fu,
            redirect_url,
            cname_records,
            a_records,
            subdomain,
            rootdomain
        );    

        const isMatched = await match_finger_cli(websiteData, mode, fingerprint_new);

   
        return res.status(200).json({ 
            success: true, 
            isMatched: isMatched.match, 
            service: isMatched.service,
            website_data : websiteData,
         });

        
    } catch (error) {
        const errorDetails = {
            message: error.message,
            code: error.code,
            errno: error.errno,
            syscall: error.syscall,
            stack: error.stack
        };


        return res.status(500).json({ success: false, error: 'Internal Server Error' });
    }
});


app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${PORT}`);
});
