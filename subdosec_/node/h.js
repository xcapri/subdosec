const { Resolver } = require('node:dns').promises;
const resolver = new Resolver();



async function resolveRecords_cli(type, subdomain) {
    try {
        return await resolver[`resolve${type}`](subdomain);
    } catch (error) {
        if (error.code === 'ENODATA') {
            // console.log(`No ${type} record found for`, subdomain);
            return null;
        } else {
            return null;
            // throw error; // Re-throw error if it's not ENODATA
        }
    }
}

async function match_finger_cli(website_data, mode, fingerprint) {
    // console.log(`response_body_base64 : ${website_data.response_body_base64}`)

    // const fingerprints = await load_fingerprints_from_db_cli();
    const matchedFingerprints = [];

    // for (const fingerprint of fingerprints) {
        const decode_fingerprint = JSON.parse(Buffer.from(fingerprint, 'base64').toString('utf-8'));
        const rules = decode_fingerprint.rules;


        if (decode_fingerprint.status_fingerprint != 1) {
            const matcherConditions = [];
            for (const key in rules) {

                if (rules.hasOwnProperty(key)) {
                    let condition = null;
                    if (key === 'title') {
                        const titleString = website_data.title.trim().toLowerCase();
                        const searchString = rules[key].trim().toLowerCase();

                        condition = website_data.title !== null && titleString.includes(searchString);
                        
                    }else if (key === 'cname') {
                        const cnameString = website_data.cname_records;
                        const searchString = rules[key];
                        // Create a regular expression pattern for searchString
                        const regex = new RegExp(searchString.replace(/\./g, "\\."), 'i'); // Escape dots and make the pattern case-insensitive
                        // Check if cnameString matches the regex pattern
                        condition = cnameString !== null && regex.test(cnameString);
                    }
                     else if (key === 'status_code') {
                        condition = website_data.status_code == parseInt(rules[key]);
                    } else if (key === 'in_body') {
                        condition = website_data.response_body_base64;
                    } else if (key === 'a_record') {
                        condition = website_data.a_records !== null && website_data.a_records.includes(rules[key]);
                    } else if (key === 'redirect') {
                        condition = website_data.redirect_url !== null ? rules[key] === website_data.redirect_url : rules[key] === "baddd";
                    }

                    if (condition !== null) {
                        matcherConditions.push(condition);
                    }
                }
            }

            const matcherCondition = matcherConditions.join(' && ');

            // console.log(matcherCondition)
            
            // Evaluate the matcher condition
            if (matcherCondition && eval(matcherCondition)) {
                matchedFingerprints.push(decode_fingerprint);
            }
        }
    // }

    // Simpan sidik jari yang cocok ke database dan kembalikan layanan yang cocok
    for (const matchedFingerprint of matchedFingerprints) {
        // savevuln_todb(website_data, matchedFingerprint, userID, mode);
        const Vulnservice = {
            match : true,
            service: matchedFingerprint,
            website_data: website_data
        };
    
        // Kembalikan layanan yang cocok
        return Vulnservice;
    }

    // Jika tidak ada sidik jari yang cocok, simpan sebagai tidak terdeteksi
    if (matchedFingerprints.length === 0) {
        const unVulnservice = {
            match : false,
            website_data: website_data,
            mode: mode,
        };
        return unVulnservice
    }

}

function WebsiteData_cli(response_body_base64,title, status_code, redirect_url, cname_records, a_records, subdomain, rootdomain) {
    this.response_body_base64 = response_body_base64;
    this.title = title;
    this.status_code = status_code;
    this.redirect_url = redirect_url;
    this.cname_records = cname_records;
    this.a_records = a_records;
    this.subdomain = subdomain;
    this.rootdomain = rootdomain;
}



module.exports = {
    match_finger_cli,
    WebsiteData_cli,
    resolveRecords_cli
};
