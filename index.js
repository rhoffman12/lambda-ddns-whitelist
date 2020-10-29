// index.js - ddns-update-security-group
//   Ryan Hoffman, 2020

const aws = require("aws-sdk");
const dns = require('dns');
const dnsPromises = dns.promises; 

exports.handler = async (event) => {
    
    const domain = process.env.ddns_domain;
    const sgid = process.env.whitelist_sg;
    
    aws.config.update({region: 'us-east-1'});
    const ec2 = new aws.EC2();
    
    let whitelist = await ec2.describeSecurityGroups({GroupIds: [sgid]}).promise()
    let ipv4 = await dnsPromises.resolve4(domain)
    
    let matches = whitelist.SecurityGroups[0].IpPermissions.map((rule)=>rule.IpRanges[0].CidrIp.includes(ipv4))
    
    if (matches.length>0 && matches.reduce((a,b)=>a||b)) {
        return {
            statusCode: 200,
            body: "whitelist up-to-date"
        }
    } else {
        var msg = []
        for (var i=0; i<whitelist.SecurityGroups[0].IpPermissions.length; i++) {
            if (whitelist.SecurityGroups[0].IpPermissions[i].IpRanges[0].Description == domain) {
                let ipperm = whitelist.SecurityGroups[0].IpPermissions[i];
                delete ipperm.Ipv6Ranges;
                delete ipperm.PrefixListIds;
                ipperm.UserIdGroupPairs = [{
                        GroupId: sgid
                }];
                let params = {
                    GroupId: sgid,
                    IpPermissions: [ipperm]
                }
                msg.push(await ec2.revokeSecurityGroupIngress(params).promise())
            }
        }
        let params = {
            GroupId: sgid,
            IpPermissions: [{
                IpProtocol: "-1",
                IpRanges: [{
                    CidrIp: ipv4+"/32",
                    Description: domain
                }]
            }]
        };
        msg.push(await ec2.authorizeSecurityGroupIngress(params).promise())
        
        return {
            statusCode: 201,
            body: "whitelist security group modified to include "+ipv4,
            detail: msg
        }
    }
    
};
