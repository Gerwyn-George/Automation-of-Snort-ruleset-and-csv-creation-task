# Signature-priority-allocation-script

Automation script was required which would automate the process of creating snort snort rulesets and csv files in a specific formula for introduction to other systems. This script reduces a manual task taking 3 hours to 60 seconds automated.  

There was a requirement for the script to perform the following tasks:
- Create four Snort rulesets which would meet the following critera.
    - A Snort ruleset which contained only official information.
    - A Snort ruleset which contained only official information, with Snort signatures above sid 201000.
    - A Snort ruleset which contains secret and official information.
    - A Snort ruleset which contains secret and official information, with Snort signatures above 201000. 

- Create four csv files which contained the following data. 
    - A csv file containing one column containing all sids for rules containing official information, and second column containing the rule data.
    - A csv file containing one column containing the sid and rev number for all rules containing official information in the following format sid:rev, without data from 
      Snort rules specified in a csv file.
    - A csv file containing one column containing all sids for rules containing secret and official information and second column containing the rule data.
    - A csv file containing one column containing the sid and rev number for all rules containing official and secret information in the following format sid:rev,                        
      without data from Snort rules specified in a csv file. 
