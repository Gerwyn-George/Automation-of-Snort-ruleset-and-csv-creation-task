#These are library modules which have been added to allow for additional functionality. 
#re is used to provide the regex functions, csv is used in this script to create csv files.
#time is used to providing timing functions, in this script it is used to time how long the script
#takes to execute. 

import re
import csv
import time

Priority_3_Signatures = ["53341","54054"]
#Priority 2 is the default value. 
Priority_1_Signatures = []
Priority_0_Signatures = ["54055"]

#These are global variables are are used throughout the the script to store data in memory.
#The majority of these are lists which denoted by the "[]".

Noisy_Signatures = []
input_file = ""

#These variables are used to store the list of values when the script collects them from the file for Secret.
#It collects the rev and sid values, it provides a place to store the colons and the default priority of 2.

SIDREV_rev_S = []
SIDREV_sid_S = []
Priority_S = []
Colon_S = []

#These variables are used to store the list of values when the script collects them from the file for Official.
#It collects the rev and sid values, it provides a place to store the colons and the default priority of 2.

SIDREV_sid_O = []
SIDREV_rev_O = []
Priority_O = []
Colon_O = []

#These variables store a list of the combined sids and revs. 

sidrev_S = []
sidrev_O = []

#This start_time, executes when the script starts to save a value to this variable. 

start_time = time.time()


#This function converts a csv file to a text file. you input the csv file in 'noisy_csv_file' and you
#outputs the file with name specified in 'noisy_txt_file'

def convert_csv_to_txt(noisy_csv_file,noisy_txt_file):
    with open(noisy_txt_file,"w") as my_output_file:
        with open(noisy_csv_file,"r") as my_input_file:
            [my_output_file.write(" ".join(row)+'\n') for row in csv.reader(my_input_file)]
        my_output_file.close()
        
#This function collects all of the sids in a noisy signatures file specified in the fuction by 'noisy_txt_file'.
#It reads through and performs regex matches, if it is a sid it is added to the 'Noisy_Signatures' list specified 
#earlier in the script. 

def create_noisy_sid_list(noisy_txt_file):
    read_file=open(noisy_txt_file,"r")
    for line in read_file:

        sid_filter = re.findall(r'^\d+',line) #This regex finds any line that begins with a number.
        empty_regex = re.search(r'^\s',line)  #This regex finds any line that does not have any content.

        if empty_regex: #If it is empty, ignore it. 
            pass

        else: #If it matches a sid, add it to the noisy signatures list. Anything else, just ignore it. 
            if sid_filter:
                 Noisy_Signatures.extend(sid_filter) 
            else:
                pass
            
#This function creates four rulesets, Official CAS, Official FMC, Secret CAS, and Secret FMC.rules, it reads the
#ruleset as 'input_file' and reads through it and adds it to the respective ruleset dependent on what is in the read
#rule. 

def import_rules(input_file):
    
    Read_file = open(input_file,'r')
    
    Write_file_CAS_O = open("Official_CAS.rules",'a')
    Write_file_FMC_O = open("Official_FMC.rules",'a')
    Write_file_CAS_S = open("Secret_CAS.rules",'a')
    Write_file_FMC_S = open("Secret_FMC.rules",'a')

    CAS_O_Counter = 0
    FMC_O_Counter = 0
    CAS_S_Counter = 0
    FMC_S_Counter = 0
    

    for line in Read_file:
        empty_regex = re.search(r'^\s',line)
        hash_regex = re.search(r'^#',line)

        if empty_regex or hash_regex:
            pass

        else:
            secret_regex =re.search(r'(?i)metadata\:secret.|metadata\:secret|metadata\:\ssecret', line)
            sid_regex = re.search(r'(?<= sid:)(\s+\d+|\d+|\s+\d+\s+|\d+\s+)(?=;)',line)
            sid_int = int(sid_regex.group(0))
           
       
       
            if sid_regex:
                Write_file_CAS_S.write(line)

                CAS_S_Counter += 1
                
                if sid_int > 2009999:
                    Write_file_FMC_S.write(line)

                    FMC_S_Counter += 1

            if sid_regex and not secret_regex:
                
                Write_file_CAS_O.write(line)
                
                CAS_O_Counter += 1
                
                if sid_int > 2009999:
                    Write_file_FMC_O.write(line)

                    FMC_O_Counter += 1

    print("There are",CAS_S_Counter,"CAS secret rules")
    print("There are",FMC_S_Counter,"FMC secret rules")
    print("There are",CAS_O_Counter,"CAS official rules")
    print("There are",FMC_O_Counter,"FMC official rules")
    

def create_all_rules_csv(input_file):
    
    All_rules_rule_S = []
    All_rules_rule_O = []
    All_rules_sid_S = []
    All_rules_sid_O = []

    
    
    Read_file = open(input_file,'r')

    for line in Read_file:
        empty_regex = re.search(r'^\s',line)
        hash_regex = re.search(r'^#',line)
        start_hash = re.search(r'^####',line)

        if empty_regex:
            pass
        
        else:
            secret_regex = re.search(r'(?i)metadata\:secret.|metadata\:secret|metadata\:\ssecret', line)
            sid_regex = re.findall(r'(?<= sid:)(\s+\d+|\d+|\s+\d+\s+|\d+\s+)(?=;)',line)

            if sid_regex:
           
                All_rules_sid_S.extend(sid_regex)
                All_rules_rule_S.append(line)
                
            if not secret_regex and not start_hash:

                All_rules_sid_O.extend(sid_regex)
                All_rules_rule_O.append(line)


                   

    with open ("All_Rules_Secret.csv",'w', newline='') as sidrulesecret:
        write = csv.writer(sidrulesecret, dialect='excel')
        header = ["SID","Rules"]
        write.writerow(header)
        for row in zip(All_rules_sid_S,All_rules_rule_S):
            write.writerow(row)

    with open ("All_Rules_Official.csv",'w', newline='') as sidruleofficial:
        write = csv.writer(sidruleofficial, dialect='excel')
        header = ["SID","Rules"]
        write.writerow(header)
        for row in zip(All_rules_sid_O,All_rules_rule_O):
            write.writerow(row)
            
            
def create_sid_rev(input_file):

    Unwanted_Classtype_list = ['attempted-dos','attempted-recon','bad-unknown','default-login-attempt','denial-of-service','misc-attack','non-standard-protocol','rpc-portmap-decode','successful-dos','successful-recon-largescale','successful-recon-limited','suspicious-filename-detect','suspicious-login','system-call-detect','unusual-client-port-connection','web-application-activity','icmp-event','misc-activity','network-scan','not-suspicious','protocol-command-decode','string-detect','tcp-connection']


#unknown classtype removed. 
#This is the secret sidrev

    Read_file = open(input_file,'r')

    for line in Read_file:
        empty_regex = re.search(r'^\s',line)
        hash_regex = re.search(r'^#',line)
      


        if empty_regex or hash_regex:
            continue

        else:
            classtype_regex = re.search(r'(?<=classtype:)\S+(?=;)',line)
            sid_regex = re.search(r'(?<= sid:)(\s+\d+|\d+|\s+\d+\s+|\d+\s+)(?=;)',line)
            rev_regex = re.search(r'(?<= rev:)(\d+|\s+\d+|\s+\d+\s+|\d+\s+)(?=.)',line)

            if sid_regex:
                sid_str = str(sid_regex.group())
                rev_str = str(rev_regex.group())
                
                if sid_str in Noisy_Signatures:
             

                    continue

                else:
           
                    if classtype_regex:
                        classtype_str = str(classtype_regex.group())
                    
                        if classtype_str in Unwanted_Classtype_list:
                        
                            continue
                        
                        else:
                            
                            if sid_str in Priority_0_Signatures:
                                Priority_S.extend("0")
                                Colon_S.extend(":")
                                SIDREV_sid_S.append(sid_str)
                                SIDREV_rev_S.append(rev_str)
                                continue
                            
                            if sid_str in Priority_3_Signatures:
                                Priority_S.extend("3")
                                Colon_S.extend(":")
                                SIDREV_sid_S.append(sid_str)
                                SIDREV_rev_S.append(rev_str)
                                continue
                            
                            else:
                                Priority_S.extend("2")
                                Colon_S.extend(":")
                                SIDREV_sid_S.append(sid_str)
                                SIDREV_rev_S.append(rev_str)
                         
                            
                    if not classtype_regex:


                        if sid_str in Priority_0_Signatures:
                            Priority_S.extend("0")
                            Colon_S.extend(":")
                            SIDREV_sid_S.append(sid_str)
                            SIDREV_rev_S.append(rev_str)
                            continue

                        if sid_str in Priority_3_Signatures:
                            Priority_S.extend("3")
                            Colon_S.extend(":")
                            SIDREV_sid_S.append(sid_str)
                            SIDREV_rev_S.append(rev_str)
                            continue
                        
                        else:

                            Priority_S.extend("2")
                            Colon_S.extend(":")
                            SIDREV_sid_S.append(sid_str)
                            SIDREV_rev_S.append(rev_str)



#This is for the official sidrev

    Read_file = open(input_file,'r')

    for line in Read_file:
        empty_regex = re.search(r'^\s',line)
        hash_regex = re.search(r'^#',line)
      


        if empty_regex or hash_regex:
            continue

        else:
            classtype_regex = re.search(r'(?<=classtype:)\S+(?=;)',line)
            secret_regex =re.search(r'(?i)metadata\:secret.|metadata\:secret|metadata\:\ssecret', line)
            sid_regex = re.search(r'(?<= sid:)(\s+\d+|\d+|\s+\d+\s+|\d+\s+)(?=;)',line)
            rev_regex = re.search(r'(?<= rev:)(\d+|\s+\d+|\s+\d+\s+|\d+\s+)(?=.)',line)

            if sid_regex and not secret_regex:
                sid_str = str(sid_regex.group())
                rev_str = str(rev_regex.group())
                
                if sid_str in Noisy_Signatures:
             

                    continue

                else:
           
                    if classtype_regex:
                        classtype_str = str(classtype_regex.group())
                    
                        if classtype_str in Unwanted_Classtype_list:
                        
                            continue
                        
                        else:

                            if sid_str in Priority_0_Signatures:

                                Priority_O.extend("0")
                                Colon_O.extend(":")
                                SIDREV_sid_O.append(sid_str)
                                SIDREV_rev_O.append(rev_str)
                                continue

                            if sid_str in Priority_3_Signatures:

                                Priority_O.extend("3")
                                Colon_O.extend(":")
                                SIDREV_sid_O.append(sid_str)
                                SIDREV_rev_O.append(rev_str)
                                continue
                            
                            else:

                                Priority_O.extend("2")
                                Colon_O.extend(":")
                                SIDREV_sid_O.append(sid_str)
                                SIDREV_rev_O.append(rev_str)
                         
                            
                    if not classtype_regex:

                        if sid_str in Priority_0_Signatures:
                            Priority_O.extend("0")
                            Colon_O.extend(":")
                            SIDREV_sid_O.append(sid_str)
                            SIDREV_rev_O.append(rev_str)
                            continue

                        if sid_str in Priority_3_Signatures:
                            Priority_O.extend("3")
                            Colon_O.extend(":")
                            SIDREV_sid_O.append(sid_str)
                            SIDREV_rev_O.append(rev_str)
                            continue

                        else: 

                            Priority_O.extend("2")
                            Colon_O.extend(":")
                            SIDREV_sid_O.append(sid_str)
                            SIDREV_rev_O.append(rev_str)

       

           
def create_sidrev_csv():
    
    sidrev_O = [x+y+z for x,y,z in zip(SIDREV_sid_O,Colon_O,SIDREV_rev_O)]
    sidrev_S = [x+y+z for x,y,z in zip(SIDREV_sid_S,Colon_S,SIDREV_rev_S)]

    
                            
    with open ("SIDREV_S.csv",'w', newline='') as sidrevsecret:
        write = csv.writer(sidrevsecret, dialect='excel')
        header = ["SIDREV","Priority"]
        write.writerow(header)
        for row in zip(sidrev_S,Priority_S):
            write.writerow(row)
              

    with open ("SIDREV_O.csv",'w', newline='') as sidrevofficial:
        write = csv.writer(sidrevofficial, dialect='excel')
        header = ["SIDREV","Priority"]
        write.writerow(header)
        for row in zip(sidrev_O,Priority_O):
            write.writerow(row)
    

noisy_csv_file = input("Please type in the noisy csv file: ")

input_file = input("Please type in the export file: ")

convert_csv_to_txt(noisy_csv_file,"noisy_signatures.txt")
create_noisy_sid_list("noisy_signatures.txt") 
import_rules(input_file)
create_all_rules_csv(input_file)
create_sid_rev(input_file)

create_sidrev_csv()

finish_time = time.time()
elapsed_time = finish_time - start_time  

print("Task complete")
print("The time to execute this code was", elapsed_time)

input() 

          
         

