#These are library modules which have been added to allow for additional functionality. 
#re is used to provide the regex functions, csv is used in this script to create csv files.
#time is used to providing timing functions, in this script it is used to time how long the script
#takes to execute. 

import re
import csv
import time
import os
import os.path

Priority_3_Signatures = []
#Priority 2 is the default value. 
Priority_1_Signatures = []
Priority_0_Signatures = []

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


#This function converts a csv file to a text file. you input a csv file in 'csv_file' and the function 
#outputs a text file file with name specified in 'txt_file'.

def convert_csv_to_txt(csv_file,txt_file):
    with open(txt_file,"w") as my_output_file:
        with open(csv_file,"r") as my_input_file:
            [my_output_file.write(" ".join(row)+'\n') for row in csv.reader(my_input_file)]
        my_output_file.close()
        
#This function collects all of the sids in a noisy signatures file specified in the fuction by 'noisy_txt_file'.
#It reads through and performs regex matches, if it is a sid it is added to the 'Noisy_Signatures' list specified 
#earlier in the script. 


def create_list_from_textfile(text_file, list_to_add):
    
    read_file=open(text_file,"r") #This opens the text file specified by 'text_file'.
    for line in read_file: #This reads through every line in te specified 'text_file'.

        sid_filter = re.findall(r'^\d+',line) #This regex finds any line that begins with a number.
        empty_regex = re.search(r'^\s',line)  #This regex finds any line that does not have any content.

        if empty_regex: #If it is empty, ignore it. 
            pass

        else: #If it matches a sid, add it to the list sepecified in 'list_to_add'. Anything else, just ignore it. 
            if sid_filter:
                 list_to_add.extend(sid_filter) 
            else:
                pass
        return list_to_add #This returns the completed list for use in the script. 
    
            
#This function creates four rulesets, Official CAS, Official FMC, Secret CAS, and Secret FMC.rules, it reads the
#ruleset as 'input_file' and reads through it and adds it to the respective ruleset dependent on what is in the read
#rule. CAS Rules are all rules, FMC are only rules above 2009999. each classication 'secret' and 'official' only contain rule data relevent 
#to its classification.

def import_rules(input_file):
    
    Read_file = open(input_file,'r') #It opens the ruleset file specified as 'input_file.
    
    #It creates the files which the rule sorter will write the rules into. It assigns them to variables so that they can be accessed. 

    Write_file_CAS_O = open("Official_CAS.rules",'a') 
    Write_file_FMC_O = open("Official_FMC.rules",'a')
    Write_file_CAS_S = open("Secret_CAS.rules",'a')
    Write_file_FMC_S = open("Secret_FMC.rules",'a')

    #These counters are used to count the amount of rules in the created rulesets. These will increment each time a rule is added to the
    #ruleset file. 

    CAS_O_Counter = 0
    FMC_O_Counter = 0
    CAS_S_Counter = 0
    FMC_S_Counter = 0
    
    #Here the file specified in 'Read_file' is read though line by line and allocates rules to the opened files depending on the rule content.

    for line in Read_file:
        empty_regex = re.search(r'^\s',line) #This identifies the regex for an empty line. 
        hash_regex = re.search(r'^#',line) #This identfifies the regex for a line which begins with a hash. (i.e disabled rules.)

        if empty_regex or hash_regex: #If the line is empty or begins with a hash, it is ignored. 
            pass

        else:
            secret_regex =re.search(r'(?i)metadata\:secret.|metadata\:secret|metadata\:\ssecret', line) #This identifies the regex for all metadata containing secret.
            sid_regex = re.search(r'(?<= sid:)(\s+\d+|\d+|\s+\d+\s+|\d+\s+)(?=;)',line) #This identifies the regex for sids contained in a rule.
            sid_int = int(sid_regex.group(0)) #The regex identifies multiple values, this ensures its just the first found value. This converts it from a string to an int. 
           
       

            if sid_regex: #If a line in the rulelist contains a sid, add the line to the open CAS secret file, increment the CAS S counter.
                Write_file_CAS_S.write(line)

                CAS_S_Counter += 1
                
                if sid_int > 2009999: #If the value of the sid is greater than 2009999, add it to the FMC secret file. and increment the FMC S counter.
                    Write_file_FMC_S.write(line)

                    FMC_S_Counter += 1

            if sid_regex and not secret_regex: #If the line the rulelist contains a sid and doesn't contain secret metadata, write the line to the CAS official file and increment the CAS O counter.
                
                Write_file_CAS_O.write(line)
                
                CAS_O_Counter += 1
                
                if sid_int > 2009999: #If the value of the sid is greater than 2009999, add it to the FMC official file and increment the FMC O counter.
                    Write_file_FMC_O.write(line)

                    FMC_O_Counter += 1

    #This section takes the values of the counters and displays them, so the user is able to see how many rules have been created in each ruleset.
    print("\nThere are",CAS_S_Counter,"CAS secret rules")
    print("There are",FMC_S_Counter,"FMC secret rules")
    print("There are",CAS_O_Counter,"CAS official rules")
    print("There are",FMC_O_Counter,"FMC official rules\n")
    

#This function creates the all rules csv. This is all the rules and the sids in a specific layout in a csv file. 

def create_all_rules_csv(input_file):

    #Here variables are created for the storage of the data collected from the file specified in 'input file'. 
    
    All_rules_rule_S = [] #This is for the secret rules. 
    All_rules_rule_O = [] #This is for the official rules.
    All_rules_sid_S = [] #This is for the secret sids. 
    All_rules_sid_O = [] #This is for the official sids. 

    
    
    Read_file = open(input_file,'r') #This opens the file specified by 'input file'.

    
    for line in Read_file: #This opens the file specified by 'input file'
        empty_regex = re.search(r'^\s',line) #This regex identifies empty lines'
        hash_regex = re.search(r'^#',line) #This regex identifies lines which begin with hash. (i.e, Disabled rules.)
        start_hash = re.search(r'^####',line) #This regex idetifes lines which begin with a triple hash.

        if empty_regex: #If the line is empty, ignore it. 
            pass
        
        else:
            secret_regex = re.search(r'(?i)metadata\:secret.|metadata\:secret|metadata\:\ssecret', line) #This regex identifies lines which contain data
            sid_regex = re.findall(r'(?<= sid:)(\s+\d+|\d+|\s+\d+\s+|\d+\s+)(?=;)',line) #This regex identifies lines which contain sids. 

            if sid_regex: #If the line contains a sid, add the rule to the list of rules for secret, and add the sid to the list of sids for secret.
           
                All_rules_sid_S.extend(sid_regex)
                All_rules_rule_S.append(line)
                
            if not secret_regex and not start_hash: #If the line contains a sid, add the rule to the list of rules for official, and add the sid to the list of sids for official.

                All_rules_sid_O.extend(sid_regex)
                All_rules_rule_O.append(line)


    #This opens up a csv file for all rules secret and adds the data collected and placed into the secret rule and sid lists into the csv file.               
    with open ("All_Rules_Secret.csv",'w', newline='') as sidrulesecret:
        write = csv.writer(sidrulesecret, dialect='excel')
        header = ["SID","Rules"]
        write.writerow(header)
        for row in zip(All_rules_sid_S,All_rules_rule_S):
            write.writerow(row)

    #This opens up a csv file for all rules offical and adds the data collected and placed into the official rule and sid lists into the csv file.
    with open ("All_Rules_Official.csv",'w', newline='') as sidruleofficial:
        write = csv.writer(sidruleofficial, dialect='excel')
        header = ["SID","Rules"]
        write.writerow(header)
        for row in zip(All_rules_sid_O,All_rules_rule_O):
            write.writerow(row)

#This function creates a sidrev file from the rule specified in 'input_file'.    
def create_sid_rev(input_file):

    #This is the list of all the unwanted classtypes. These are removed during this function. 
    Unwanted_Classtype_list = ['attempted-dos','attempted-recon','bad-unknown','default-login-attempt','denial-of-service','misc-attack','non-standard-protocol','rpc-portmap-decode','successful-dos','successful-recon-largescale','successful-recon-limited','suspicious-filename-detect','suspicious-login','system-call-detect','unusual-client-port-connection','web-application-activity','icmp-event','misc-activity','network-scan','not-suspicious','protocol-command-decode','string-detect','tcp-connection']


 
#This is for the create of the secret sidrev.

    Read_file = open(input_file,'r') #This opens the file specified by 'input_file'.

    for line in Read_file:
        empty_regex = re.search(r'^\s',line) # This regex identifies empty lines. 
        hash_regex = re.search(r'^#',line) # This regex identifies lines with a hash.
      


        if empty_regex or hash_regex: #If line is empty or contains a hash it is ignored. 
            continue

        else:
            classtype_regex = re.search(r'(?<=classtype:)\S+(?=;)',line) #This regex identifies the classtype in the rule. 
            sid_regex = re.search(r'(?<= sid:)(\s+\d+|\d+|\s+\d+\s+|\d+\s+)(?=;)',line) #This regex identifies the sid in the rule. 
            rev_regex = re.search(r'(?<= rev:)(\d+|\s+\d+|\s+\d+\s+|\d+\s+)(?=.)',line) #This regex identifies the rev in the rule. 

            if sid_regex: #If rule contains a sid then continue with this process. 
                sid_str = str(sid_regex.group())
                rev_str = str(rev_regex.group())
                
                if sid_str in Noisy_Signatures: #If the sid of the rule matches a sid in the the Noisy_signatures rule, just ignore it. else continue the process.
             

                    continue

                else:
           
                    if classtype_regex: #If it finds a classtype in a rule, it checks if its in the unwanted class type list, if is is, it is ignored. If its a
                                        #class that is needed, comparisons are made against the list of sids created for priority 0,1, 3 etc. from this
                                        # they are allocate the correct priorities. These details are added to the lists created earlier in the script. for
                                        # creation of the sidrev file.  
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

                            if sid_str in Priority_1_Signatures:
                                Priority_S.extend("1")
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
                         
                            
                    if not classtype_regex: #If the line does not have any classtypes at all, this process of allocating priorities is also completed. 


                        if sid_str in Priority_0_Signatures:
                            Priority_S.extend("0")
                            Colon_S.extend(":")
                            SIDREV_sid_S.append(sid_str)
                            SIDREV_rev_S.append(rev_str)
                            continue
                        
                        if sid_str in Priority_1_Signatures:
                            Priority_S.extend("1")
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

    Read_file = open(input_file,'r') #This opens the file specified by 'input_file'.

    for line in Read_file:
        empty_regex = re.search(r'^\s',line) # This regex identifies empty lines.
        hash_regex = re.search(r'^#',line) # This regex identifies lines with a hash.
      


        if empty_regex or hash_regex: #If line is empty or contains a hash it is ignored. 
            continue

        else:
            classtype_regex = re.search(r'(?<=classtype:)\S+(?=;)',line) #This regex identifies the classtype in the rule.
            secret_regex =re.search(r'(?i)metadata\:secret.|metadata\:secret|metadata\:\ssecret', line) #This regex idenfies if there is secret metadata.
            sid_regex = re.search(r'(?<= sid:)(\s+\d+|\d+|\s+\d+\s+|\d+\s+)(?=;)',line) #This regex identifies the sid in the rule.
            rev_regex = re.search(r'(?<= rev:)(\d+|\s+\d+|\s+\d+\s+|\d+\s+)(?=.)',line) #This regex identifies the rev in the rule.

            if sid_regex and not secret_regex: #If rule contains a sid and doesn't contain secret metadata then continue with this process.
                sid_str = str(sid_regex.group())
                rev_str = str(rev_regex.group())
                
                if sid_str in Noisy_Signatures: #If the sid of the rule matches a sid in the the Noisy_signatures rule, just ignore it. else continue the process.
             

                    continue

                else:
           
                    if classtype_regex: #If it finds a classtype in a rule, it checks if its in the unwanted class type list, if is is, it is ignored. If its a
                                        #class that is needed, comparisons are made against the list of sids created for priority 0,1, 3 etc. from this
                                        # they are allocate the correct priorities. These details are added to the lists created earlier in the script. for
                                        # creation of the sidrev file.

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

                            if sid_str in Priority_1_Signatures:

                                Priority_O.extend("1")
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

                        if sid_str in Priority_1_Signatures:
                            Priority_O.extend("1")
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

       

#This function takes the lists created in the create_sid_rev function and adds it to a csv file. 

def create_sidrev_csv():
    
    sidrev_O = [x+y+z for x,y,z in zip(SIDREV_sid_O,Colon_O,SIDREV_rev_O)] #This variable takes the list data and creates it in this format sid:rev. for official.
    sidrev_S = [x+y+z for x,y,z in zip(SIDREV_sid_S,Colon_S,SIDREV_rev_S)] #This variable takes the list data and creates it in this format sid:rev. for secret.

    
    #These files add the created list of sidrev and priorites to a sidrev secret file.                        
    with open ("SIDREV_S.csv",'w', newline='') as sidrevsecret:
        write = csv.writer(sidrevsecret, dialect='excel')
        header = ["SIDREV","Priority"]
        write.writerow(header)
        for row in zip(sidrev_S,Priority_S):
            write.writerow(row)
              
    #These files add the created list of sidrev and priorites to a sidrev official file.
    with open ("SIDREV_O.csv",'w', newline='') as sidrevofficial:
        write = csv.writer(sidrevofficial, dialect='excel')
        header = ["SIDREV","Priority"]
        write.writerow(header)
        for row in zip(sidrev_O,Priority_O):
            write.writerow(row)

#This function clears up the folder in which the script is run, removing temporary files which are generated during this the script process. 
def file_clean_up():
    if os.path.isfile("noisy_signatures.txt"):
        os.remove("noisy_signatures.txt")

    if os.path.isfile("priority_0_csv.txt"):
        os.remove("priority_0_csv.txt")
    
    if os.path.isfile("priority_1_csv.txt"):
        os.remove("priority_1_csv.txt")

    if os.path.isfile("priority_3_csv.txt"):
        os.remove("priority_3_csv.txt")

#This function moves all of the files created and adds them to a folder based on their classification, if the folder doesn't exsist then
#it is created and the files added afterwards. 
def file_organise():
    if not os.path.isdir("Official"):
        
        os.mkdir("Official")
        os.rename("Official_CAS.rules", "Official/Official_CAS.rules")
        os.rename("Official_FMC.rules", "Official/Official_FMC.rules")
        os.rename("All_Rules_Official.csv", "Official/All_Rules_Official.csv")
        os.rename("SIDREV_O.csv","Official/SIDREV_O.csv")
    else:
        os.rename("Official_CAS.rules", "Official/Official_CAS.rules")
        os.rename("Official_FMC.rules", "Official/Official_FMC.rules")
        os.rename("All_Rules_Official.csv", "Official/All_Rules_Official.csv")
        os.rename("SIDREV_O.csv","Official/SIDREV_O.csv")

    if not os.path.isdir("Secret"):
       
        os.mkdir("Secret")
        os.rename("Secret_CAS.rules", "Secret/Secret_CAS.rules")
        os.rename("Secret_FMC.rules", "Secret/Secret_FMC.rules")
        os.rename("All_Rules_Secret.csv", "Secret/All_Rules_Secret.csv")
        os.rename("SIDREV_S.csv", "Secret/SIDREV_S.csv") 

    else:
        os.rename("Secret_CAS.rules", "Secret/Secret_CAS.rules")
        os.rename("Secret_FMC.rules", "Secret/Secret_FMC.rules")
        os.rename("All_Rules_Secret.csv", "Secret/All_Rules_Secret.csv")
        os.rename("SIDREV_S.csv", "Secret/SIDREV_S.csv") 



print("RSM snort rules sorter and content manager documentation creation script.\n")

noisy_csv_file = input("Please type in the noisy csv file: ") #input the noisy csv file. 
input_file = input("Please type in the export file: ") #input the ruleset file. 

priority_0_csv = input("Please type in the priority 0 csv file: ") #input the priority 0 csv file. 
priority_1_csv = input("Please type in the priority 1 csv file: ") #input the priority 1 csv file.
priority_3_csv = input("Please type in the priority 3 csv file: ") #input the priority 3 csv file.

convert_csv_to_txt(noisy_csv_file,"noisy_signatures.txt") #Its converting the noisy csv to a text file. 
create_list_from_textfile("noisy_signatures.txt", Noisy_Signatures) #It opens the noisy txt file and adds its entries to the Noisy_signatures list.
import_rules(input_file) #Creates the rulesets based on the ruleset file. 
create_all_rules_csv(input_file) # Creates the all rules csv based on the ruleset file.

#Here it opens the various priority csvs and adds its entires to the relevent lists for use. 
convert_csv_to_txt(priority_0_csv, "priority_0_csv.txt")
create_list_from_textfile("priority_0_csv.txt", Priority_0_Signatures)

convert_csv_to_txt(priority_1_csv, "priority_1_csv.txt")
create_list_from_textfile("priority_1_csv.txt", Priority_1_Signatures)

convert_csv_to_txt(priority_3_csv, "priority_3_csv.txt")
create_list_from_textfile("priority_3_csv.txt", Priority_3_Signatures)

#Creates sid rev based on the inputed ruleset and then creates the sidrev csv files.
create_sid_rev(input_file)
create_sidrev_csv()

#cleans up the temp files and puts the created files into folders for organisation.
file_clean_up() 
file_organise()

# finish_time is used to stop the timer set at the beginning of the script. 
finish_time = time.time()
elapsed_time = finish_time - start_time #shows the time taken to complete the script.   

print("Task complete")
print("The time to execute this code was", elapsed_time)

input() #Keeps terminal open so user can view displayed stats. 

          
         

