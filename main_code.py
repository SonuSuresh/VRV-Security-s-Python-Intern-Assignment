import pandas as pd
import numpy as np

def read_log_file(filename):
    ########################################### Initialization#################################
    ipaddress=[]
    directory=[]
    statuscode=[]
    error_msg=[]
    fault_ipaddr=[]
    frq_end=[]
    count_max_end=[]
    fault_ip1=[]
    count__faultip1=[]


    ########################################### log file reading #################################
    sample=open(filename,mode='r')
    entry=str(sample.read()).split('\n')
    sample.close()

    ########################################### Data array creation #################################
    for i in range(len(entry)):
        each_entry=str(entry[i]).split(' ')
        ipaddress.append(each_entry[0])
        directory.append(each_entry[6])
        statuscode.append(each_entry[8])
        try:
            error_msg.append(str(each_entry[10])+str(each_entry[11]))
        except:
            pass
    
    ########################################### Counts #################################
    ip, count_ip = np.unique(ipaddress, return_counts=True)
    
    for i in range(len(statuscode)):
        if statuscode[i]=='401': ########################################### Fault check #################################
            fault_ipaddr.append(ipaddress[i])
    fault_ip, count__faultip = np.unique(fault_ipaddr, return_counts=True)  

    
    ########################################### un comment this when using actual data and change array name#################################
    # for i in range(len(fault_ip)):
    #     if count__faultip[i]>10:
    #         fault_ip1.append(fault_ip[i])
    #         count__faultip1.append(count__faultip[i])

    ########################################################################################################################################
    endpoint, count_end = np.unique(directory, return_counts=True)
    max__count = int(max(count_end))
    index1 = np.where(count_end==max__count)[0]
    index1=int(index1[0])

    frq_end.append(endpoint[index1])
    count_max_end.append(count_end[index1])

    ########################################### Data Frame for write to csv  #################################
    Requests_IP = {
        "IP ADDRESS": ip,
        "REQUEST COUNT": count_ip,
    }
    MostAccessedEndpoint = {
        "Endpoint":frq_end ,
        "Accessedcount":count_max_end,
    }

    SuspiciousActivity = {
        "ip address":fault_ip ,
        "Failed Attemptscount":count__faultip,
    }
    req_ip = pd.DataFrame(Requests_IP)
    end_ponit_data = pd.DataFrame(MostAccessedEndpoint)
    susp_act=pd.DataFrame(SuspiciousActivity)

    ########################################### Output csv writing #################################
    with open("log_analysis_results.csv", mode="w", newline='') as file:
        req_ip.to_csv(file, index=False, header=True)
        file.write("\n")
        file.write('Most Frequently Accessed Endpoint:\n')
        end_ponit_data.to_csv(file, index=False, header=True)
        file.write("\n") 
        file.write('Suspicious Activity Detected:\n')
        susp_act.to_csv(file, index=False, header=True)
    file.close()



    # Write DataFrame to a CSV file
    # df1.to_csv("log_analysis_results_ip.csv",index=False)
    # df2.to_csv("log_analysis_results_accses_count.csv",index=False)
    # df3.to_csv("log_analysis_results_suspisiousactivity.csv",index=False)
    print('output completed.....')

########################################### Initial file  #################################
file='sample.log'
########################################### Function call #################################
read_log_file(file)


 