"""
   
   Module to match the every packet information with a all rules, if any rule matches the corresponding actions could be taken

"""
import doActions
import storeLogs
import re
import time

def ExtractRuleInfo(rule):
   
   """ Function to extact infomation from give rule"""
   
   rule_info = {
        'action':None,
        'protocol': None,
        'source_ip': None,
        'destination_ip': None,
        'source_port': None,
        'destination_port': None,
        'flags': None,
        'icode': None,
        'itype': None,
        'url':None,
        'payload': None,
        'count': None,
        'seconds': None,
        'track': None,
        'msg': None,
        'sid': None
    }

   rule_parts=rule.split(" ")
   rule_info['action'] = rule_parts[0]
   rule_info['protocol'] = rule_parts[1]
   rule_info['source_ip'] = rule_parts[2]
   rule_info['source_port'] = rule_parts[3]
   rule_info['destination_ip'] = rule_parts[5]
   rule_info['destination_port'] = rule_parts[6]

   pattern = r'flags:\s*([a-zA-Z]+)'
   match=re.search(pattern,rule)
   if match:
      rule_info['flags']=match.group(1)  

   pattern = r'icode:\s*(\d+)'
   match=re.search(pattern,rule)
   if match:
      rule_info['icode']=match.group(1)

   pattern = r'itype:\s*(\d+)'
   match=re.search(pattern,rule)
   if match:
      rule_info['itype']=match.group(1)

   pattern = r'content:\s*"([^"]+)"'
   match=re.search(pattern,rule)
   if match:
      content=match.group(1)
      if content=="../":
         rule_info['url']= "../"
      else:
         rule_info['payload']=match.group(1)   
   
   pattern = r'count:\s*(\d+)'           
   match = re.search(pattern, rule)
   if match:
      rule_info['count']=match.group(1)

   pattern= r'seconds:\s*(\d+)'       
   match=re.search(pattern,rule)
   if match:
      rule_info['seconds']=match.group(1)

   pattern = r'track:\s*([a-zA-Z_]+)'
   match=re.search(pattern,rule)
   if match:
      rule_info['track']=match.group(1)

   pattern=r'(?<=msg: ")[^"]+' 
   match=re.search(pattern,rule)
   if match:
      rule_info['msg']=match.group(0)
   
   pattern=r'(?<=sid: )\d+'
   match=re.search(pattern,rule)
   if match:
      rule_info['sid']=match.group(0)
   
   pattern = r'flow:\s*(\S+);'
   match = re.search(pattern,rule)
   if match:
      rule_info['flow'] = match.group(1)
   
   return rule_info
   

def MatchRules(packet_info):
   
   """ Function to perform a match of packet info with rule info if rule matched the corresponding action could be taken """

   count_ips={}
   file=open("snortRules.txt",mode="r")
   while True:
      rule=file.readline()   
      if rule:
         
         rule_info=ExtractRuleInfo(rule)
      
         if rule_info['protocol']!=packet_info['protocol']:
            continue
         
         if rule_info['source_ip']!=packet_info['source_ip'] and rule_info['source_ip']!='any':
            continue
         
         if rule_info['source_port']!=packet_info['source_port'] and rule_info['source_port']!='any':
            continue
      
         if rule_info['destination_ip']!=str(packet_info['destination_ip']) and rule_info['destination_ip']!='any':
            continue
         
         if rule_info['destination_port']!=str(packet_info['destination_port']) and rule_info['destination_port']!='any':
            continue

         if rule_info['payload']!=None and packet_info['payload']!=None:
            if str(rule_info['payload']) not in str(packet_info['payload']):
               continue
      
         if rule_info['url']!=None and packet_info['url']!=None: 
            if rule_info['url'] not in packet_info['url']:
               continue
         
         if rule_info['flags']!=None:
            if rule_info['flags'] not in packet_info['flags']:
               continue
      
         if rule_info['icode']!=None:
            if  rule_info['icode'] != packet_info['icode']:
               continue
         

         if rule_info['itype']!=None:
            if rule_info['itype']!=packet_info['itype']:
               continue
      
         if rule_info['count']!=None:
            
            current_time=int(time.time())

            if rule_info['track'] == "by_dst":
               
               if packet_info['destination_ip'] not in count_ips:

                  count_ips[packet_info['destination_ip']]=[1,current_time]        

               else:
                  
                  count_info=count_ips[packet_info['destination_ip']]
                  
                  if count_info[0]>=rule_info['count'] and (current_time-count_info[1])<rule_info['seconds']:
                     count_ips.pop(packet_info['source_ip'])
                     storeLogs(rule_info['msg'],rule_info['sid'])
                     
                     if rule_info['action'] == "drop":
            
                        if rule_info['flow'] == "to_server":
                           result = doActions.IncommingIpBlock(packet_info['source_ip'])
                           if result==1:
                              storeLogs.AttackLogs(rule_info['msg'],rule_info['sid'])
                              continue
                        elif rule_info['flow'] == "to_client":
                           result = doActions.OutgoingIpBlock(packet_info['destination_ip'])
                           if result == 1:
                              storeLogs.AttackLogs(rule_info['msg'],rule_info['sid'])
                              time.sleep(1)
               
            if rule_info['track'] == "by_src":
               
               if packet_info['source_ip'] not in count_ips:
                  
                  count_ips[packet_info['source_ip']]=[1,current_time]          
               else:
                  
                  count_info=count_ips[packet_info['source_ip']]
                  
                  if count_info[0]>=rule_info['count'] and (current_time-count_info[1])<rule_info['seconds']:
                     count_ips.pop(packet_info['source_ip'])
                     storeLogs(rule_info['msg'],rule_info['sid'])
                     
                     if rule_info['action'] == "drop":
            
                        if rule_info['flow'] == "to_server":
                           result = doActions.IncommingIpBlock(packet_info['source_ip'])
                           if result==1:
                              storeLogs.AttackLogs(rule_info['msg'],rule_info['sid'])
                              continue
                        elif rule_info['flow'] == "to_client":
                           result = doActions.OutgoingIpBlock(packet_info['destination_ip'])
                           if result == 1:
                              storeLogs.AttackLogs(rule_info['msg'],rule_info['sid'])
                              continue

                     time.sleep(1)
                        
            else:
               pass
         
         if rule_info['action'] == "alert":

            storeLogs.AttackLogs(rule_info['msg'],rule_info['sid'])
            print("Aleret Generated Check Logs")
            continue
         
         if rule_info['action'] == "drop":
            
            if rule_info['flow'] == "to_server":
               
               result = doActions.IncommingIpBlock(packet_info['source_ip'])
               if result==1:
                  storeLogs.AttackLogs(rule_info['msg'],rule_info['sid'])
                  continue
            elif rule_info['flow'] == "to_client":
               print("Fuck")
               result = doActions.OutgoingIpBlock(packet_info['destination_ip'])
               if result == 1:
                  storeLogs.AttackLogs(rule_info['msg'],rule_info['sid'])
                  
               
      else:
         break    
