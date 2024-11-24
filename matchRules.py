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
        'protocal': None,
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
   rule_info['action']=rule_parts[0]
   rule_info['protocal']=rule_parts[1]
   rule_info['source_ip']=rule_parts[2]
   rule_info['source_port']=rule_parts[3]
   rule_info['destination_ip']=rule_parts[5]
   rule_info['destination_port']=rule_parts[6]

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
      if match.group(1)=="../":
         rule_info['url']=match.group(1)
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

   return rule_info
   

def MatchRules():
   """ Function to perform a match of packet info with rule info if rule matched the corresponding action could be taken """
   
   file=open("snortRules.txt",mode="r")
   while True:
      rule=file.readline()   
      if rule:
         rule_info=ExtractRuleInfo(rule)
         
      else:
         break    
MatchRules()
