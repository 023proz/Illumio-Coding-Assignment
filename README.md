### Illumio-Coding-Assignment

# Enviroment: Python3.6

# Prerequisites

  * the input datas and datas in rules are always valid
  * there is no confliction in rules
# How to test the code

  * download the .py file and .csv files
  * you can add any test set based on the rules in the .csv file
  * run the .py file in 
  * see if the result is "all cases passed", it means it passes all the test cases
  
 # The architecture of this code
 
  * parse the rules, then according to the direction and protocol to seperate the rules.
  * use class PortIpRange to check if input port and ip is in the whitelist
  
 # About the optimization
 Actually, I think there are two different ways to implement this according to different size of the rules and inputs.
  * If the size of the rule is small, and the input is large, my approach is very efficient.
  * If the size of the rule is very large, the input is small, may be we can add another dimension to the dictionary: the port.
 So, this is my thinking about the performance.
 
 # About the team
 I am interested in all of the teams that Illumio has, if I had to rank them, I'd choose:
    1.Platform
    2.Policy
    3.Data
