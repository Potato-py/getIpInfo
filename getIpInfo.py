import re,sys
from module.ipSearch import *
from module.font import *

def getIpInfo(stringIp,getDetails):
    print(Processing()+"正在识别ip，并进行标注……")
    ipList = re.findall(r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", stringIp)    #   ipV6: |(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}
    if(len(ipList)==0):
        print(Error()+"未检测到IP存在")
        return False
    posDict = ipPos(ipList) #自带去重
    outText = stringIp
    for key,value in posDict.items():
        stringIp = stringIp.replace(key,f"{blue(key)}{red(f'[{value}]')}")
        outText = outText.replace(key,f"{key}[{value}]")
    print(Result()+"IP已识别并标识,结果如下：")
    print(bold(stringIp)+"\n")
    if not os.path.exists('./Result'):
        os.makedirs('./Result')
    with open(f'./Result/newData.txt', 'w') as f:
        f.write(outText)
    print(Result()+"已导出至./Result/newData.txt\n")

    if(getDetails):
        print(Processing()+"正在查询涉及ip的历史攻击、信誉等详细信息……")
        ipReputationFromQax(ipList,True)
        #ipInfo = ipReputationFromQax(ipList,True) ipInfo可取IP各类所有信息

if __name__ == "__main__":
#     print('\n'+Information()+bold("请输入存在ip的文本，遇到空行则结束："))
#     string_ip = Input_lines(False)
    try:
        with open("./data.txt", "r") as f:
            string_ip = f.read()
    except:
        print("\n"+Error()+"请将存在ip的内容放至data.txt内")
        sys.exit()
    getIpInfo(string_ip,True)