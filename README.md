# getIpInfo

将文本中含有的IP进行标记、添加IP物理位置标记，并进行输出。提取存在的外网IP，依赖奇安信威胁分析武器库进行批量自动化情报查询，展示IP信誉详情、实现检测详情、恶意详情以及数据统计，并输出xlsx表格。

Mark the IP contained in the text and add the IP physical location mark. Extract the existing Internet IP, perform batch automatic intelligence query, and display the IP reputation details, implementation detection details, malicious details, and data statistics.

# 适用场景
- 适用于[安服工作]中针对DMZ服务器入站IP批量自动化情报查询；

- 适用于[蓝队监测工作]中针对可疑IP进行批量自动化情报查询；

- 适用于[蓝队溯源工作]中针对攻击IP代理机和肉鸡过滤进行批量自动化情报查询；

- 适用于[应急工作]中主机外联自动化情报查询。

# 基本用法：

### 将含有IP的文本放置根目录下的data.txt文件中：

![image](/img/1.png)

### python getIpInfo 执行脚本：

![image](/img/2.png)

### 批量自动化情报查询，粗略打印内容，详细内容保存为xlsx：

![image](/img/3.png)

![image](/img/4.png)

### xlsx——IP信誉详细信息、失陷检测详细信息、恶意详细信息、统计信息：

![image](/img/5.png)

![image](/img/6.png)

![image](/img/7.png)
>>>>>>> 5c13139 (init)
