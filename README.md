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

- 第一次使用脚本时，会自动下载最新纯真IP数据库，请耐心等待。
- 若需更新纯真IP数据库，请删除根目录下qqwry.dat文件。

### 每天第一次使用批量自动化情报查询，需要先获取个人cookie信息(有坑,认真看)：

- 19号之前存在接口越权问题，个人用户可访问所有武器库功能，可直接使用个人账户cookie信息

![image](/img/8.png)

- **19号上午才上传的初版脚本V1.0，下午就被修复了一个BUG(导致个人用户无权限使用接口)，虎厂牛逼plus**
- 但是！还有两个bug呢宝儿(这个就不多说了)，针对于这次修复，我们先对比一下个人用户权限及员工权限：

![image](/img/9.png)

![image](/img/10.png)

- 奇安信也算是天花板了，所有很多小伙伴都有奇安信蓝信账号(做过奇安信外包的小伙伴应该也有)
- 使用内部员工登录即可（有奇安信蓝信账号即可，原厂和做过奇安信外包的应该都有）：
- [https://user.ti.qianxin.com/login/?tab=Staff&next=http%3A%2F%2Fti.qianxin.com%2Flogin](https://user.ti.qianxin.com/login/?tab=Staff&next=http%3A%2F%2Fti.qianxin.com%2Flogin)

![image](/img/11.png)

- 脚本使用时会提示输入cookie-session值，并自动保存无需再次输入，直至cookie过期。

### 批量自动化情报查询，粗略打印内容，详细内容保存为xlsx：

![image](/img/3.png)

![image](/img/4.png)

### xlsx——IP信誉详细信息、失陷检测详细信息、恶意详细信息、统计信息：

![image](/img/5.png)

![image](/img/6.png)

![image](/img/7.png)

# UPDATE 2022年11月02日09:09:27

- 第一部分功能已做出线上版本：
- [https://potato.gold/navbar/tool/getIpInfo/IpInfo.html](https://potato.gold/navbar/tool/getIpInfo/IpInfo.html)

![image](/img/web1.png)

![image](/img/web2.png)

- 线上版本暂不考虑自动化威胁情报查询，如有其他需求，请提Issues/主页留言!
